#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
環境チェック（Cognito: パスキー/RP ID・ALLOW_USER_AUTH・ClientSecret無/ユーザー状態、
IDプール連携、S3 favicon）をまとめて判定。
設定は .env から読み込み（python-dotenv の load_dotenv を使用）。
AWSプロファイル切替は .env の AWS_PROFILE で行う。

必要:
  pip install boto3 python-dotenv
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional

import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from dotenv import load_dotenv

# .env をカレントディレクトリから読み込む（ENV_FILE 指定があればそれを優先）
load_dotenv(os.environ.get("ENV_FILE") or ".env")

RESULTS: List[Dict[str, Any]] = []

def add_result(name: str, ok: bool, detail: str, data: Optional[Dict[str, Any]] = None, critical: bool = True):
    RESULTS.append({"check": name, "ok": ok, "detail": detail, "data": data or {}, "critical": critical})

def add_skip(name: str, reason: str):
    RESULTS.append({"check": name, "ok": True, "detail": f"SKIP: {reason}", "data": {}, "critical": False})

def bool_icon(ok: bool) -> str:
    return "PASS" if ok else "FAIL"

def summarize_and_exit():
    print("\n=== Environment Check Summary ===")
    width = max((len(r["check"]) for r in RESULTS), default=10)
    failed_critical = False
    for r in RESULTS:
        line = f"[{bool_icon(r['ok'])}] {r['check']:<{width}} : {r['detail']}"
        print(line)
        if r['data']:
            print("        " + json.dumps(r['data'], ensure_ascii=False))
        if not r["ok"] and r.get("critical", True):
            failed_critical = True
    print("=" * 34)
    sys.exit(1 if failed_critical else 0)

def getenv(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if (v is not None and v != "") else default

def main():
    # ======= .env から読み込み =======
    profile      = getenv("AWS_PROFILE")
    region       = getenv("AWS_REGION", "ap-northeast-1")

    user_pool_id = getenv("COGNITO_USER_POOL_ID")
    app_client_id= getenv("COGNITO_APP_CLIENT_ID")
    username     = getenv("COGNITO_USERNAME")

    user_pool_domain = getenv("COGNITO_USER_POOL_DOMAIN")
    identity_pool_id = getenv("COGNITO_IDENTITY_POOL_ID")

    s3_bucket    = getenv("S3_BUCKET")
    favicon_key  = getenv("S3_FAVICON_KEY", "assets/favicon.ico")

    # 必須チェック
    missing = [k for k, v in {
        "COGNITO_USER_POOL_ID": user_pool_id,
        "COGNITO_APP_CLIENT_ID": app_client_id,
        "COGNITO_USERNAME": username
    }.items() if not v]
    if missing:
        print(f"ERROR: .env の必須値が未設定です: {', '.join(missing)}")
        sys.exit(2)

    # セッション（プロファイル切替対応）
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as e:
        print(f"ERROR: AWS profile not found: {e}")
        sys.exit(2)

    idp = session.client("cognito-idp")
    s3  = session.client("s3")
    cid = session.client("cognito-identity") if identity_pool_id else None

    # 1) User pool MFA & WebAuthn config（RP ID / UserVerification）
    try:
        resp = idp.get_user_pool_mfa_config(UserPoolId=user_pool_id)
        # 例: {'WebAuthnConfiguration': {'RelyingPartyId': 'ui.example.co.jp', 'UserVerification': 'preferred'}}
        webauthn = resp.get("WebAuthnConfiguration") or resp.get("webauthnConfiguration")
        rp_id = (webauthn or {}).get("RelyingPartyId")
        uv    = (webauthn or {}).get("UserVerification")
        ok = bool(webauthn and rp_id)
        add_result(
            "Cognito: WebAuthn (RP ID / UserVerification)",
            ok,
            "RP ID が設定済み" if ok else "WebAuthn/RP ID が未設定（パスキー不可）",
            {"RelyingPartyId": rp_id, "UserVerification": uv, "MfaConfiguration": resp.get("MfaConfiguration")}
        )
    except ClientError as e:
        add_result("Cognito: WebAuthn (RP ID / UserVerification)", False, f"API error: {e.response['Error']['Message']}")

    # 2) App client: ALLOW_USER_AUTH & ClientSecretなし
    try:
        c = idp.describe_user_pool_client(UserPoolId=user_pool_id, ClientId=app_client_id)
        cli = c.get("UserPoolClient", {})
        flows: List[str] = cli.get("ExplicitAuthFlows", []) or []
        has_user_auth   = "ALLOW_USER_AUTH" in flows
        secret_present  = bool(cli.get("ClientSecret"))
        ok = has_user_auth and not secret_present
        add_result(
            "App Client: ALLOW_USER_AUTH & Secretなし",
            ok,
            ("OK: ALLOW_USER_AUTH 有効 & ClientSecret なし"
             if ok else f"NG: flows={flows} secret_present={secret_present}"),
            {"ExplicitAuthFlows": flows, "SecretPresent": secret_present}
        )
        # 初回ログイン用のパスワード系フロー（任意）
        pw_ok = ("ALLOW_USER_PASSWORD_AUTH" in flows) or ("ALLOW_USER_SRP_AUTH" in flows)
        add_result(
            "App Client: パスワード系フロー（初回用・任意）",
            pw_ok,
            "推奨: 初回サインイン用に USER_PASSWORD_AUTH/SRP を有効化" if not pw_ok else "有効",
            {"ExplicitAuthFlows": flows},
            critical=False
        )
    except ClientError as e:
        add_result("App Client: ALLOW_USER_AUTH & Secretなし", False, f"API error: {e.response['Error']['Message']}")

    # 3) User existence & status（Enabled & CONFIRMED）
    try:
        u = idp.admin_get_user(UserPoolId=user_pool_id, Username=username)
        enabled = bool(u.get("Enabled"))
        status  = u.get("UserStatus")
        ok = enabled and status == "CONFIRMED"
        add_result(
            f"User: {username} の状態",
            ok,
            "Enabled & CONFIRMED" if ok else f"状態={status}, Enabled={enabled}",
            {"Enabled": enabled, "UserStatus": status}
        )
    except ClientError as e:
        # 権限の都合で admin_get_user が使えない場合のフォールバック
        try:
            lu = idp.list_users(UserPoolId=user_pool_id, Filter=f'username = "{username}"', Limit=1)
            users = lu.get("Users", [])
            if not users:
                add_result(f"User: {username} の状態", False, "ユーザーが見つかりませんでした")
            else:
                u0 = users[0]
                status = u0.get("UserStatus")
                enabled = u0.get("Enabled")
                ok = enabled and status == "CONFIRMED"
                add_result(
                    f"User: {username} の状態（list-users）",
                    ok,
                    "Enabled & CONFIRMED" if ok else f"状態={status}, Enabled={enabled}",
                    {"Enabled": enabled, "UserStatus": status}
                )
        except ClientError as e2:
            add_result(f"User: {username} の状態", False, f"API error: {e2.response['Error']['Message']}")

    # 4) User pool domain（任意）
    if user_pool_domain:
        try:
            d = idp.describe_user_pool_domain(Domain=user_pool_domain)
            dd = d.get("DomainDescription") or {}
            ok = dd.get("UserPoolId") == user_pool_id
            add_result(
                "User Pool Domain: ドメイン設定",
                ok,
                "プールIDが一致" if ok else f"別プールに関連付け（{dd.get('UserPoolId')}）",
                {"Domain": dd.get("Domain"),
                 "CloudFrontDistribution": dd.get("CloudFrontDistribution"),
                 "CustomDomainConfig": dd.get("CustomDomainConfig")}
            )
        except ClientError as e:
            add_result("User Pool Domain: ドメイン設定", False, f"API error: {e.response['Error']['Message']}")
    else:
        add_skip("User Pool Domain: ドメイン設定", "COGNITO_USER_POOL_DOMAIN が未設定")

    # 5) Identity Pool（任意）
    if identity_pool_id:
        try:
            cid = cid or session.client("cognito-identity")
            ip = cid.describe_identity_pool(IdentityPoolId=identity_pool_id)
            providers = ip.get("CognitoIdentityProviders") or []
            provider_names = [p.get("ProviderName") for p in providers]
            expected_provider = f"cognito-idp.{region}.amazonaws.com/{user_pool_id}"
            provider_ok = expected_provider in provider_names
            client_ids = [p.get("ClientId") for p in providers if p.get("ProviderName") == expected_provider]
            client_ok = (app_client_id in client_ids) if client_ids else False
            ok = provider_ok and client_ok
            add_result(
                "Identity Pool: ユーザープール連携",
                ok,
                "OK: Provider/ClientId が一致" if ok else f"NG: providers={provider_names}, clientIds={client_ids}",
                {"Providers": providers, "ExpectedProvider": expected_provider}
            )
        except ClientError as e:
            add_result("Identity Pool: ユーザープール連携", False, f"API error: {e.response['Error']['Message']}")

        try:
            roles = cid.get_identity_pool_roles(IdentityPoolId=identity_pool_id)
            auth_role = roles.get("Roles", {}).get("authenticated")
            ok = bool(auth_role)
            add_result(
                "Identity Pool: 認証ユーザーロール割当",
                ok,
                f"{'OK' if ok else 'NG: authenticated ロールなし'}",
                {"Roles": roles.get("Roles")}
            )
        except ClientError as e:
            add_result("Identity Pool: 認証ユーザーロール割当", False, f"API error: {e.response['Error']['Message']}")
    else:
        add_skip("Identity Pool: 連携/ロール", "COGNITO_IDENTITY_POOL_ID が未設定")

    # 6) S3 favicon（任意）
    if s3_bucket:
        try:
            head = s3.head_object(Bucket=s3_bucket, Key=favicon_key)
            ctype = (head.get("ContentType") or "").lower()
            ok = ctype in ("image/x-icon", "image/vnd.microsoft.icon") or favicon_key.endswith(".ico")
            add_result(
                "S3: favicon の存在/Content-Type",
                ok,
                "OK" if ok else f"Content-Type が ico ではない: {ctype}",
                {"Bucket": s3_bucket, "Key": favicon_key, "ContentType": ctype}
            )
        except ClientError as e:
            add_result("S3: favicon の存在/Content-Type", False, f"head_object 失敗: {e.response['Error']['Message']}")
    else:
        add_skip("S3: favicon", "S3_BUCKET が未設定")

    summarize_and_exit()

if __name__ == "__main__":
    main()
