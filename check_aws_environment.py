#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/**
 * 役割: 環境自動チェック（配信/認証/認可/IoT）＋ 未設定値のディスカバリ（SSM/CloudFormation/タグ/逆引き）
 * 参照: README の「アーキテクチャ要件」「CSP/キャッシュ/最小権限」、手順書の
 *       「Cognito（Passkey/RP ID/Flows）」「ID プール」「CloudFront(OAC/CSP)」「IoT(DescribeEndpoint)」「仕上げ」
 * 注意: クライアント側は Public App Client（Secret なし）前提。Hosted UI は必須ではない（自前UI）。
 * 追加: TARGET_SCOPE=cdk-only で CDK出力のものだけを対象に検査できる。
 *       OUTPUT_JSON=true で、秒精度のタイムスタンプ付きJSONに結果を保存。
 */
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from dotenv import load_dotenv

# ========== .env 読み込み ==========
load_dotenv(os.environ.get("ENV_FILE") or ".env")

# ========== 出力ユーティリティ ==========
RESULTS: List[Dict[str, Any]] = []
META: Dict[str, Any] = {}

def _add(check: str, ok: bool, detail: str, data: Optional[Dict[str, Any]] = None, critical: bool = True):
    RESULTS.append({"check": check, "ok": ok, "detail": detail, "data": data or {}, "critical": critical})

def _skip(check: str, reason: str):
    RESULTS.append({"check": check, "ok": True, "detail": f"SKIP: {reason}", "data": {}, "critical": False})

def _icon(ok: bool) -> str:
    return "PASS" if ok else "FAIL"

def _summarize_and_exit(ctx: Dict[str, str], emit_env_block: Optional[str] = None):
    print("\n=== Environment Check Summary ===")
    width = max((len(r["check"]) for r in RESULTS), default=10)
    failed_critical = False
    for r in RESULTS:
        line = f"[{_icon(r['ok'])}] {r['check']:<{width}} : {r['detail']}"
        print(line)
        if r['data']:
            print("        " + json.dumps(r['data'], ensure_ascii=False))
        if not r["ok"] and r.get("critical", True):
            failed_critical = True
    if emit_env_block:
        print("\n--- Suggested .env (discovered) ---")
        print(emit_env_block)
    print("=" * 34)

    # JSON保存
    if (_getenv("OUTPUT_JSON","false").lower()=="true"):
        path = _save_json(ctx)
        print(f"Saved JSON: {path}")

    sys.exit(1 if failed_critical else 0)

def _save_json(ctx: Dict[str, str]) -> str:
    outdir = _getenv("OUTPUT_DIR",".")
    base = _getenv("OUTPUT_BASENAME","envcheck")
    os.makedirs(outdir, exist_ok=True)
    now = datetime.now(timezone.utc).astimezone()
    stamp = now.strftime("%Y%m%d-%H%M%S")  # 秒精度
    path = os.path.join(outdir, f"{base}-{stamp}.json")
    payload = {
        "timestamp": now.isoformat(),
        "account": META.get("Account"),
        "region": ctx.get("AWS_REGION"),
        "target_scope": _getenv("TARGET_SCOPE","all"),
        "discovery": {
            "by_ssm": _getenv("DISCOVERY_BY_SSM","false"),
            "ssm_namespace": _getenv("SSM_NAMESPACE",""),
            "by_cfn": _getenv("CFN_DISCOVERY","false"),
            "cfn_stack_prefix": _getenv("CFN_STACK_PREFIX",""),
            "cfn_stack_names": _getenv("CFN_STACK_NAMES",""),
            "cfn_stack_tag_key": _getenv("CFN_STACK_TAG_KEY",""),
            "cfn_stack_tag_value": _getenv("CFN_STACK_TAG_VALUE",""),
            "by_tag": _getenv("DISCOVERY_BY_TAG","false"),
            "tag_key": _getenv("DISCOVERY_TAG_KEY",""),
            "tag_value": _getenv("DISCOVERY_TAG_VALUE",""),
            "stage": _getenv("DISCOVERY_STAGE",""),
            "require_cloudfront": _getenv("REQUIRE_CLOUDFRONT","false"),
            "require_identity_pool": _getenv("REQUIRE_IDENTITY_POOL","false"),
        },
        "context": ctx,
        "results": RESULTS,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path

def _getenv(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if (v is not None and v != "") else default

def _host(x: Optional[str]) -> Optional[str]:
    if not x:
        return None
    if "://" in x:
        try:
            return urlparse(x).hostname
        except Exception:
            return x
    return x

def _same_host(a: Optional[str], b: Optional[str]) -> bool:
    return ( (_host(a) or "").lower() == (_host(b) or "").lower() )

# ========== CloudFormation 出力からの補完 ==========
def discover_from_cfn(session: boto3.Session, ctx: Dict[str, str]) -> Dict[str, str]:
    if _getenv("CFN_DISCOVERY","false").lower() != "true":
        return ctx
    cfn = session.client("cloudformation")
    stack_prefix = _getenv("CFN_STACK_PREFIX","") or ""
    names_csv = _getenv("CFN_STACK_NAMES","")
    names = [n.strip() for n in names_csv.split(",") if n.strip()] if names_csv else []
    tag_k = _getenv("CFN_STACK_TAG_KEY","")
    tag_v = _getenv("CFN_STACK_TAG_VALUE","")

    target_stacks: List[str] = []

    # 1) 指定名
    if names:
        for n in names:
            # prefix + name を優先（なければそのまま）
            sn = f"{stack_prefix}{n}" if stack_prefix and not n.startswith(stack_prefix) else n
            target_stacks.append(sn)

    # 2) プレフィックス/タグで補足
    try:
        pager = cfn.get_paginator("describe_stacks")
        for page in pager.paginate():
            for st in page.get("Stacks", []):
                sn = st.get("StackName")
                status = st.get("StackStatus","")
                if not status.endswith("_COMPLETE"):
                    continue
                if stack_prefix and not sn.startswith(stack_prefix):
                    continue
                if tag_k and tag_v:
                    tmap = {t.get("Key"): t.get("Value") for t in (st.get("Tags") or [])}
                    if tmap.get(tag_k) != tag_v:
                        continue
                if sn not in target_stacks:
                    target_stacks.append(sn)
    except ClientError:
        pass

    # 3) 出力を拾う
    keys = {
        "COGNITO_USER_POOL_ID": ["UserPoolId"],
        "COGNITO_APP_CLIENT_ID": ["UserPoolClientId","AppClientId"],
        "COGNITO_IDENTITY_POOL_ID": ["IdentityPoolId"],
        "CLOUDFRONT_DISTRIBUTION_ID": ["CloudFrontDistributionId","DistributionId"],
        "CLOUDFRONT_DOMAIN_NAME": ["CloudFrontDomainName","DistributionDomainName"],
        "S3_BUCKET": ["StaticBucketName","WebBucketName","S3BucketName"],
        "IOT_ENDPOINT": ["IotEndpoint","IotDataEndpoint"],
        "IOT_PROVISIONING_TEMPLATE": ["ProvisioningTemplateName"],
        "EXPECTED_RP_ID": ["RpId","RelyingPartyId","CloudFrontDomainName","DistributionDomainName"],
    }

    for sn in target_stacks:
        try:
            d = cfn.describe_stacks(StackName=sn)
            stacks = d.get("Stacks", [])
            if not stacks:
                continue
            outs = {o.get("OutputKey"): o.get("OutputValue") for o in (stacks[0].get("Outputs") or [])}
            # マップ
            for env_key, candidates in keys.items():
                if ctx.get(env_key):
                    continue
                for c in candidates:
                    if c in outs and outs[c]:
                        ctx[env_key] = outs[c]
                        break
        except ClientError:
            continue
    return ctx

# ========== SSM/タグ/逆引きディスカバリ ==========
def discover_values(session: boto3.Session, ctx: Dict[str, str]) -> Dict[str, str]:
    """
    未設定のものを SSM / CloudFormation / タグ / CloudFront 逆引きで補完して返す。
    TARGET_SCOPE=cdk-only の場合は SSM/CFN 由来のみ採用し、タグや網羅探索は行わない。
    """
    region = ctx.get("AWS_REGION") or "ap-northeast-1"
    scope = _getenv("TARGET_SCOPE","all").lower()
    do_ssm = (_getenv("DISCOVERY_BY_SSM","true").lower() == "true")
    ssm_ns = _getenv("SSM_NAMESPACE")
    do_tag = (_getenv("DISCOVERY_BY_TAG","true").lower() == "true") and scope != "cdk-only"

    idp = session.client("cognito-idp")
    ssm = session.client("ssm") if do_ssm and ssm_ns else None
    cfr = session.client("cloudfront")
    cid = session.client("cognito-identity")

    # --- SSM ---
    def ssm_get(rel: str) -> Optional[str]:
        if not ssm:
            return None
        name = ssm_ns.rstrip("/") + "/" + rel.lstrip("/")
        try:
            resp = ssm.get_parameter(Name=name)
            return resp.get("Parameter", {}).get("Value")
        except ClientError:
            return None

    if do_ssm and ssm_ns:
        ctx.setdefault("COGNITO_USER_POOL_ID", ssm_get("Cognito/UserPoolId") or ctx.get("COGNITO_USER_POOL_ID",""))
        ctx.setdefault("COGNITO_APP_CLIENT_ID", ssm_get("Cognito/AppClientId") or ctx.get("COGNITO_APP_CLIENT_ID",""))
        ctx.setdefault("COGNITO_IDENTITY_POOL_ID", ssm_get("Cognito/IdentityPoolId") or ctx.get("COGNITO_IDENTITY_POOL_ID",""))
        ctx.setdefault("CLOUDFRONT_DISTRIBUTION_ID", ssm_get("CloudFront/DistributionId") or ctx.get("CLOUDFRONT_DISTRIBUTION_ID",""))
        ctx.setdefault("CLOUDFRONT_DOMAIN_NAME", ssm_get("CloudFront/DomainName") or ctx.get("CLOUDFRONT_DOMAIN_NAME",""))
        ctx.setdefault("S3_BUCKET", ssm_get("S3/Bucket") or ctx.get("S3_BUCKET",""))
        ctx.setdefault("IOT_ENDPOINT", ssm_get("IoT/Endpoint") or ctx.get("IOT_ENDPOINT",""))
        ctx.setdefault("IOT_PROVISIONING_TEMPLATE", ssm_get("IoT/ProvisioningTemplate") or ctx.get("IOT_PROVISIONING_TEMPLATE",""))
        ctx.setdefault("EXPECTED_RP_ID", ssm_get("Cognito/RpId") or ctx.get("EXPECTED_RP_ID",""))

    # --- CFN 出力 ---
    if _getenv("CFN_DISCOVERY","false").lower()=="true":
        ctx = discover_from_cfn(session, ctx)

    # --- CloudFront の ID/ドメイン探索（cdk-only では実施しない） ---
    if scope != "cdk-only":
        dist_id = ctx.get("CLOUDFRONT_DISTRIBUTION_ID") or ""
        dist_domain = ctx.get("CLOUDFRONT_DOMAIN_NAME") or ""
        expected_rp = ctx.get("EXPECTED_RP_ID") or ""
        def find_distribution_by_domain_or_tag() -> Tuple[Optional[str], Optional[str]]:
            tag_key = _getenv("DISCOVERY_TAG_KEY","Project")
            tag_val = _getenv("DISCOVERY_TAG_VALUE")
            stage   = _getenv("DISCOVERY_STAGE")
            try:
                pager = cfr.get_paginator("list_distributions")
                for page in pager.paginate():
                    items = (((page.get("DistributionList") or {}).get("Items")) or [])
                    for d in items:
                        did = d.get("Id")
                        dom = d.get("DomainName")
                        aliases = [a for a in ((d.get("Aliases") or {}).get("Items") or [])]
                        target_dom = expected_rp or dist_domain
                        if target_dom and (target_dom in aliases or _same_host(target_dom, dom)):
                            return did, dom
                        if do_tag and tag_val:
                            try:
                                tags = cfr.list_tags_for_resource(Resource=d.get("ARN")).get("Tags", {}).get("Items", [])
                                tmap = {t.get("Key"): t.get("Value") for t in tags}
                                if tmap.get(tag_key) == tag_val and (not stage or tmap.get("Stage") == stage):
                                    return did, dom
                            except ClientError:
                                pass
                return None, None
            except ClientError:
                return None, None

        if not dist_id or not dist_domain:
            did, dom = find_distribution_by_domain_or_tag()
            if did and dom:
                ctx["CLOUDFRONT_DISTRIBUTION_ID"] = did
                ctx["CLOUDFRONT_DOMAIN_NAME"] = dom
                if not expected_rp:
                    ctx["EXPECTED_RP_ID"] = dom

    # --- RP ID（未決定なら CF ドメインを採用） ---
    if not ctx.get("EXPECTED_RP_ID") and ctx.get("CLOUDFRONT_DOMAIN_NAME"):
        ctx["EXPECTED_RP_ID"] = ctx["CLOUDFRONT_DOMAIN_NAME"]

    # --- CloudFront Origin から S3 バケット逆引き（CF特定済みのとき） ---
    if ctx.get("CLOUDFRONT_DISTRIBUTION_ID") and not ctx.get("S3_BUCKET"):
        try:
            cfg = cfr.get_distribution_config(Id=ctx["CLOUDFRONT_DISTRIBUTION_ID"]).get("DistributionConfig") or {}
            origins = (cfg.get("Origins") or {}).get("Items", [])
            s3_candidates: List[str] = []
            for o in origins:
                dom = o.get("DomainName") or ""
                if ".s3" in dom:
                    s3_candidates.append(dom.split(".s3")[0])
            if len(s3_candidates) == 1:
                ctx["S3_BUCKET"] = s3_candidates[0]
        except ClientError:
            pass

    return ctx

# ========== メイン検査 ==========
def main():
    # ---- .env ----
    profile      = _getenv("AWS_PROFILE")
    region       = _getenv("AWS_REGION", "ap-northeast-1")
    scope        = _getenv("TARGET_SCOPE","all").lower()

    ctx: Dict[str, str] = {
        "AWS_REGION": region,
        "COGNITO_USER_POOL_ID": _getenv("COGNITO_USER_POOL_ID",""),
        "COGNITO_APP_CLIENT_ID": _getenv("COGNITO_APP_CLIENT_ID",""),
        "COGNITO_USERNAME": _getenv("COGNITO_USERNAME",""),
        "COGNITO_USER_POOL_DOMAIN": _getenv("COGNITO_USER_POOL_DOMAIN",""),
        "COGNITO_IDENTITY_POOL_ID": _getenv("COGNITO_IDENTITY_POOL_ID",""),
        "CLOUDFRONT_DISTRIBUTION_ID": _getenv("CLOUDFRONT_DISTRIBUTION_ID",""),
        "CLOUDFRONT_DOMAIN_NAME": _getenv("CLOUDFRONT_DOMAIN_NAME",""),
        "EXPECTED_RP_ID": _getenv("EXPECTED_RP_ID",""),
        "S3_BUCKET": _getenv("S3_BUCKET",""),
        "S3_INDEX_KEY": _getenv("S3_INDEX_KEY","index.html"),
        "S3_FAVICON_KEY": _getenv("S3_FAVICON_KEY","assets/favicon.ico"),
        "IOT_ENDPOINT": _getenv("IOT_ENDPOINT",""),
        "IOT_PROVISIONING_TEMPLATE": _getenv("IOT_PROVISIONING_TEMPLATE",""),
    }

    # 必須
    missing = [k for k, v in {
        "COGNITO_USER_POOL_ID": ctx["COGNITO_USER_POOL_ID"],
        "COGNITO_APP_CLIENT_ID": ctx["COGNITO_APP_CLIENT_ID"],
        "COGNITO_USERNAME": ctx["COGNITO_USERNAME"],
    }.items() if not v]
    if missing:
        print(f"ERROR: .env の必須値が未設定です: {', '.join(missing)}")
        sys.exit(2)

    # ---- セッション ----
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        META["Account"] = ident.get("Account")
    except ProfileNotFound as e:
        print(f"ERROR: AWS profile not found: {e}")
        sys.exit(2)
    except ClientError:
        META["Account"] = None

    # ---- ディスカバリ ----
    ctx = discover_values(session, ctx)

    idp = session.client("cognito-idp")
    s3  = session.client("s3")
    cid = session.client("cognito-identity")
    iot = session.client("iot")
    iam = session.client("iam")

    # CloudFront は、cdk-only のとき「IDがCFN/SSMから特定できた場合のみ」検査
    create_cf_client = (
        (scope != "cdk-only" and (ctx.get("CLOUDFRONT_DISTRIBUTION_ID") or ctx.get("EXPECTED_RP_ID") or ctx.get("CLOUDFRONT_DOMAIN_NAME")))
        or (scope == "cdk-only" and ctx.get("CLOUDFRONT_DISTRIBUTION_ID"))
        or (_getenv("REQUIRE_CLOUDFRONT","false").lower()=="true")
    )
    cfr = session.client("cloudfront") if create_cf_client else None

    # 0) リージョン整合（Advisory）
    try:
        up = idp.describe_user_pool(UserPoolId=ctx["COGNITO_USER_POOL_ID"])
        up_id = up.get("UserPool", {}).get("Id") or ctx["COGNITO_USER_POOL_ID"]
        prefix = (up_id.split("_", 1)[0] if "_" in up_id else "").strip()
        reg_ok = (not prefix) or (prefix == region)
        _add("Meta: リージョン整合（.env と UserPoolId 前置）", reg_ok,
             "一致" if reg_ok else f"不一致: env={region}, poolPrefix={prefix}",
             {"UserPoolId": up_id, "RegionEnv": region}, critical=False)
    except ClientError as e:
        _add("Meta: リージョン整合（.env と UserPoolId 前置）", False, f"API error: {e.response['Error']['Message']}", critical=False)

    # 1) WebAuthn（RP ID / UV）
    try:
        resp = idp.get_user_pool_mfa_config(UserPoolId=ctx["COGNITO_USER_POOL_ID"])
        webauthn = resp.get("WebAuthnConfiguration") or resp.get("webauthnConfiguration")
        rp_id = (webauthn or {}).get("RelyingPartyId")
        uv    = (webauthn or {}).get("UserVerification")
        ok_presence = bool(webauthn and rp_id)
        _add("Cognito: WebAuthn（RP ID 設定）", ok_presence,
             "RP ID が設定済み" if ok_presence else "WebAuthn/RP ID が未設定（パスキー不可）",
             {"RelyingPartyId": rp_id, "UserVerification": uv, "MfaConfiguration": resp.get("MfaConfiguration")})
        expected_rp = ctx.get("EXPECTED_RP_ID")
        if expected_rp:
            ok_match = _same_host(rp_id, expected_rp)
            _add("Cognito: WebAuthn（RP ID 一致）",
                 ok_match,
                 "期待FQDNと一致" if ok_match else f"不一致: expected={expected_rp}, actual={rp_id}",
                 {"Expected": expected_rp, "Actual": rp_id})
        if uv:
            _add("Cognito: WebAuthn（UserVerification 推奨=required）",
                 (uv == "required"),
                 f"現在: {uv}（required 推奨）",
                 {"UserVerification": uv}, critical=False)
        else:
            _add("Cognito: WebAuthn（UserVerification 推奨=required）",
                 False, "値が取得できませんでした", critical=False)
    except ClientError as e:
        _add("Cognito: WebAuthn（RP ID 設定）", False, f"API error: {e.response['Error']['Message']}")

    # 2) App client: Flows / Secret
    try:
        c = idp.describe_user_pool_client(UserPoolId=ctx["COGNITO_USER_POOL_ID"], ClientId=ctx["COGNITO_APP_CLIENT_ID"])
        cli = c.get("UserPoolClient", {}) or {}
        flows: List[str] = cli.get("ExplicitAuthFlows", []) or []
        secret_present = bool(cli.get("ClientSecret"))
        has_user_auth = "ALLOW_USER_AUTH" in flows
        has_pw_auth   = "ALLOW_USER_PASSWORD_AUTH" in flows
        _add("App Client: Public（ClientSecret なし）", not secret_present,
             "OK: Secretなし" if not secret_present else "NG: Secretあり", {"SecretPresent": secret_present})
        _add("App Client: フロー（ALLOW_USER_AUTH 必須）", has_user_auth,
             "OK: 有効" if has_user_auth else f"NG: flows={flows}", {"ExplicitAuthFlows": flows})
        _add("App Client: フロー（ALLOW_USER_PASSWORD_AUTH 必須）", has_pw_auth,
             "OK: 有効" if has_pw_auth else "NG: 初回ログインで 400(USER_PASSWORD_AUTH not enabled) になります",
             {"ExplicitAuthFlows": flows})
        _add("App Client: フロー（ALLOW_REFRESH_TOKEN_AUTH 推奨）",
             ("ALLOW_REFRESH_TOKEN_AUTH" in flows),
             "有効（推奨）" if ("ALLOW_REFRESH_TOKEN_AUTH" in flows) else "未有効（推奨）",
             {"ExplicitAuthFlows": flows}, critical=False)
        _add("App Client: フロー（ALLOW_USER_SRP_AUTH 任意）",
             ("ALLOW_USER_SRP_AUTH" in flows),
             "任意: 有効" if ("ALLOW_USER_SRP_AUTH" in flows) else "任意: 未有効",
             {"ExplicitAuthFlows": flows}, critical=False)
    except ClientError as e:
        _add("App Client: 設定取得", False, f"API error: {e.response['Error']['Message']}")

    # 3) User existence & status
    try:
        u = idp.admin_get_user(UserPoolId=ctx["COGNITO_USER_POOL_ID"], Username=ctx["COGNITO_USERNAME"])
        enabled = bool(u.get("Enabled"))
        status  = u.get("UserStatus")
        ok = enabled and status == "CONFIRMED"
        _add(f"User: {ctx['COGNITO_USERNAME']} の状態", ok,
             "Enabled & CONFIRMED" if ok else f"状態={status}, Enabled={enabled}",
             {"Enabled": enabled, "UserStatus": status})
    except ClientError:
        try:
            lu = idp.list_users(UserPoolId=ctx["COGNITO_USER_POOL_ID"], Filter=f'username = "{ctx["COGNITO_USERNAME"]}"', Limit=1)
            users = lu.get("Users", [])
            if not users:
                _add(f"User: {ctx['COGNITO_USERNAME']} の存在", False, "ユーザーが見つかりませんでした")
            else:
                u0 = users[0]
                status = u0.get("UserStatus")
                enabled = u0.get("Enabled")
                ok = enabled and status == "CONFIRMED"
                _add(f"User: {ctx['COGNITO_USERNAME']} の状態（list-users）", ok,
                     "Enabled & CONFIRMED" if ok else f"状態={status}, Enabled={enabled}",
                     {"Enabled": enabled, "UserStatus": status})
        except ClientError as e2:
            _add(f"User: {ctx['COGNITO_USERNAME']} の状態", False, f"API error: {e2.response['Error']['Message']}")

    # 4) Identity Pool（連携/ロール/信頼）
    identity_pool_id = ctx.get("COGNITO_IDENTITY_POOL_ID")
    require_id = (_getenv("REQUIRE_IDENTITY_POOL","false").lower()=="true")
    if identity_pool_id:
        cid = session.client("cognito-identity")
        try:
            ip = cid.describe_identity_pool(IdentityPoolId=identity_pool_id)
            providers = ip.get("CognitoIdentityProviders") or []
            provider_names = [p.get("ProviderName") for p in providers]
            expected_provider = f"cognito-idp.{region}.amazonaws.com/{ctx['COGNITO_USER_POOL_ID']}"
            provider_ok = expected_provider in provider_names
            client_ids = [p.get("ClientId") for p in providers if p.get("ProviderName") == expected_provider]
            client_ok = (ctx["COGNITO_APP_CLIENT_ID"] in client_ids) if client_ids else False
            _add("Identity Pool: ユーザープール連携", (provider_ok and client_ok),
                 "OK: Provider/ClientId が一致" if (provider_ok and client_ok)
                 else f"NG: providers={provider_names}, clientIds={client_ids}",
                 {"Providers": providers, "ExpectedProvider": expected_provider})

            roles = cid.get_identity_pool_roles(IdentityPoolId=identity_pool_id)
            auth_role_arn = (roles.get("Roles") or {}).get("authenticated")
            has_auth_role = bool(auth_role_arn)
            _add("Identity Pool: 認証ユーザーロール割当", has_auth_role,
                 "OK" if has_auth_role else "NG: authenticated ロールなし",
                 {"Roles": roles.get("Roles")})

            if auth_role_arn:
                iam = session.client("iam")
                role_name = auth_role_arn.split("/")[-1]
                role = iam.get_role(RoleName=role_name)
                assume = (role.get("Role") or {}).get("AssumeRolePolicyDocument") or {}
                statements: List[Dict[str, Any]] = assume.get("Statement", [])
                principal_ok = False
                aud_ok = False
                amr_ok = False
                for st in statements:
                    pr = st.get("Principal", {})
                    if ("Service" in pr and pr["Service"] == "cognito-identity.amazonaws.com") or \
                       ("Federated" in pr and pr["Federated"] == "cognito-identity.amazonaws.com"):
                        principal_ok = True
                    cond = st.get("Condition", {})
                    for condops in cond.values():
                        if isinstance(condops, dict):
                            for k, v in condops.items():
                                if k.endswith(":aud") and (identity_pool_id in ([v] if isinstance(v, str) else v or [])):
                                    aud_ok = True
                                if k.endswith(":amr"):
                                    vals = ([v] if isinstance(v, str) else v or [])
                                    if any("authenticated" in str(x) for x in vals):
                                        amr_ok = True
                _add("Identity Role: 信頼ポリシー（aud/amr）",
                     (principal_ok and aud_ok and amr_ok),
                     ("OK" if (principal_ok and aud_ok and amr_ok)
                      else f"NG: principal_ok={principal_ok}, aud_ok={aud_ok}, amr_ok={amr_ok}"),
                     {"AssumeRolePolicyDocument": assume})
                # IoT 最小権限の雰囲気チェック（Advisory）
                actions_found: List[str] = []
                inlines = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
                for pn in inlines:
                    pd = iam.get_role_policy(RoleName=role_name, PolicyName=pn).get("PolicyDocument", {})
                    for st in pd.get("Statement", []):
                        acts = st.get("Action")
                        acts = [acts] if isinstance(acts, str) else (acts or [])
                        for a in acts:
                            if isinstance(a, str) and a.startswith("iot:"):
                                actions_found.append(a)
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                for ap in attached:
                    ver = iam.get_policy(PolicyArn=ap["PolicyArn"]).get("Policy", {}).get("DefaultVersionId")
                    if ver:
                        pd = iam.get_policy_version(PolicyArn=ap["PolicyArn"], VersionId=ver).get("PolicyVersion", {}).get("Document", {})
                        for st in pd.get("Statement", []):
                            acts = st.get("Action")
                            acts = [acts] if isinstance(acts, str) else (acts or [])
                            for a in acts:
                                if isinstance(a, str) and a.startswith("iot:"):
                                    actions_found.append(a)
                have_min = all(any(a.lower().startswith(f"iot:{x}") for a in actions_found)
                               for x in ["connect", "publish", "subscribe", "receive"])
                _add("Identity Role: IoT 最小権限の雰囲気チェック（Advisory）",
                     have_min,
                     "必要アクションの痕跡あり" if have_min else f"不足の可能性: actions={sorted(set(actions_found))}",
                     {"IoTActionsFound": sorted(set(actions_found))}, critical=False)
        except ClientError as e:
            _add("Identity Pool: 検査", False, f"API error: {e.response['Error']['Message']}")
    else:
        if require_id:
            _add("Identity Pool: 未設定", False, "REQUIRE_IDENTITY_POOL=true のため必須扱い")
        else:
            _skip("Identity Pool: 連携/ロール/信頼", "ID プール未設定（任意）")

    # 5) S3: index.html / favicon / BlockPublicAccess
    if ctx.get("S3_BUCKET"):
        s3 = session.client("s3")
        try:
            head = s3.head_object(Bucket=ctx["S3_BUCKET"], Key=ctx["S3_INDEX_KEY"])
            ctype = (head.get("ContentType") or "").lower()
            ok = (ctype.startswith("text/html") or ctx["S3_INDEX_KEY"].endswith(".html"))
            _add("S3: index.html の存在/Content-Type", ok,
                 "OK" if ok else f"Content-Type が text/html ではない: {ctype}",
                 {"Bucket": ctx["S3_BUCKET"], "Key": ctx["S3_INDEX_KEY"], "ContentType": ctype})
        except ClientError as e:
            _add("S3: index.html の存在/Content-Type", False, f"head_object 失敗: {e.response['Error']['Message']}")
        try:
            head = s3.head_object(Bucket=ctx["S3_BUCKET"], Key=ctx["S3_FAVICON_KEY"])
            ctype = (head.get("ContentType") or "").lower()
            ok = ctype in ("image/x-icon", "image/vnd.microsoft.icon") or ctx["S3_FAVICON_KEY"].endswith(".ico")
            _add("S3: favicon の存在/Content-Type", ok,
                 "OK" if ok else f"Content-Type が ico ではない: {ctype}",
                 {"Bucket": ctx["S3_BUCKET"], "Key": ctx["S3_FAVICON_KEY"], "ContentType": ctype})
        except ClientError as e:
            _add("S3: favicon の存在/Content-Type", False, f"head_object 失敗: {e.response['Error']['Message']}")
        try:
            pab = s3.get_public_access_block(Bucket=ctx["S3_BUCKET"]).get("PublicAccessBlockConfiguration", {})
            flags = [pab.get(k) for k in ["BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets"]]
            ok = all(bool(x) for x in flags)
            _add("S3: Block Public Access（4項目）", ok,
                 "OK: 4項目すべて True" if ok else f"NG: {pab}", {"PublicAccessBlock": pab})
        except ClientError as e:
            _add("S3: Block Public Access（4項目）", False, f"API error: {e.response['Error']['Message']}")
    else:
        _skip("S3: index/favicon/BPA", "S3_BUCKET が未設定（CF→Origin逆引きで補完できる場合あり）")

    # 6) IoT: Data-ATS endpoint / Provisioning Template（任意）
    try:
        de = iot.describe_endpoint(endpointType="iot:Data-ATS")
        endpoint_addr = de.get("endpointAddress")
        ok = bool(endpoint_addr)
        if ctx.get("IOT_ENDPOINT"):
            ok = ok and _same_host(endpoint_addr, ctx["IOT_ENDPOINT"])
            detail = "OK: describe-endpoint と .env/SSM が一致" if ok else f"NG: env={ctx['IOT_ENDPOINT']}, actual={endpoint_addr}"
        else:
            detail = "取得OK"
        _add("IoT: Data-ATS エンドポイント", ok, detail, {"endpointAddress": endpoint_addr})
    except ClientError as e:
        _add("IoT: Data-ATS エンドポイント", False, f"API error: {e.response['Error']['Message']}")

    if ctx.get("IOT_PROVISIONING_TEMPLATE"):
        try:
            desc = iot.describe_provisioning_template(templateName=ctx["IOT_PROVISIONING_TEMPLATE"])
            ok = bool(desc.get("templateArn"))
            _add("IoT: プロビジョニングテンプレート存在（任意）", ok,
                 "存在" if ok else "見つからない", {"templateName": ctx["IOT_PROVISIONING_TEMPLATE"]}, critical=False)
        except ClientError as e:
            _add("IoT: プロビジョニングテンプレート存在（任意）", False,
                 f"API error: {e.response['Error']['Message']}", critical=False)
    else:
        _skip("IoT: プロビジョニングテンプレート存在（任意）", "IOT_PROVISIONING_TEMPLATE が未設定")

    # 7) CloudFront（スコープに応じた検査）
    require_cf = (_getenv("REQUIRE_CLOUDFRONT","false").lower()=="true")
    if cfr:
        if not ctx.get("CLOUDFRONT_DISTRIBUTION_ID"):
            if scope == "cdk-only":
                _add("CloudFront: 未特定", False if require_cf else True,
                     "cdk-only のため CFN/SSM 由来の DistributionId が必要（見つからず）",
                     critical=require_cf)
            else:
                _skip("CloudFront: DefaultRoot/OAC/CSP", "配信の特定ができなかったためスキップ（任意）")
        else:
            try:
                cg = cfr.get_distribution_config(Id=ctx["CLOUDFRONT_DISTRIBUTION_ID"])
                cfg = cg.get("DistributionConfig") or {}
                dro = (cfg.get("DefaultRootObject") or "")
                _add("CloudFront: DefaultRootObject", (dro == "index.html"),
                     f"現在: {dro!r}（index.html 推奨）", {"DefaultRootObject": dro})
                origins = (cfg.get("Origins") or {}).get("Items", [])
                oac_used = any(o.get("S3OriginConfig") and o.get("OriginAccessControlId") for o in origins)
                _add("CloudFront: OAC 使用", oac_used, "OK: OAC", {"Origins": origins})
                dcb = cfg.get("DefaultCacheBehavior") or {}
                rhp_id = dcb.get("ResponseHeadersPolicyId")
                if rhp_id:
                    rhp = cfr.get_response_headers_policy(Id=rhp_id)
                    items = (((rhp.get("ResponseHeadersPolicy") or {})
                              .get("ResponseHeadersPolicyConfig") or {})
                             .get("HeadersConfig") or {}).get("Items", [])
                    csp_vals = [it.get("Value") for it in items if (it.get("Header") or "").lower() == "content-security-policy"]
                    if csp_vals:
                        csp_val = csp_vals[0]
                        expect_idp = f"https://cognito-idp.{region}.amazonaws.com"
                        candidate_iot = ctx.get("IOT_ENDPOINT")
                        expect_iot = (f"wss://{candidate_iot}" if candidate_iot else "wss://")
                        csp_ok = (("connect-src" in csp_val) and (expect_idp in csp_val) and (expect_iot in csp_val))
                        _add("CloudFront: CSP（connect-src に cognito-idp / wss://IoT-ATS）",
                             csp_ok,
                             "OK" if csp_ok else f"NG: CSP に {expect_idp} / {expect_iot} が見当たらない",
                             {"CSP": csp_val})
                    else:
                        _add("CloudFront: CSP（connect-src）", False, "CSP ヘッダーが見つかりません")
                else:
                    _add("CloudFront: ResponseHeadersPolicy", False, "DefaultCacheBehavior に未設定")
            except ClientError as e:
                _add("CloudFront: 設定取得", False, f"API error: {e.response['Error']['Message']}")
    else:
        if require_cf:
            _add("CloudFront: 未初期化", False, "REQUIRE_CLOUDFRONT=true だが CloudFront クライアントを生成できず")
        else:
            _skip("CloudFront: DefaultRoot/OAC/CSP", "CLOUDFRONT_* / EXPECTED_RP_ID が未設定（任意）")

    # ---- .env 候補の出力 ----
    emit = (_getenv("EMIT_DISCOVERED_ENV","false").lower()=="true")
    env_block = None
    if emit:
        lines = [
            f"AWS_PROFILE={_getenv('AWS_PROFILE','default')}",
            f"AWS_REGION={ctx.get('AWS_REGION','ap-northeast-1')}",
            "",
            f"COGNITO_USER_POOL_ID={ctx.get('COGNITO_USER_POOL_ID','')}",
            f"COGNITO_APP_CLIENT_ID={ctx.get('COGNITO_APP_CLIENT_ID','')}",
            f"COGNITO_USERNAME={ctx.get('COGNITO_USERNAME','')}",
            f"COGNITO_USER_POOL_DOMAIN={_getenv('COGNITO_USER_POOL_DOMAIN','')!s}",
            "",
            f"COGNITO_IDENTITY_POOL_ID={ctx.get('COGNITO_IDENTITY_POOL_ID','')}",
            "",
            f"CLOUDFRONT_DISTRIBUTION_ID={ctx.get('CLOUDFRONT_DISTRIBUTION_ID','')}",
            f"CLOUDFRONT_DOMAIN_NAME={ctx.get('CLOUDFRONT_DOMAIN_NAME','')}",
            f"EXPECTED_RP_ID={ctx.get('EXPECTED_RP_ID','')}",
            "",
            f"S3_BUCKET={ctx.get('S3_BUCKET','')}",
            f"S3_INDEX_KEY={ctx.get('S3_INDEX_KEY','index.html')}",
            f"S3_FAVICON_KEY={ctx.get('S3_FAVICON_KEY','assets/favicon.ico')}",
            "",
            f"IOT_ENDPOINT={ctx.get('IOT_ENDPOINT','')}",
            f"IOT_PROVISIONING_TEMPLATE={ctx.get('IOT_PROVISIONING_TEMPLATE','')}",
        ]
        env_block = "\n".join(lines)

    _summarize_and_exit(ctx, env_block)

if __name__ == "__main__":
    main()
