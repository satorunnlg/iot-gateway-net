#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/**
 * 役割: 環境自動チェック（配信/認証/認可/IoT）
 * 追加: - CloudFormation スタックID/名前/タグでターゲット特定
 *       - 指定スタックの所有物であることの厳密検証（Ownership）
 *       - 結果を秒精度のファイル名で JSON 保存
 * 参照: README/手順書（CSP/キャッシュ/Passkey(RP)/最小権限/Outputs→SSM）
 * 注意: Public App Client（Secret なし）前提。Hosted UI は必須ではない（自前UI可）。
 */
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from dotenv import load_dotenv

# ===== .env =====
load_dotenv(os.environ.get("ENV_FILE") or ".env")

# ===== Globals =====
RESULTS: List[Dict[str, Any]] = []
META: Dict[str, Any] = {
    "Account": None,
    "CfnStacks": [],  # [{StackId, StackName, Outputs}]
    "CfnResourceIndex": {},  # {Type: [PhysicalId,...]}
}


# ----- helpers -----
def _add(
    check: str,
    ok: bool,
    detail: str,
    data: Optional[Dict[str, Any]] = None,
    critical: bool = True,
):
    RESULTS.append(
        {
            "check": check,
            "ok": ok,
            "detail": detail,
            "data": data or {},
            "critical": critical,
        }
    )


def _skip(check: str, reason: str):
    RESULTS.append(
        {
            "check": check,
            "ok": True,
            "detail": f"SKIP: {reason}",
            "data": {},
            "critical": False,
        }
    )


def _icon(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


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
    return (_host(a) or "").lower() == (_host(b) or "").lower()


def _summarize_and_exit(ctx: Dict[str, str], emit_env_block: Optional[str] = None):
    print("\n=== Environment Check Summary ===")
    width = max((len(r["check"]) for r in RESULTS), default=10)
    failed_critical = False
    for r in RESULTS:
        line = f"[{_icon(r['ok'])}] {r['check']:<{width}} : {r['detail']}"
        print(line)
        if r["data"]:
            print("        " + json.dumps(r["data"], ensure_ascii=False))
        if not r["ok"] and r.get("critical", True):
            failed_critical = True
    if emit_env_block:
        print("\n--- Suggested .env (discovered) ---")
        print(emit_env_block)
    print("=" * 34)

    if _getenv("OUTPUT_JSON", "false").lower() == "true":
        path = _save_json(ctx)
        print(f"Saved JSON: {path}")

    sys.exit(1 if failed_critical else 0)


def _save_json(ctx: Dict[str, str]) -> str:
    outdir = _getenv("OUTPUT_DIR", ".")
    base = _getenv("OUTPUT_BASENAME", "envcheck")
    os.makedirs(outdir, exist_ok=True)
    now = datetime.now(timezone.utc).astimezone()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(outdir, f"{base}-{stamp}.json")
    payload = {
        "timestamp": now.isoformat(),
        "account": META.get("Account"),
        "region": ctx.get("AWS_REGION"),
        "target_scope": _getenv("TARGET_SCOPE", "all"),
        "discovery": {
            "by_ssm": _getenv("DISCOVERY_BY_SSM", "false"),
            "ssm_namespace": _getenv("SSM_NAMESPACE", ""),
            "by_cfn": _getenv("CFN_DISCOVERY", "false"),
            "cfn_stack_ids": _getenv("CFN_STACK_IDS", ""),
            "cfn_stack_prefix": _getenv("CFN_STACK_PREFIX", ""),
            "cfn_stack_names": _getenv("CFN_STACK_NAMES", ""),
            "cfn_stack_tag_key": _getenv("CFN_STACK_TAG_KEY", ""),
            "cfn_stack_tag_value": _getenv("CFN_STACK_TAG_VALUE", ""),
            "by_tag": _getenv("DISCOVERY_BY_TAG", "false"),
            "tag_key": _getenv("DISCOVERY_TAG_KEY", ""),
            "tag_value": _getenv("DISCOVERY_TAG_VALUE", ""),
            "stage": _getenv("DISCOVERY_STAGE", ""),
            "require_cloudfront": _getenv("REQUIRE_CLOUDFRONT", "false"),
            "require_identity_pool": _getenv("REQUIRE_IDENTITY_POOL", "false"),
            "cfn_strict_ownership": _getenv("CFN_STRICT_OWNERSHIP", ""),
        },
        "context": ctx,
        "cfn": {
            "stacks": META.get("CfnStacks"),
            "resource_index": META.get("CfnResourceIndex"),
        },
        "results": RESULTS,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


# ----- CloudFormation discovery & ownership -----
CFN_TYPES_OF_INTEREST = [
    "AWS::Cognito::UserPool",
    "AWS::Cognito::UserPoolClient",
    "AWS::Cognito::IdentityPool",
    "AWS::CloudFront::Distribution",
    "AWS::S3::Bucket",
    "AWS::IoT::ProvisioningTemplate",
]


def _collect_stack_resources(cfn, stack_id_or_name: str) -> Dict[str, Set[str]]:
    """Return {Type: set(PhysicalIds)} for one stack."""
    index: Dict[str, Set[str]] = {t: set() for t in CFN_TYPES_OF_INTEREST}
    try:
        resp = cfn.describe_stack_resources(StackName=stack_id_or_name)
        for r in resp.get("StackResources", []):
            t = r.get("ResourceType")
            pid = r.get("PhysicalResourceId")
            if t in index and pid:
                index[t].add(pid)
    except ClientError:
        pass
    return index


def _merge_index(dst: Dict[str, Set[str]], src: Dict[str, Set[str]]):
    for t, s in src.items():
        if t not in dst:
            dst[t] = set()
        dst[t].update(s)


def discover_from_cfn(session: boto3.Session, ctx: Dict[str, str]) -> Dict[str, str]:
    if _getenv("CFN_DISCOVERY", "false").lower() != "true":
        return ctx
    cfn = session.client("cloudformation")

    # 第一優先: 明示のスタックID群
    ids_csv = _getenv("CFN_STACK_IDS", "") or ""
    given_ids = [x.strip() for x in ids_csv.split(",") if x.strip()]

    # 第二優先: 名前指定/接頭辞/タグ
    names_csv = _getenv("CFN_STACK_NAMES", "") or ""
    names = [n.strip() for n in names_csv.split(",") if n.strip()]
    prefix = _getenv("CFN_STACK_PREFIX", "") or ""
    tag_k = _getenv("CFN_STACK_TAG_KEY", "")
    tag_v = _getenv("CFN_STACK_TAG_VALUE", "")

    target_ids: List[str] = []
    target_names: List[str] = []

    # a) 指定IDを採用
    if given_ids:
        target_ids = given_ids

    # b) 指定名 / 接頭辞 / タグで補足（ID未指定時）
    if not target_ids:
        # 指定名（prefix 付与を試みる）
        for n in names:
            nn = f"{prefix}{n}" if prefix and not n.startswith(prefix) else n
            target_names.append(nn)
        # describe_stacks から補完
        try:
            pager = cfn.get_paginator("describe_stacks")
            for page in pager.paginate():
                for st in page.get("Stacks", []):
                    sn = st.get("StackName")
                    sid = st.get("StackId")
                    status = st.get("StackStatus", "")
                    if not status.endswith("_COMPLETE"):
                        continue
                    cond_ok = True
                    if prefix and not sn.startswith(prefix):
                        cond_ok = False
                    if target_names and sn not in target_names:
                        # もし明示名が与えられていれば、そのみに絞る
                        cond_ok = False
                    if tag_k and tag_v:
                        tmap = {
                            t.get("Key"): t.get("Value") for t in (st.get("Tags") or [])
                        }
                        if tmap.get(tag_k) != tag_v:
                            cond_ok = False
                    if cond_ok:
                        target_ids.append(sid)
                        META["CfnStacks"].append(
                            {
                                "StackId": sid,
                                "StackName": sn,
                                "Outputs": st.get("Outputs", []),
                            }
                        )
        except ClientError:
            pass
    else:
        # 明示IDが与えられている場合はメタ情報も取っておく
        for sid in target_ids:
            try:
                d = cfn.describe_stacks(StackName=sid)
                st = (d.get("Stacks") or [None])[0]
                if st:
                    META["CfnStacks"].append(
                        {
                            "StackId": st.get("StackId"),
                            "StackName": st.get("StackName"),
                            "Outputs": st.get("Outputs", []),
                        }
                    )
            except ClientError:
                META["CfnStacks"].append(
                    {"StackId": sid, "StackName": None, "Outputs": []}
                )

    # c) Outputs を ctx へ反映
    keymap = {
        "COGNITO_USER_POOL_ID": ["UserPoolId"],
        "COGNITO_APP_CLIENT_ID": ["UserPoolClientId", "AppClientId"],
        "COGNITO_IDENTITY_POOL_ID": ["IdentityPoolId"],
        "CLOUDFRONT_DISTRIBUTION_ID": ["CloudFrontDistributionId", "DistributionId"],
        "CLOUDFRONT_DOMAIN_NAME": ["CloudFrontDomainName", "DistributionDomainName"],
        "S3_BUCKET": ["StaticBucketName", "WebBucketName", "S3BucketName"],
        "IOT_ENDPOINT": ["IotEndpoint", "IotDataEndpoint"],
        "IOT_PROVISIONING_TEMPLATE": ["ProvisioningTemplateName"],
        "EXPECTED_RP_ID": [
            "RpId",
            "RelyingPartyId",
            "CloudFrontDomainName",
            "DistributionDomainName",
        ],
    }
    for sid in target_ids:
        try:
            d = cfn.describe_stacks(StackName=sid)
            stacks = d.get("Stacks", [])
            if not stacks:
                continue
            outs = {
                o.get("OutputKey"): o.get("OutputValue")
                for o in (stacks[0].get("Outputs") or [])
            }
            # マッピング
            for env_key, cands in keymap.items():
                if ctx.get(env_key):
                    continue
                for k in cands:
                    if k in outs and outs[k]:
                        ctx[env_key] = outs[k]
                        break
        except ClientError:
            continue

    # d) 所有権インデックスを構築
    merged: Dict[str, Set[str]] = {t: set() for t in CFN_TYPES_OF_INTEREST}
    for sid in target_ids:
        idx = _collect_stack_resources(cfn, sid)
        _merge_index(merged, idx)
    # 保存（JSON出力用）
    META["CfnResourceIndex"] = {k: sorted(list(v)) for k, v in merged.items()}

    return ctx


# ----- SSM / Tag / CloudFront 逆引き -----
def discover_values(session: boto3.Session, ctx: Dict[str, str]) -> Dict[str, str]:
    region = ctx.get("AWS_REGION") or "ap-northeast-1"
    scope = _getenv("TARGET_SCOPE", "all").lower()
    do_ssm = _getenv("DISCOVERY_BY_SSM", "true").lower() == "true"
    ssm_ns = _getenv("SSM_NAMESPACE")
    do_tag = (
        _getenv("DISCOVERY_BY_TAG", "true").lower() == "true"
    ) and scope != "cdk-only"

    # CFN → ctx 反映 & 所有権インデックス
    if _getenv("CFN_DISCOVERY", "false").lower() == "true":
        ctx = discover_from_cfn(session, ctx)

    idp = session.client("cognito-idp")
    ssm = session.client("ssm") if do_ssm and ssm_ns else None
    cfr = session.client("cloudfront")
    cid = session.client("cognito-identity")

    # --- SSM (補完) ---
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
        ctx.setdefault(
            "COGNITO_USER_POOL_ID",
            ssm_get("Cognito/UserPoolId") or ctx.get("COGNITO_USER_POOL_ID", ""),
        )
        ctx.setdefault(
            "COGNITO_APP_CLIENT_ID",
            ssm_get("Cognito/AppClientId") or ctx.get("COGNITO_APP_CLIENT_ID", ""),
        )
        ctx.setdefault(
            "COGNITO_IDENTITY_POOL_ID",
            ssm_get("Cognito/IdentityPoolId")
            or ctx.get("COGNITO_IDENTITY_POOL_ID", ""),
        )
        ctx.setdefault(
            "CLOUDFRONT_DISTRIBUTION_ID",
            ssm_get("CloudFront/DistributionId")
            or ctx.get("CLOUDFRONT_DISTRIBUTION_ID", ""),
        )
        ctx.setdefault(
            "CLOUDFRONT_DOMAIN_NAME",
            ssm_get("CloudFront/DomainName") or ctx.get("CLOUDFRONT_DOMAIN_NAME", ""),
        )
        ctx.setdefault("S3_BUCKET", ssm_get("S3/Bucket") or ctx.get("S3_BUCKET", ""))
        ctx.setdefault(
            "IOT_ENDPOINT", ssm_get("IoT/Endpoint") or ctx.get("IOT_ENDPOINT", "")
        )
        ctx.setdefault(
            "IOT_PROVISIONING_TEMPLATE",
            ssm_get("IoT/ProvisioningTemplate")
            or ctx.get("IOT_PROVISIONING_TEMPLATE", ""),
        )
        ctx.setdefault(
            "EXPECTED_RP_ID", ssm_get("Cognito/RpId") or ctx.get("EXPECTED_RP_ID", "")
        )

    # --- CloudFront ドメイン/ID を探索（cdk-only ではスキップ） ---
    if scope != "cdk-only":
        dist_id = ctx.get("CLOUDFRONT_DISTRIBUTION_ID") or ""
        dist_domain = ctx.get("CLOUDFRONT_DOMAIN_NAME") or ""
        expected_rp = ctx.get("EXPECTED_RP_ID") or ""
        tag_key = _getenv("DISCOVERY_TAG_KEY", "Project")
        tag_val = _getenv("DISCOVERY_TAG_VALUE")
        stage = _getenv("DISCOVERY_STAGE")
        try:
            if not dist_id or not dist_domain:
                pager = cfr.get_paginator("list_distributions")
                for page in pager.paginate():
                    items = ((page.get("DistributionList") or {}).get("Items")) or []
                    for d in items:
                        did = d.get("Id")
                        dom = d.get("DomainName")
                        aliases = [
                            a for a in ((d.get("Aliases") or {}).get("Items") or [])
                        ]
                        target_dom = expected_rp or dist_domain
                        if target_dom and (
                            target_dom in aliases or _same_host(target_dom, dom)
                        ):
                            ctx["CLOUDFRONT_DISTRIBUTION_ID"] = did
                            ctx["CLOUDFRONT_DOMAIN_NAME"] = dom
                            if not expected_rp:
                                ctx["EXPECTED_RP_ID"] = dom
                            raise StopIteration
                        if do_tag and tag_val:
                            try:
                                tags = (
                                    cfr.list_tags_for_resource(Resource=d.get("ARN"))
                                    .get("Tags", {})
                                    .get("Items", [])
                                )
                                tmap = {t.get("Key"): t.get("Value") for t in tags}
                                if tmap.get(tag_key) == tag_val and (
                                    not stage or tmap.get("Stage") == stage
                                ):
                                    ctx["CLOUDFRONT_DISTRIBUTION_ID"] = did
                                    ctx["CLOUDFRONT_DOMAIN_NAME"] = dom
                                    if not expected_rp:
                                        ctx["EXPECTED_RP_ID"] = dom
                                    raise StopIteration
                            except ClientError:
                                pass
        except StopIteration:
            pass
        except ClientError:
            pass

    # --- RP ID（未決定なら CF ドメイン） ---
    if not ctx.get("EXPECTED_RP_ID") and ctx.get("CLOUDFRONT_DOMAIN_NAME"):
        ctx["EXPECTED_RP_ID"] = ctx["CLOUDFRONT_DOMAIN_NAME"]

    # --- CloudFront Origin から S3 バケット逆引き ---
    if ctx.get("CLOUDFRONT_DISTRIBUTION_ID") and not ctx.get("S3_BUCKET"):
        try:
            cfg = (
                cfr.get_distribution_config(Id=ctx["CLOUDFRONT_DISTRIBUTION_ID"]).get(
                    "DistributionConfig"
                )
                or {}
            )
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


# ----- Ownership check helpers -----
def _ownership_required() -> bool:
    """CFN_STRICT_OWNERSHIP:
    - 'true'  明示オン
    - 'false' 明示オフ
    - 'auto'  CFN_STACK_IDS が与えられ、かつ TARGET_SCOPE=cdk-only のとき True
    """
    val = (_getenv("CFN_STRICT_OWNERSHIP", "auto") or "auto").lower()
    if val in ("true", "false"):
        return val == "true"
    # auto
    has_ids = bool(_getenv("CFN_STACK_IDS", "").strip())
    is_cdk_only = _getenv("TARGET_SCOPE", "all").lower() == "cdk-only"
    return has_ids and is_cdk_only


def _belongs(resource_type: str, physical_id: Optional[str]) -> bool:
    if not physical_id:
        return False
    idx: Dict[str, List[str]] = META.get("CfnResourceIndex") or {}
    allowed = set(idx.get(resource_type) or [])
    return physical_id in allowed if allowed else False


# ===== Main checks =====
def main():
    # env → ctx
    profile = _getenv("AWS_PROFILE")
    region = _getenv("AWS_REGION", "ap-northeast-1")
    scope = _getenv("TARGET_SCOPE", "all").lower()

    ctx: Dict[str, str] = {
        "AWS_REGION": region,
        "COGNITO_USER_POOL_ID": _getenv("COGNITO_USER_POOL_ID", ""),
        "COGNITO_APP_CLIENT_ID": _getenv("COGNITO_APP_CLIENT_ID", ""),
        "COGNITO_USERNAME": _getenv("COGNITO_USERNAME", ""),
        "COGNITO_USER_POOL_DOMAIN": _getenv("COGNITO_USER_POOL_DOMAIN", ""),
        "COGNITO_IDENTITY_POOL_ID": _getenv("COGNITO_IDENTITY_POOL_ID", ""),
        "CLOUDFRONT_DISTRIBUTION_ID": _getenv("CLOUDFRONT_DISTRIBUTION_ID", ""),
        "CLOUDFRONT_DOMAIN_NAME": _getenv("CLOUDFRONT_DOMAIN_NAME", ""),
        "EXPECTED_RP_ID": _getenv("EXPECTED_RP_ID", ""),
        "S3_BUCKET": _getenv("S3_BUCKET", ""),
        "S3_INDEX_KEY": _getenv("S3_INDEX_KEY", "index.html"),
        "S3_FAVICON_KEY": _getenv("S3_FAVICON_KEY", "assets/favicon.ico"),
        "IOT_ENDPOINT": _getenv("IOT_ENDPOINT", ""),
        "IOT_PROVISIONING_TEMPLATE": _getenv("IOT_PROVISIONING_TEMPLATE", ""),
    }

    # 必須（最小限）
    missing = [
        k
        for k, v in {
            "COGNITO_USER_POOL_ID": ctx["COGNITO_USER_POOL_ID"],
            "COGNITO_APP_CLIENT_ID": ctx["COGNITO_APP_CLIENT_ID"],
            "COGNITO_USERNAME": ctx["COGNITO_USERNAME"],
        }.items()
        if not v
    ]
    if missing:
        print(f"ERROR: .env の必須値が未設定です: {', '.join(missing)}")
        sys.exit(2)

    # session
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

    # ディスカバリ（CFN/SSM/Tag/逆引き）
    ctx = discover_values(session, ctx)

    # clients
    idp = session.client("cognito-idp")
    s3 = session.client("s3")
    cid = session.client("cognito-identity")
    iot = session.client("iot")
    iam = session.client("iam")

    # CloudFront client（cdk-only の場合は DistributionId が確定している時のみ）
    create_cf_client = (
        (
            scope != "cdk-only"
            and (
                ctx.get("CLOUDFRONT_DISTRIBUTION_ID")
                or ctx.get("EXPECTED_RP_ID")
                or ctx.get("CLOUDFRONT_DOMAIN_NAME")
            )
        )
        or (scope == "cdk-only" and ctx.get("CLOUDFRONT_DISTRIBUTION_ID"))
        or (_getenv("REQUIRE_CLOUDFRONT", "false").lower() == "true")
    )
    cfr = session.client("cloudfront") if create_cf_client else None

    # 0) リージョン整合（Advisory）
    try:
        up = idp.describe_user_pool(UserPoolId=ctx["COGNITO_USER_POOL_ID"])
        up_id = up.get("UserPool", {}).get("Id") or ctx["COGNITO_USER_POOL_ID"]
        prefix = (up_id.split("_", 1)[0] if "_" in up_id else "").strip()
        reg_ok = (not prefix) or (prefix == region)
        _add(
            "Meta: リージョン整合（.env と UserPoolId 前置）",
            reg_ok,
            "一致" if reg_ok else f"不一致: env={region}, poolPrefix={prefix}",
            {"UserPoolId": up_id, "RegionEnv": region},
            critical=False,
        )
    except ClientError as e:
        _add(
            "Meta: リージョン整合（.env と UserPoolId 前置）",
            False,
            f"API error: {e.response['Error']['Message']}",
            critical=False,
        )

    # 1) WebAuthn（RP / UV）
    try:
        resp = idp.get_user_pool_mfa_config(UserPoolId=ctx["COGNITO_USER_POOL_ID"])
        webauthn = resp.get("WebAuthnConfiguration") or resp.get(
            "webauthnConfiguration"
        )
        rp_id = (webauthn or {}).get("RelyingPartyId")
        uv = (webauthn or {}).get("UserVerification")
        ok_presence = bool(webauthn and rp_id)
        _add(
            "Cognito: WebAuthn（RP ID 設定）",
            ok_presence,
            (
                "RP ID が設定済み"
                if ok_presence
                else "WebAuthn/RP ID が未設定（パスキー不可）"
            ),
            {
                "RelyingPartyId": rp_id,
                "UserVerification": uv,
                "MfaConfiguration": resp.get("MfaConfiguration"),
            },
        )
        expected_rp = ctx.get("EXPECTED_RP_ID")
        if expected_rp:
            ok_match = _same_host(rp_id, expected_rp)
            _add(
                "Cognito: WebAuthn（RP ID 一致）",
                ok_match,
                (
                    "期待FQDNと一致"
                    if ok_match
                    else f"不一致: expected={expected_rp}, actual={rp_id}"
                ),
                {"Expected": expected_rp, "Actual": rp_id},
            )
    except ClientError as e:
        _add(
            "Cognito: WebAuthn（RP ID 設定）",
            False,
            f"API error: {e.response['Error']['Message']}",
        )

    # 2) App client: Flows / Secret
    try:
        c = idp.describe_user_pool_client(
            UserPoolId=ctx["COGNITO_USER_POOL_ID"],
            ClientId=ctx["COGNITO_APP_CLIENT_ID"],
        )
        cli = c.get("UserPoolClient", {}) or {}
        flows: List[str] = cli.get("ExplicitAuthFlows", []) or []
        secret_present = bool(cli.get("ClientSecret"))
        has_user_auth = "ALLOW_USER_AUTH" in flows
        has_pw_auth = "ALLOW_USER_PASSWORD_AUTH" in flows
        _add(
            "App Client: Public（ClientSecret なし）",
            not secret_present,
            "OK: Secretなし" if not secret_present else "NG: Secretあり",
            {"SecretPresent": secret_present},
        )
        _add(
            "App Client: フロー（ALLOW_USER_AUTH 必須）",
            has_user_auth,
            "OK: 有効" if has_user_auth else f"NG: flows={flows}",
            {"ExplicitAuthFlows": flows},
        )
        _add(
            "App Client: フロー（ALLOW_USER_PASSWORD_AUTH 必須）",
            has_pw_auth,
            (
                "OK: 有効"
                if has_pw_auth
                else "NG: 初回ログインで 400(USER_PASSWORD_AUTH not enabled)"
            ),
            {"ExplicitAuthFlows": flows},
        )
    except ClientError as e:
        _add(
            "App Client: 設定取得",
            False,
            f"API error: {e.response['Error']['Message']}",
        )

    # 3) User existence & status
    try:
        u = idp.admin_get_user(
            UserPoolId=ctx["COGNITO_USER_POOL_ID"], Username=ctx["COGNITO_USERNAME"]
        )
        enabled = bool(u.get("Enabled"))
        status = u.get("UserStatus")
        ok = enabled and status == "CONFIRMED"
        _add(
            f"User: {ctx['COGNITO_USERNAME']} の状態",
            ok,
            "Enabled & CONFIRMED" if ok else f"状態={status}, Enabled={enabled}",
            {"Enabled": enabled, "UserStatus": status},
        )
    except ClientError:
        _add(
            f"User: {ctx['COGNITO_USERNAME']} の状態",
            False,
            "取得失敗（ユーザーが存在しない可能性）",
        )

    # 4) Identity Pool
    identity_pool_id = ctx.get("COGNITO_IDENTITY_POOL_ID")
    require_id = _getenv("REQUIRE_IDENTITY_POOL", "false").lower() == "true"
    if identity_pool_id:
        try:
            ip = cid.describe_identity_pool(IdentityPoolId=identity_pool_id)
            providers = ip.get("CognitoIdentityProviders") or []
            provider_names = [p.get("ProviderName") for p in providers]
            expected_provider = (
                f"cognito-idp.{region}.amazonaws.com/{ctx['COGNITO_USER_POOL_ID']}"
            )
            provider_ok = expected_provider in provider_names
            client_ids = [
                p.get("ClientId")
                for p in providers
                if p.get("ProviderName") == expected_provider
            ]
            client_ok = (
                (ctx["COGNITO_APP_CLIENT_ID"] in client_ids) if client_ids else False
            )
            _add(
                "Identity Pool: ユーザープール連携",
                (provider_ok and client_ok),
                (
                    "OK: Provider/ClientId 一致"
                    if (provider_ok and client_ok)
                    else f"NG: providers={provider_names}, clientIds={client_ids}"
                ),
                {"Providers": providers, "ExpectedProvider": expected_provider},
            )
        except ClientError as e:
            _add(
                "Identity Pool: 検査",
                False,
                f"API error: {e.response['Error']['Message']}",
            )
    else:
        if require_id:
            _add(
                "Identity Pool: 未設定",
                False,
                "REQUIRE_IDENTITY_POOL=true のため必須扱い",
            )
        else:
            _skip("Identity Pool: 連携", "ID プール未設定（任意）")

    # 5) S3
    if ctx.get("S3_BUCKET"):
        try:
            head = s3.head_object(Bucket=ctx["S3_BUCKET"], Key=ctx["S3_INDEX_KEY"])
            ctype = (head.get("ContentType") or "").lower()
            ok = ctype.startswith("text/html") or ctx["S3_INDEX_KEY"].endswith(".html")
            _add(
                "S3: index.html の存在/Content-Type",
                ok,
                "OK" if ok else f"Content-Type が text/html ではない: {ctype}",
                {
                    "Bucket": ctx["S3_BUCKET"],
                    "Key": ctx["S3_INDEX_KEY"],
                    "ContentType": ctype,
                },
            )
        except ClientError as e:
            _add(
                "S3: index.html の存在/Content-Type",
                False,
                f"head_object 失敗: {e.response['Error']['Message']}",
            )
        try:
            head = s3.head_object(Bucket=ctx["S3_BUCKET"], Key=ctx["S3_FAVICON_KEY"])
            ctype = (head.get("ContentType") or "").lower()
            ok = ctype in ("image/x-icon", "image/vnd.microsoft.icon") or ctx[
                "S3_FAVICON_KEY"
            ].endswith(".ico")
            _add(
                "S3: favicon の存在/Content-Type",
                ok,
                "OK" if ok else f"Content-Type が ico ではない: {ctype}",
                {
                    "Bucket": ctx["S3_BUCKET"],
                    "Key": ctx["S3_FAVICON_KEY"],
                    "ContentType": ctype,
                },
            )
        except ClientError as e:
            _add(
                "S3: favicon の存在/Content-Type",
                False,
                f"head_object 失敗: {e.response['Error']['Message']}",
            )
        try:
            pab = s3.get_public_access_block(Bucket=ctx["S3_BUCKET"]).get(
                "PublicAccessBlockConfiguration", {}
            )
            flags = [
                pab.get(k)
                for k in [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]
            ]
            ok = all(bool(x) for x in flags)
            _add(
                "S3: Block Public Access（4項目）",
                ok,
                "OK: 4項目すべて True" if ok else f"NG: {pab}",
                {"PublicAccessBlock": pab},
            )
        except ClientError as e:
            _add(
                "S3: Block Public Access（4項目）",
                False,
                f"API error: {e.response['Error']['Message']}",
            )
    else:
        _skip(
            "S3: index/favicon/BPA",
            "S3_BUCKET 未設定（CF→Origin逆引きで補完できる場合あり）",
        )

    # 6) IoT
    try:
        de = iot.describe_endpoint(endpointType="iot:Data-ATS")
        endpoint_addr = de.get("endpointAddress")
        ok = bool(endpoint_addr)
        if ctx.get("IOT_ENDPOINT"):
            ok = ok and _same_host(endpoint_addr, ctx["IOT_ENDPOINT"])
            detail = (
                "OK: describe-endpoint と .env/SSM が一致"
                if ok
                else f"NG: env={ctx['IOT_ENDPOINT']}, actual={endpoint_addr}"
            )
        else:
            detail = "取得OK"
        _add(
            "IoT: Data-ATS エンドポイント",
            ok,
            detail,
            {"endpointAddress": endpoint_addr},
        )
    except ClientError as e:
        _add(
            "IoT: Data-ATS エンドポイント",
            False,
            f"API error: {e.response['Error']['Message']}",
        )

    if ctx.get("IOT_PROVISIONING_TEMPLATE"):
        try:
            desc = iot.describe_provisioning_template(
                templateName=ctx["IOT_PROVISIONING_TEMPLATE"]
            )
            ok = bool(desc.get("templateArn"))
            _add(
                "IoT: プロビジョニングテンプレート存在（任意）",
                ok,
                "存在" if ok else "見つからない",
                {"templateName": ctx["IOT_PROVISIONING_TEMPLATE"]},
                critical=False,
            )
        except ClientError as e:
            _add(
                "IoT: プロビジョニングテンプレート存在（任意）",
                False,
                f"API error: {e.response['Error']['Message']}",
                critical=False,
            )
    else:
        _skip(
            "IoT: プロビジョニングテンプレート存在（任意）",
            "IOT_PROVISIONING_TEMPLATE 未設定",
        )

    # 7) CloudFront
    require_cf = _getenv("REQUIRE_CLOUDFRONT", "false").lower() == "true"
    cfr_client_ready = bool(cfr)
    if cfr_client_ready and ctx.get("CLOUDFRONT_DISTRIBUTION_ID"):
        try:
            cg = cfr.get_distribution_config(Id=ctx["CLOUDFRONT_DISTRIBUTION_ID"])
            cfg = cg.get("DistributionConfig") or {}
            dro = cfg.get("DefaultRootObject") or ""
            _add(
                "CloudFront: DefaultRootObject",
                (dro == "index.html"),
                f"現在: {dro!r}（index.html 推奨）",
                {"DefaultRootObject": dro},
            )
            origins = (cfg.get("Origins") or {}).get("Items", [])
            oac_used = any(
                o.get("S3OriginConfig") and o.get("OriginAccessControlId")
                for o in origins
            )
            _add("CloudFront: OAC 使用", oac_used, "OK: OAC", {"Origins": origins})
            dcb = cfg.get("DefaultCacheBehavior") or {}
            rhp_id = dcb.get("ResponseHeadersPolicyId")
            if rhp_id:
                rhp = cfr.get_response_headers_policy(Id=rhp_id)
                items = (
                    (
                        (rhp.get("ResponseHeadersPolicy") or {}).get(
                            "ResponseHeadersPolicyConfig"
                        )
                        or {}
                    ).get("HeadersConfig")
                    or {}
                ).get("Items", [])
                csp_vals = [
                    it.get("Value")
                    for it in items
                    if (it.get("Header") or "").lower() == "content-security-policy"
                ]
                if csp_vals:
                    csp_val = csp_vals[0]
                    expect_idp = f"https://cognito-idp.{region}.amazonaws.com"
                    candidate_iot = ctx.get("IOT_ENDPOINT")
                    expect_iot = f"wss://{candidate_iot}" if candidate_iot else "wss://"
                    csp_ok = (
                        ("connect-src" in csp_val)
                        and (expect_idp in csp_val)
                        and (expect_iot in csp_val)
                    )
                    _add(
                        "CloudFront: CSP（connect-src に cognito-idp / wss://IoT-ATS）",
                        csp_ok,
                        (
                            "OK"
                            if csp_ok
                            else f"NG: CSP に {expect_idp} / {expect_iot} が見当たらない"
                        ),
                        {"CSP": csp_val},
                    )
                else:
                    _add(
                        "CloudFront: CSP（connect-src）",
                        False,
                        "CSP ヘッダーが見つかりません",
                    )
            else:
                _add(
                    "CloudFront: ResponseHeadersPolicy",
                    False,
                    "DefaultCacheBehavior に未設定",
                )
        except ClientError as e:
            _add(
                "CloudFront: 設定取得",
                False,
                f"API error: {e.response['Error']['Message']}",
            )
    else:
        if require_cf:
            _add(
                "CloudFront: 未特定",
                False,
                "REQUIRE_CLOUDFRONT=true だが Distribution が特定できず",
            )
        else:
            _skip("CloudFront: DefaultRoot/OAC/CSP", "配信を特定できず（任意）")

    # 8) 所有権チェック（指定スタックの所有物か）
    strict = _ownership_required()

    def own_check(name: str, typ: str, pid: Optional[str]):
        if not pid:
            _skip(name, "IDが未設定のためスキップ")
            return
        ok = _belongs(typ, pid)
        _add(
            f"Ownership: {name}",
            ok,
            "指定スタックの所有物" if ok else "指定スタック外（不一致）",
            {"Type": typ, "PhysicalId": pid},
            critical=strict,
        )

    # 物理IDを確認
    own_check(
        "Cognito UserPool", "AWS::Cognito::UserPool", ctx.get("COGNITO_USER_POOL_ID")
    )
    own_check(
        "Cognito AppClient",
        "AWS::Cognito::UserPoolClient",
        ctx.get("COGNITO_APP_CLIENT_ID"),
    )
    if ctx.get("COGNITO_IDENTITY_POOL_ID"):
        own_check(
            "Cognito IdentityPool",
            "AWS::Cognito::IdentityPool",
            ctx.get("COGNITO_IDENTITY_POOL_ID"),
        )
    if ctx.get("CLOUDFRONT_DISTRIBUTION_ID"):
        own_check(
            "CloudFront Distribution",
            "AWS::CloudFront::Distribution",
            ctx.get("CLOUDFRONT_DISTRIBUTION_ID"),
        )
    if ctx.get("S3_BUCKET"):
        own_check("S3 Bucket", "AWS::S3::Bucket", ctx.get("S3_BUCKET"))
    if ctx.get("IOT_PROVISIONING_TEMPLATE"):
        own_check(
            "IoT ProvisioningTemplate",
            "AWS::IoT::ProvisioningTemplate",
            ctx.get("IOT_PROVISIONING_TEMPLATE"),
        )

    # 9) .env 候補の出力
    emit = _getenv("EMIT_DISCOVERED_ENV", "false").lower() == "true"
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
