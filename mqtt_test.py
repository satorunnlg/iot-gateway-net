# mqtt_test_fixed.py
import boto3
import datetime
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import paho.mqtt.client as mqtt
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
import sys
import ssl, socket, time, os, base64

# --- 設定 ---
REGION = "ap-northeast-1"
USER_POOL_ID = "ap-northeast-1_2jfmfM2GA"
CLIENT_ID = "l8r960o0rgade8fbdppdghr04"
IDENTITY_POOL_ID = "ap-northeast-1:4b39a8fb-49d2-429f-9523-a5c7534d9ab0"
IOT_ENDPOINT = "a2osrgpri6xnln-ats.iot.ap-northeast-1.amazonaws.com"
USERNAME = "org-operator"
PASSWORD = "Lead9313-"  # 実運用では環境変数/Secretに

# --- Cognito: ユーザープール認証 → IDプールで STS 一時クレデンシャル取得 ---
def get_iot_credentials() -> dict | None:
    try:
        idp = boto3.client("cognito-idp", region_name=REGION)
        auth = idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": USERNAME, "PASSWORD": PASSWORD},
            ClientId=CLIENT_ID,
        )
        id_token = auth["AuthenticationResult"]["IdToken"]
    except Exception as e:
        print(f"[auth] ユーザープール認証エラー: {e}")
        return None

    try:
        ident = boto3.client("cognito-identity", region_name=REGION)
        id_res = ident.get_id(
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token},
        )
        identity_id = id_res["IdentityId"]
        cred_res = ident.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token},
        )
        return identity_id, cred_res["Credentials"]  # dict: AccessKeyId/SecretKey/SessionToken/Expiration
    except Exception as e:
        print(f"[auth] GetCredentialsForIdentity エラー: {e}")
        return None

# --- SigV4: WebSocket用のクエリ署名URLを作る（/mqtt?X-Amz-...） ---
def create_presigned_ws_url(credentials: dict, endpoint: str, region: str, expires: int = 60) -> str:
    # 1) /mqtt?X-Amz-Security-Token=... を先に作る（＝署名対象に含める）
    base = f"https://{endpoint}/mqtt"
    pre = urlparse(base)
    q = dict(parse_qsl(pre.query, keep_blank_values=True))
    q["X-Amz-Security-Token"] = credentials["SessionToken"]
    url_with_token = urlunparse(pre._replace(query=urlencode(q, safe="~")))

    # 2) そのURLに対してクエリ署名（SigV4QueryAuth）
    creds = Credentials(
        access_key=credentials["AccessKeyId"],
        secret_key=credentials["SecretKey"],
        token=credentials["SessionToken"],
    )
    req = AWSRequest(method="GET", url=url_with_token)
    SigV4QueryAuth(creds, "iotdevicegateway", region, expires=expires).add_auth(req)

    # 3) これで完成。以後クエリは変更しない！
    return req.url

# --- MQTT コールバック ---
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("[mqtt] 接続成功")
        client.subscribe("my/topic")
        client.publish("my/topic", payload="Hello via wss+SigV4", qos=0)
    else:
        print(f"[mqtt] 接続失敗 rc={rc}")

def on_message(client, userdata, msg):
    print(f"[mqtt] {msg.topic}: {msg.payload.decode()}")

def main():
    print("[main] 認証～署名URL生成...")
    identity_id, creds = get_iot_credentials()
    if not creds:
        print("[main] 認証情報取得に失敗しました。終了。")
        sys.exit(1)

    # 署名URLを使って paho を接続（main内）
    presigned = create_presigned_ws_url(creds, IOT_ENDPOINT, REGION, expires=60)
    u = urlparse(presigned)
    ws_path = u.path + ("?" + u.query if u.query else "")

    client = mqtt.Client(
        client_id=identity_id,          # ← IoTポリシーと合わせるなら IdentityId をそのまま
        transport="websockets",
        protocol=mqtt.MQTTv311
    )
    client.enable_logger()
    client.tls_set()                    # wss に必須
    client.ws_set_options(path=ws_path) # ← パス＋クエリだけ渡す
    client.connect(host=IOT_ENDPOINT, port=443, keepalive=60)
    client.loop_start()

    # ついでに簡単な publish を試す
    time.sleep(1)
    client.publish("amr/test", "hello via wss+cognito", qos=0)

if __name__ == "__main__":
    main()
