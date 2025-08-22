#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS IoT: MQTT 経由の証明書ローテーション E2E 検証スクリプト
- claim 証明書で接続
- $aws/certificates/create/json で新しい本番証明書/鍵を取得
- $aws/provisioning-templates/<template>/provision/json で RegisterThing
- 新本番証明書で再接続し、Shadow の GET 応答（accepted）で「有効化」を確認
※ すべて QoS=1。Publish 前に accepted/rejected を Subscribe 済みにする。
"""

import os, ssl, json, time, stat, threading, argparse
import uuid
from typing import Optional
import paho.mqtt.client as mqtt

# ======== 設定 =========
IOT_ENDPOINT = "a2osrgpri6xnln-ats.iot.ap-northeast-1.amazonaws.com"  # IoT データエンドポイント
PORT = 8883

# claim（20年・更新専用）で最初に接続する
CLAIM_CERT = "./cert/claim.crt"
CLAIM_KEY  = "./cert/claim.key"

# 新しい本番証明書/鍵を書き出す先
NEW_CERT_OUT = "./cert/new_production.crt"
NEW_KEY_OUT  = "./cert/new_production.key"

# Amazon ルート CA（例：AmazonRootCA1.pem）
ROOT_CA = "./cert/AmazonRootCA1.pem"

# Fleet Provisioning
TEMPLATE_NAME = "amr-prod-template"
PROVISION_TOPIC = f"$aws/provisioning-templates/{TEMPLATE_NAME}/provision/json"
PROVISION_ACCEPTED = PROVISION_TOPIC + "/accepted"
PROVISION_REJECTED = PROVISION_TOPIC + "/rejected"

# CreateKeysAndCertificate（MQTT API）
CREATE_TOPIC = "$aws/certificates/create/json"
CREATE_ACCEPTED = CREATE_TOPIC + "/accepted"
CREATE_REJECTED = CREATE_TOPIC + "/rejected"

# RegisterThing の parameters（テンプレートのプレースホルダに合わせて）
PARAMETERS = {"SerialNumber": "001"}  # 必要に応じて追加/変更

# 検証方法：Shadow GET が accepted で返れば「本番証明書で有効」
def shadow_topics(thing_name: str):
    base = f"$aws/things/{thing_name}/shadow"
    return (f"{base}/get", f"{base}/get/accepted", f"{base}/get/rejected")

# 任意の自己検証用トピック（自分にエコーさせる）
def verify_topics(thing_name: str):
    t = f"amr/{thing_name}/cert-rotate/verify"
    return t, t  # publish と subscribe 同一でOK


# ======== ユーティリティ =========
def secure_write(path: str, data: str, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)

def wait_event(evt: threading.Event, timeout: float, what: str):
    if not evt.wait(timeout):
        raise TimeoutError(f"タイムアウト: {what}")


# ======== MQTT クライアント（共通） =========
class MqttSession:
    def __init__(self, client_id: str, certfile: str, keyfile: str):
        self.client = mqtt.Client(client_id=client_id, clean_session=True, protocol=mqtt.MQTTv311)
        self.client.tls_set(
            ca_certs=ROOT_CA,
            certfile=certfile,
            keyfile=keyfile,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        self.client.tls_insecure_set(False)
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = self._on_subscribe
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        self._connected = threading.Event()
        self._messages = {}  # topic -> last json payload
        self._suback = threading.Event()
        self.client.on_subscribe = self._on_subscribe

    def _on_subscribe(self, c, userdata, mid, granted_qos, properties=None):
        self._suback.set()

    def _on_connect(self, c, userdata, flags, rc):
        if rc == 0:
            print(f"[OK] Connected: rc={rc}")
            self._connected.set()
        else:
            print(f"[ERR] Connect failed: rc={rc}")

    def _on_disconnect(self, c, userdata, rc):
        print(f"[INFO] Disconnected: rc={rc}")

    def _on_message(self, c, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8") if msg.payload else ""
            js = json.loads(payload) if payload else {}
        except Exception:
            js = {"_raw": msg.payload.decode("utf-8", errors="ignore")}
        self._messages[msg.topic] = js
        print(f"[MSG] {msg.topic} -> {js}")

    def connect(self):
        self.client.connect(IOT_ENDPOINT, PORT, keepalive=60)
        self.client.loop_start()
        wait_event(self._connected, 20, "MQTT 接続")

    def disconnect(self):
        try:
            self.client.loop_stop()
        except Exception:
            pass
        try:
            self.client.disconnect()
        except Exception:
            pass

    # def subscribe(self, topics_qos1):
    #     # topics_qos1: list[str]
    #     for tp in topics_qos1:
    #         print(f"[SUB] {tp}")
    #         self.client.subscribe(tp, qos=1)
    def subscribe(self, topics_qos1):
        for tp in topics_qos1:
            print(f"[SUB] {tp}")
            self._suback.clear()
            (rc, mid) = self.client.subscribe(tp, qos=1)
            if rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f"Subscribe失敗: {tp} rc={rc}")
            wait_event(self._suback, 5, f"SUBACK: {tp}")

    def publish_json(self, topic: str, obj):
        payload = json.dumps(obj).encode("utf-8")
        print(f"[PUB] {topic} -> {obj}")
        r = self.client.publish(topic, payload=payload, qos=1)
        r.wait_for_publish()
        if r.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"Publish に失敗: {topic} rc={r.rc}")

    def last_message(self, topic: str) -> Optional[dict]:
        return self._messages.get(topic)


# ======== メインフロー =========
def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--thing", default=None, help="既知の Thing 名（テンプレート側で自動採番なら省略可）")
    args = parser.parse_args()

    # --- 1) claim で接続 ---
    claim_id = f"claim-{uuid.uuid4().hex[:8]}"
    claim = MqttSession(client_id=claim_id, certfile=CLAIM_CERT, keyfile=CLAIM_KEY)
    claim.connect()

    # 受信（accepted/rejected）を先に subscribe
    claim.subscribe([CREATE_ACCEPTED, CREATE_REJECTED, PROVISION_ACCEPTED, PROVISION_REJECTED])

    # --- 2) 新しい鍵/証明書を作成 ---
    create_ev = threading.Event()
    provision_ev = threading.Event()

    def wait_create():
        # ポーリングで簡易待機（受信は callback が埋める）
        for _ in range(200):  # ~20秒
            m = claim.last_message(CREATE_ACCEPTED) or claim.last_message(CREATE_REJECTED)
            if m:
                return m
            time.sleep(0.1)
        return None

    def wait_provision():
        for _ in range(300):  # ~30秒
            m = claim.last_message(PROVISION_ACCEPTED) or claim.last_message(PROVISION_REJECTED)
            if m:
                return m
            time.sleep(0.1)
        return None

    # Publish（空 JSON）
    claim.publish_json(CREATE_TOPIC, {})

    resp = wait_create()
    if resp is None:
        raise TimeoutError("CreateKeysAndCertificate の応答なし")
    if "certificatePem" not in resp or "privateKey" not in resp or "certificateOwnershipToken" not in resp:
        raise RuntimeError(f"CreateKeysAndCertificate が失敗: {resp}")

    new_cert_pem = resp["certificatePem"]
    new_priv_key = resp["privateKey"]
    token = resp["certificateOwnershipToken"]

    # 書き出し（0600）
    os.makedirs(os.path.dirname(NEW_CERT_OUT), exist_ok=True)
    secure_write(NEW_CERT_OUT, new_cert_pem, 0o600)
    secure_write(NEW_KEY_OUT, new_priv_key, 0o600)
    print(f"[OK] 新しい本番証明書/鍵を書き出し: {NEW_CERT_OUT}, {NEW_KEY_OUT}")

    # --- 3) RegisterThing（provision）---
    params = dict(PARAMETERS)  # コピー
    if args.thing:
        # テンプレートが ThingName を受けるならここで渡す（テンプレート側に合わせて key 名を調整）
        params.setdefault("ThingName", args.thing)

    claim.publish_json(PROVISION_TOPIC, {
        "certificateOwnershipToken": token,
        "parameters": params
    })

    resp2 = wait_provision()
    if resp2 is None:
        raise TimeoutError("RegisterThing (provision) の応答なし")
    if resp2 is claim.last_message(PROVISION_REJECTED):
        raise RuntimeError(f"RegisterThing が rejected: {resp2}")

    # 期待ペイロードの一例: {"thingName": "...", ...}
    thing_name = resp2.get("thingName") or params.get("ThingName") or "UNKNOWN"
    print(f"[OK] RegisterThing accepted: thingName={thing_name}")

    # claim セッションを終了
    claim.disconnect()
    time.sleep(1.0)

    # --- 4) 新・本番証明書で再接続して検証 ---
    # prod_id = f"{thing_name}-prod-{uuid.uuid4().hex[:4]}"
    prod_id = thing_name
    prod = MqttSession(client_id=prod_id, certfile=NEW_CERT_OUT, keyfile=NEW_KEY_OUT)
    prod.connect()

    # 検証1：Shadow GET → accepted が返るか
    get_topic, get_acc, get_rej = shadow_topics(thing_name)
    # prod.subscribe([get_acc, get_rej])
    # GET/UPDATE の両方を購読
    upd_topic_acc = f"$aws/things/{thing_name}/shadow/update/accepted"
    upd_topic_rej = f"$aws/things/{thing_name}/shadow/update/rejected"
    prod.subscribe([get_acc, get_rej, upd_topic_acc, upd_topic_rej])
    prod.publish_json(get_topic, {})  # GET は空 JSON

    ok = False
    for _ in range(200):  # ~20秒
        if prod.last_message(get_acc):
            print(f"[OK] Shadow GET accepted を受信。新本番証明書での権限有効を確認。")
            ok = True
            break
        # if prod.last_message(get_rej):
        #     raise RuntimeError(f"Shadow GET が rejected: {prod.last_message(get_rej)}")
        rej = prod.last_message(get_rej)
        if rej:
            # 404: Shadow がまだ存在しない → 最小 update で作ってから再GET
            if rej.get("code") == 404:
                print("[INFO] Shadow が未作成。最小 update で作成します。")
                # 端末の“自己紹介”など、無害な reported を1つ置く
                init_doc = {"state": {"reported": {"_init": True, "ts": int(time.time())}}}
                prod.publish_json(f"$aws/things/{thing_name}/shadow/update", init_doc)
                # update/accepted 待ち
                for _ in range(200):
                    if prod.last_message(upd_topic_acc):
                        print("[OK] Shadow update accepted（初期作成）。再度 GET します。")
                        break
                    err2 = prod.last_message(upd_topic_rej)
                    if err2:
                        raise RuntimeError(f"Shadow update が rejected: {err2}")
                    time.sleep(0.1)
                # 再GET
                prod.publish_json(get_topic, {})
                # 以降のループで拾う
            else:
                raise RuntimeError(f"Shadow GET が rejected: {rej}")
        time.sleep(0.1)

    # 検証2：自エコー（任意）。Subscribeして Publish → 自分自身にも配信されることを確認
    if ok:
        v_pub, v_sub = verify_topics(thing_name)
        prod.subscribe([v_sub])
        payload = {"ts": int(time.time()), "msg": "cert-rotation-verify"}
        prod.publish_json(v_pub, payload)

        echoed = False
        for _ in range(100):
            m = prod.last_message(v_sub)
            if m and m.get("msg") == "cert-rotation-verify":
                echoed = True
                print("[OK] 検証 Publish を自分で受信できた（トピック権限 OK）")
                break
            time.sleep(0.1)

        if not echoed:
            print("[WARN] 自エコーは未確認（Subscribe/Pub のタイミングやポリシー範囲を確認してください）")

    prod.disconnect()
    print("[DONE] 証明書ローテーション検証フロー完了")

if __name__ == "__main__":
    run()
