#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
役割: 設備側サーバ（MQTT/TLS 8883, X.509）＋ MqttSession（移植）
参照: README の「IoT 接続」「メッセージ設計」章、手順書の該当セクション
注意: 本ファイル単体で動作。公開識別子のみ使用（クライアントシークレットは扱わない）。
"""

import json
import ssl
import time
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

import paho.mqtt.client as mqtt

# ========= 設定（自環境の値に更新） =========
IOT_ENDPOINT = "a2osrgpri6xnln-ats.iot.ap-northeast-1.amazonaws.com"  # README の「IoT 接続」参照
PORT = 8883
THING_NAME   = "AMR-001"                                              # Provisioning で確定した Thing 名に合わせる（clientId と一致）
SHADOW_NAME  = "robot"                                                # 名前付き Shadow
ROOT_CA_PATH = "./certs/AmazonRootCA1.pem"
CERT_PATH    = "./certs/new_production.crt"
KEY_PATH     = "./certs/new_production.key"

# トピック
TOPIC_CALL   = f"amr/{THING_NAME}/cmd/call"
TOPIC_STATUS = f"amr/{THING_NAME}/status"

# Shadow トピック
SHADOW_BASE   = f"$aws/things/{THING_NAME}/shadow/name/{SHADOW_NAME}"
SHADOW_UPDATE = f"{SHADOW_BASE}/update"
SHADOW_GET    = f"{SHADOW_BASE}/get"

# 送信 QoS / Heartbeat
QOS = 1
HEARTBEAT_SEC = 10
MOVING_SECONDS = 5

# ========= 内部状態 =========
state_lock = threading.Lock()
current_state = "idle"
last_request_id: Optional[str] = None
reported_version = 0  # 簡易管理（厳密な version 連携は README 参照）

def now_ms() -> int:
    return int(time.time() * 1000)

def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ======== ユーティリティ（provision_and_verify と同等） ========
def wait_event(evt: threading.Event, timeout: float, what: str):
    if not evt.wait(timeout):
        raise TimeoutError(f"タイムアウト: {what}")  # CHANGED: 明示

# ========（移植）MQTT セッション薄ラッパ ========
class MqttSession:
    """
    provision_and_verify.py の MqttSession を移植（接続待機/SUBACK待機/Publish 完了待機）。
    - SUBACK 待機: subscribe 後に 5 秒タイムアウトで同期
    - Publish 完了待機: QoS1 の配信完了を待って rc を確認
    """
    def __init__(self, client_id: str, certfile: str, keyfile: str):
        self.client = mqtt.Client(client_id=client_id, clean_session=True, protocol=mqtt.MQTTv311)
        self.client.tls_set(
            ca_certs=ROOT_CA_PATH,
            certfile=certfile,
            keyfile=keyfile,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,  # provision_and_verify と同一設定 :contentReference[oaicite:4]{index=4}
        )
        self.client.tls_insecure_set(False)
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = self._on_subscribe
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        self._connected = threading.Event()
        self._messages: dict[str, dict] = {}  # topic -> last json payload
        self._suback = threading.Event()

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
        self.client.connect(IOT_ENDPOINT, PORT, keepalive=60)  # provision_and_verify と同一パス :contentReference[oaicite:5]{index=5}
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

    def subscribe(self, topics_qos1: list[str]):
        for tp in topics_qos1:
            print(f"[SUB] {tp}")
            self._suback.clear()
            (rc, mid) = self.client.subscribe(tp, qos=1)
            if rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f"Subscribe失敗: {tp} rc={rc}")
            wait_event(self._suback, 5, f"SUBACK: {tp}")  # SUBACK 待機（移植）

    def publish_json(self, topic: str, obj, retain: bool = False):  # ADDED: retain を追加（status/LWT 用）
        payload = json.dumps(obj).encode("utf-8")
        print(f"[PUB] {topic} -> {obj}")
        r = self.client.publish(topic, payload=payload, qos=1, retain=retain)
        r.wait_for_publish()
        if r.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"Publish に失敗: {topic} rc={r.rc}")

    def last_message(self, topic: str) -> Optional[dict]:
        return self._messages.get(topic)

# ======== アプリ固有ロジック ========
def build_status_payload():
    with state_lock:
        payload = {
            "state": current_state,
            "updatedAt": now_ms(),
            "heartbeatAt": now_ms(),
        }
        if last_request_id:
            payload["requestId"] = last_request_id
        return payload

def publish_status(sess: MqttSession, heartbeat=False):
    payload = build_status_payload()
    if heartbeat:
        payload["heartbeatAt"] = now_ms()
    sess.publish_json(TOPIC_STATUS, payload, retain=True)  # retain は True

def shadow_report(sess: MqttSession):
    global reported_version
    with state_lock:
        reported_version += 1
        doc = {
            "state": {"reported": {
                "state": current_state,
                "version": reported_version,
                "updatedAt": now_ms()
            }}
        }
    sess.publish_json(SHADOW_UPDATE, doc)

def to_idle(sess: MqttSession):
    global current_state, last_request_id
    with state_lock:
        current_state = "idle"
    shadow_report(sess)
    publish_status(sess)

def handle_message(sess: MqttSession, msg):
    global current_state, last_request_id
    try:
        if msg.topic == TOPIC_CALL:
            data = json.loads(msg.payload.decode("utf-8")) if msg.payload else {}
            req_id = data.get("requestId", str(uuid.uuid4()))
            dest = data.get("dest", "A-01")
            print(f"[call] dest={dest} reqId={req_id}")

            with state_lock:
                current_state = "moving"
                last_request_id = req_id

            shadow_report(sess)
            publish_status(sess)

            # 5秒後に idle へ戻す
            threading.Timer(MOVING_SECONDS, to_idle, args=(sess,)).start()
        else:
            # 必要に応じて Shadow 応答などをログ
            pass
    except Exception as e:
        print(f"[message] error: {e}")

def heartbeat_loop(sess: MqttSession):
    while True:
        try:
            publish_status(sess, heartbeat=True)
        except Exception as e:
            print(f"[heartbeat] error: {e}")
        time.sleep(HEARTBEAT_SEC)

def main():
    # --- MqttSession の生成（provision_and_verify と同じ TLS/接続フロー）---
    sess = MqttSession(client_id=THING_NAME, certfile=CERT_PATH, keyfile=KEY_PATH)

    # LWT（異常切断時に offline を retain）
    lwt = {"state": "offline", "updatedAt": now_ms()}
    sess.client.will_set(TOPIC_STATUS, json.dumps(lwt), qos=QOS, retain=True)

    # 受信ハンドラ（本ファイルのロジックを呼ぶ）
    sess.client.on_message = lambda c, u, m: handle_message(sess, m)

    print("[connect] connecting to IoT Core ...")
    sess.connect()

    # 先に購読（SUBACK 待機）
    sess.subscribe([TOPIC_CALL])

    # Shadow GET（権威の確認）と初期 status
    try:
        sess.publish_json(SHADOW_GET, {})  # GET は空 JSON
    except Exception as e:
        print(f"[shadow-get] error: {e}")
    publish_status(sess)

    # Heartbeat
    threading.Thread(target=heartbeat_loop, args=(sess,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("bye")
    finally:
        sess.disconnect()

if __name__ == "__main__":
    main()
