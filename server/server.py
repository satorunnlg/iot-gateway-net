#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Raspberry Pi（現場サーバ機）サンプル
- MQTT/TLS(8883)で AWS IoT Core に接続（X.509）
- コマンド amr/<THING>/cmd/call を受信すると moving へ遷移し、5秒後に idle へ戻す
- ステータス amr/<THING>/status を retain + QoS1 で配信
- 10秒ごとに Heartbeat（status に heartbeatAt を更新）
- Shadow（名前付き: robot）に reported.state を反映
- LWT: offline を retain で宣言

前提:
- 証明書（本番/ブートストラップは別だが、接続時は本番証明書を使用）
- Amazon Root CA 証明書（ATS）
"""

import json
import ssl
import time
import threading
import uuid
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

# ========= 設定（TODO: 事前に値を埋めてください） =========
IOT_ENDPOINT = "xxxxxxxxxxxxxx-ats.iot.ap-northeast-1.amazonaws.com"  # TODO: IoT Core デバイスデータエンドポイント
THING_NAME   = "AMR-001"                                              # TODO: Thing 名
SHADOW_NAME  = "robot"                                                # 名前付きShadow
ROOT_CA_PATH = "/certs/AmazonRootCA1.pem"                             # TODO: ルートCA
CERT_PATH    = "/certs/device.pem.crt"                                # TODO: 本番デバイス証明書
KEY_PATH     = "/certs/private.pem.key"                               # TODO: 本番秘密鍵

# トピック
TOPIC_CALL   = f"amr/{THING_NAME}/cmd/call"
TOPIC_STATUS = f"amr/{THING_NAME}/status"

# Shadow トピック
SHADOW_BASE  = f"$aws/things/{THING_NAME}/shadow/name/{SHADOW_NAME}"
SHADOW_UPDATE= f"{SHADOW_BASE}/update"
SHADOW_GET   = f"{SHADOW_BASE}/get"

# 送信 QoS / Heartbeat
QOS = 1
HEARTBEAT_SEC = 10
MOVING_SECONDS = 5

# ========= 内部状態 =========
state_lock = threading.Lock()
current_state = "idle"
last_request_id = None
reported_version = 0  # 簡易。厳密に version を扱う場合は get/accepted から取得して整合させる

def now_ms():
    return int(time.time() * 1000)

def utc_iso():
    return datetime.now(timezone.utc).isoformat()

def build_status_payload():
    with state_lock:
        payload = {
            "state": current_state,
            "updatedAt": now_ms(),
            "heartbeatAt": now_ms(),  # Heartbeat時は更新、通常は publish 時刻
        }
        if last_request_id:
            payload["requestId"] = last_request_id
        return payload

def publish_status(client, heartbeat=False):
    payload = build_status_payload()
    if heartbeat:
        # heartbeatAtのみを確実に前進させる（他は現状を反映）
        payload["heartbeatAt"] = now_ms()
    client.publish(TOPIC_STATUS, json.dumps(payload), qos=QOS, retain=True)

def shadow_report(client):
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
    client.publish(SHADOW_UPDATE, json.dumps(doc), qos=QOS)

def to_idle(client):
    global current_state, last_request_id
    with state_lock:
        current_state = "idle"
    shadow_report(client)
    publish_status(client)

def on_connect(client, userdata, flags, rc, properties=None):
    print(f"[connect] rc={rc}")
    if rc == 0:
        client.subscribe(TOPIC_CALL, qos=QOS)
        # 起動時に Shadow GET しておく（権威の確認）
        client.publish(SHADOW_GET, json.dumps({}), qos=QOS)
        # 接続直後に現在の状態を retain 配信
        publish_status(client)
    else:
        print("[connect] failed")

def on_message(client, userdata, msg):
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

            shadow_report(client)
            publish_status(client)

            # 5秒後に idle へ
            threading.Timer(MOVING_SECONDS, to_idle, args=(client,)).start()
        else:
            # 必要に応じて Shadow 応答をログ出力
            pass
    except Exception as e:
        print(f"[message] error: {e}")

def on_disconnect(client, userdata, rc, properties=None):
    print(f"[disconnect] rc={rc}")

def heartbeat_loop(client):
    while True:
        try:
            publish_status(client, heartbeat=True)
        except Exception as e:
            print(f"[heartbeat] error: {e}")
        time.sleep(HEARTBEAT_SEC)

def main():
    client_id = THING_NAME  # デバイス側は ThingName を clientId に
    client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311, clean_session=True, transport="tcp")

    # LWT（異常切断検知）
    lwt = {"state":"offline", "updatedAt": now_ms()}
    client.will_set(TOPIC_STATUS, json.dumps(lwt), qos=QOS, retain=True)

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    client.tls_set(ca_certs=ROOT_CA_PATH,
                   certfile=CERT_PATH,
                   keyfile=KEY_PATH,
                   cert_reqs=ssl.CERT_REQUIRED,
                   tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.tls_insecure_set(False)

    print("[connect] connecting to IoT Core ...")
    client.connect(IOT_ENDPOINT, port=8883, keepalive=60)
    client.loop_start()

    # Heartbeat
    threading.Thread(target=heartbeat_loop, args=(client,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("bye")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
