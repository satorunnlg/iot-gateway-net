#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
役割: 設備側サーバ（MQTT/TLS 8883, X.509）
シンプル版 - 基本的なフローでAMR状態管理
"""

import json
import ssl
import time
import threading
import uuid
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

# ========= 設定（すべて定数で定義） =========
IOT_ENDPOINT = "a2osrgpri6xnln-ats.iot.ap-northeast-1.amazonaws.com"
PORT = 8883
THING_NAME = "AMR-001"
SHADOW_NAME = "robot"
ROOT_CA_PATH = "./certs/AmazonRootCA1.pem"
CERT_PATH = "./certs/new_production.crt"
KEY_PATH = "./certs/new_production.key"

# トピック
TOPIC_CALL = f"amr/{THING_NAME}/cmd/call"
TOPIC_STATUS = f"amr/{THING_NAME}/status"
SHADOW_UPDATE = f"$aws/things/{THING_NAME}/shadow/name/{SHADOW_NAME}/update"
SHADOW_GET = f"$aws/things/{THING_NAME}/shadow/name/{SHADOW_NAME}/get"

# タイミング設定
QOS = 1
HEARTBEAT_INTERVAL = 10  # 秒
MOVING_DURATION = 5  # 秒

# ========= グローバル状態 =========
current_state = "idle"
last_request_id = None
reported_version = 0
state_lock = threading.Lock()


def now_ms():
    """現在時刻をミリ秒で取得"""
    return int(time.time() * 1000)


def build_status_payload():
    """ステータスペイロード作成"""
    with state_lock:
        payload = {
            "state": current_state,
            "updatedAt": now_ms(),
            "heartbeatAt": now_ms(),
        }
        if last_request_id:
            payload["requestId"] = last_request_id
        return payload


def publish_status(client, heartbeat=False):
    """ステータス発行"""
    payload = build_status_payload()
    if heartbeat:
        payload["heartbeatAt"] = now_ms()

    try:
        client.publish(TOPIC_STATUS, json.dumps(payload), qos=QOS, retain=True)
        if heartbeat:
            print(f"[HB] {payload['state']}")
        else:
            print(f"[STATUS] {payload['state']}")
    except Exception as e:
        print(f"[ERROR] ステータス発行エラー: {e}")


def publish_shadow(client):
    """Shadow状態報告"""
    global reported_version
    with state_lock:
        reported_version += 1
        doc = {
            "state": {
                "reported": {
                    "state": current_state,
                    "version": reported_version,
                    "updatedAt": now_ms(),
                }
            }
        }

    try:
        client.publish(SHADOW_UPDATE, json.dumps(doc), qos=QOS)
        print(f"[SHADOW] 状態更新: {current_state}")
    except Exception as e:
        print(f"[ERROR] Shadow更新エラー: {e}")


def transition_to_idle(client):
    """アイドル状態に遷移"""
    global current_state
    with state_lock:
        current_state = "idle"

    publish_shadow(client)
    publish_status(client)
    print("[TRANSITION] moving -> idle")


def handle_call_message(client, payload):
    """呼出しメッセージ処理"""
    global current_state, last_request_id

    try:
        data = json.loads(payload.decode("utf-8"))
        req_id = data.get("requestId", str(uuid.uuid4()))
        dest = data.get("dest", "A-01")

        print(f"[CALL] 呼出し受信: dest={dest}, requestId={req_id}")

        with state_lock:
            current_state = "moving"
            last_request_id = req_id

        # 状態更新
        publish_shadow(client)
        publish_status(client)

        # 移動完了タイマー設定
        timer = threading.Timer(MOVING_DURATION, transition_to_idle, args=(client,))
        timer.daemon = True
        timer.start()

    except Exception as e:
        print(f"[ERROR] 呼出し処理エラー: {e}")


def heartbeat_loop(client):
    """ハートビートループ"""
    while True:
        try:
            publish_status(client, heartbeat=True)
        except Exception as e:
            print(f"[ERROR] ハートビートエラー: {e}")
        time.sleep(HEARTBEAT_INTERVAL)


# ========= MQTTコールバック =========
def on_connect(client, userdata, flags, rc):
    """接続コールバック"""
    if rc == 0:
        print("[MQTT] 接続成功")

        # 購読開始
        client.subscribe(TOPIC_CALL, qos=QOS)
        print(f"[MQTT] 購読開始: {TOPIC_CALL}")

        # Shadow GET（初期同期）
        client.publish(SHADOW_GET, "{}", qos=QOS)

        # 初期ステータス発行
        publish_status(client)

        # ハートビート開始
        hb_thread = threading.Thread(target=heartbeat_loop, args=(client,), daemon=True)
        hb_thread.start()
        print(f"[HEARTBEAT] 開始 (間隔: {HEARTBEAT_INTERVAL}秒)")

    else:
        print(f"[ERROR] 接続失敗: rc={rc}")


def on_message(client, userdata, msg):
    """メッセージ受信コールバック"""
    try:
        if msg.topic == TOPIC_CALL:
            handle_call_message(client, msg.payload)
        else:
            # その他のメッセージ（Shadow応答など）
            payload = json.loads(msg.payload.decode("utf-8"))
            print(f"[MSG] {msg.topic}: {payload}")
    except Exception as e:
        print(f"[ERROR] メッセージ処理エラー: {e}")


def on_disconnect(client, userdata, rc):
    """切断コールバック"""
    print(f"[MQTT] 切断: rc={rc}")


def main():
    """メイン実行関数"""
    print("=== AMR Server 開始 ===")
    print(f"Thing: {THING_NAME}")
    print(f"Endpoint: {IOT_ENDPOINT}")
    print(f"Shadow: {SHADOW_NAME}")

    # MQTTクライアント作成
    client = mqtt.Client(
        client_id=THING_NAME, clean_session=True, protocol=mqtt.MQTTv311
    )

    # TLS設定
    try:
        client.tls_set(
            ca_certs=ROOT_CA_PATH,
            certfile=CERT_PATH,
            keyfile=KEY_PATH,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        client.tls_insecure_set(False)
    except Exception as e:
        print(f"[ERROR] TLS設定エラー: {e}")
        return

    # コールバック設定
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    # LWT設定
    lwt_payload = {"state": "offline", "updatedAt": now_ms()}
    client.will_set(TOPIC_STATUS, json.dumps(lwt_payload), qos=QOS, retain=True)

    # 接続
    try:
        print("[MQTT] 接続開始...")
        client.connect(IOT_ENDPOINT, PORT, keepalive=60)
        client.loop_start()

        # メインループ
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[EXIT] 終了シグナル受信")
    except Exception as e:
        print(f"[ERROR] 実行エラー: {e}")
    finally:
        # 最終ステータス送信
        global current_state
        with state_lock:
            current_state = "offline"
        publish_status(client)

        client.loop_stop()
        client.disconnect()
        print("[EXIT] 終了")


if __name__ == "__main__":
    main()
