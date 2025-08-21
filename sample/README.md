# Iot-gateway-net / sample
本ディレクトリは **サンプル実行に最低限必要なものだけ** を集約しています。  
アーキテクチャ仕様やセキュリティ要件は上位の `docs/` を参照してください。

- ブラウザ側（S3/CloudFront）：`sample/s3/`
- 設備側 Thing（Raspberry Pi / Python）：`sample/thing/`

---

## 前提
- AWS リージョン：ap-northeast-1（東京）
- Cognito（User Pool/Identity Pool）、IoT Core、S3/CloudFront は `docs/` の手順どおりに構築済み
- 共有アカウント方式（User Pool ユーザー `org-operator` へ Passkey 登録）を利用
- サンプルは **PoC 用最小構成**。商用導入時は `docs/` のセキュリティ要件を遵守

---

## 1) ブラウザ側（S3）セットアップ

### 1-1. `config.js` の TODO を置換
`sample/s3/config.js` の各値（公開識別子）を自アカウントに合わせて修正します。
- `region`: `"ap-northeast-1"`
- `userPoolId`: `ap-northeast-1_XXXXXXXXX`
- `userPoolClientId`: `xxxxxxxxxxxxxxxxxxxxxx`（**public client**）
- `userPoolDomain`: `xxxxxxxx.auth.ap-northeast-1.amazoncognito.com`
- `identityPoolId`: `ap-northeast-1:xxxx-xxxx-...`
- `redirectUri`: `https://<CloudFrontドメイン>/index.html`
- `iotEndpoint`: `xxxxxxxxxxxxxx-ats.iot.ap-northeast-1.amazonaws.com`
- `thingName`: `AMR-001`
- `shadowName`: `robot`

> メモ：`config.js` は **公開識別子のみ**を含みます。クライアントシークレットや長期アクセスキー等は絶対に含めないでください。

### 1-2. S3 へアップロード（AWS CLI）
```bash
# 例: バケット名を環境変数に
export BUCKET_NAME=my-iotgw-sample-site-bucket

aws s3 sync ./sample/s3 s3://$BUCKET_NAME/ \
  --exclude ".DS_Store" --cache-control "no-cache"
````

### 1-3. CloudFront で無効化（任意）

```bash
aws cloudfront create-invalidation \
  --distribution-id <DIST_ID> \
  --paths "/*"
```

---

## 2) 設備側 Thing（Raspberry Pi）セットアップ

### 2-1. venv 構築と依存インストール

```bash
cd sample/thing
python3 -m venv venv
. venv/bin/activate             # Windowsの場合: venv\Scripts\activate
pip install -U pip
pip install -r requirements.txt
```

### 2-2. 証明書を配置

`sample/thing/certs/` に以下を配置します（**git管理しない**）。

* `AmazonRootCA1.pem`（ATS Root CA）
* `device.pem.crt`（本番用デバイス証明書）
* `private.pem.key`（本番用秘密鍵）

> 参考：ブートストラップ証明書（claim）は通常ファクトリ段階で別領域に格納。
> 本サンプルは **本番証明書での接続デモ** を想定しています。

### 2-3. エンドポイント等の設定

`server.py` の先頭付近の `TODO` を修正します。

* `IOT_ENDPOINT`
* `THING_NAME`
* 証明書パス（必要に応じて相対パスを調整）

### 2-4. 実行

```bash
. venv/bin/activate
python server.py
```

**ログの期待値**

* 接続成功：`[connect] rc=0`
* 購読開始 & Shadow GET 発行
* 10 秒ごとに Heartbeat を `amr/<THING>/status` へ retain + QoS1 で配信
* ブラウザから呼び出しで `moving` → 5 秒後 `idle` 復帰

---

## 3) 動作確認

### 3-1. 認証（共有アカウントのパスキー）

1. ブラウザで CloudFront の URL にアクセス
2. 「サインイン」→ Hosted UI → `org-operator` の **Passkey でサインイン**
3. 初回端末は「この端末を登録」で **パスキー追加**

### 3-2. MQTT 接続

* サインイン後、自動で **SigV4 署名付き WSS** で IoT Core に接続
* 初期同期：retain `status` + Shadow GET（保険）
* 画面の状態が「接続済み」になり、ボタンが有効化される

### 3-3. 呼び出しと状態遷移

* 「呼出し」→ `amr/<THING>/cmd/call` を Publish
* Pi 側が `moving` に遷移 → 5 秒後 `idle` に戻る
* Heartbeat は 10 秒周期。**25 秒欠落**で UI は「通信不良（再同期中）」と表示し Shadow GET を発行

---

## 4) セキュリティ注意事項（サンプル運用時）

* `config.js` には **公開識別子のみ**。
* Identity Pool 認証ロールの IAM は **clientId/トピックを最小権限**に制限（本番前に必須）。
* S3 は **Block Public Access + CloudFront OAC** で配布。
* WAF で **組織プロキシ IP 許可 + レート制限 + マネージドルール** を適用。
* 設備側の秘密鍵は **端末外へ出さない**（TPM/SE 推奨）。

---

````

---

# 5) 既存ファイルからの差分（移動ガイド）

- `client/index.html` → `sample/s3/index.html`  
- `client/app.js` → `sample/s3/app.js`  
- `client/config.js` → `sample/s3/config.js`  
- `server/server.py` → `sample/thing/server.py`  
- `server/requirements.txt` → `sample/thing/requirements.txt`

**スクリプト内の相対パス**だけ、上記構成に合わせて修正してください（前述の例を参照）。

---

# 6) 便利コマンド例（任意）

## S3 へ同期
```bash
export BUCKET_NAME=my-iotgw-sample-site-bucket
aws s3 sync ./sample/s3 s3://$BUCKET_NAME/ --delete --exclude ".DS_Store"
````

## CloudFront 無効化

```bash
aws cloudfront create-invalidation --distribution-id <DIST_ID> --paths "/*"
```

## Raspberry Pi（再起動時に自動起動したい場合の systemd）

`/etc/systemd/system/iotgw-sample.service`

```ini
[Unit]
Description=Iot-gateway-net sample thing
After=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/Iot-gateway-net/sample/thing
ExecStart=/home/pi/Iot-gateway-net/sample/thing/venv/bin/python server.py
Restart=on-failure
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable iotgw-sample.service
sudo systemctl start iotgw-sample.service
sudo systemctl status iotgw-sample.service
```

---