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
```

### 1-3. CloudFront で無効化（任意）
```bash
aws cloudfront create-invalidation \
  --distribution-id <DIST_ID> \
  --paths "/*"
```
