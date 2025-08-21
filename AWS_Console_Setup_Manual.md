# AWS コンソール設定手順書

本書は、AMR（自律移動ロボット）およびモバイル端末・PCを含むシステムにおける **AWS IoT Core / 証明書管理 / API Gateway / WAF / ログ監視** の設定手順をまとめたものです。  
東京リージョン（ap-northeast-1）を前提とします。

---

## 1. 前提条件

- AWS アカウント作成済み
- 管理者権限を持つ IAM ユーザが存在
- IoT Core / API Gateway / CloudWatch が有効化済み
- OpenSSL により発行された **20年有効のブートストラップ証明書**を保持
- 利用者（顧客側）は **共有アカウント方式**で UI にアクセス

---

## 2. IAM とセキュリティ

### 2.1 管理者ユーザの作成
1. コンソールで **IAM → Users → Add user** を選択。
2. ユーザ名: `system-admin`
3. アクセス: **AWS Management Console access**
4. 権限セット: **AdministratorAccess**
5. MFA（多要素認証）を有効化。

### 2.2 インテグレータ用ロール作成
1. **IAM → Roles → Create role**
2. Trusted entity: **AWS account**
3. 権限: `AmazonIoTFullAccess`, `AmazonS3FullAccess`, `AWSIoTConfigAccess`
4. ロール名: `IntegratorRole`

### 2.3 顧客 UI アクセス用ユーザ作成
1. IAM → Users → `customer-ui`
2. 権限は制限：
   - `AmazonAPIGatewayInvokeFullAccess`
   - `AWSIoTDataAccess`
3. **共有アカウント**として運用し、パスワードは顧客へ配布。

---

## 3. IoT Core 設定手順

### 3.1 IoT Core 有効化
1. AWS コンソール → **IoT Core**
2. [Settings] → リージョンを `ap-northeast-1` に固定

### 3.2 デバイスの Thing 登録
1. IoT Core → **Manage → Things → Create things**
2. `Create single thing`
3. 名前: `AMR-001`
4. Type: `AMR-Type`
5. Attribute: `location=factory1`
6. 保存。

### 3.3 ポリシーの作成
1. IoT Core → **Secure → Policies → Create**
2. 名前: `AMRPolicy`
3. Action:
   - `iot:Connect`
   - `iot:Publish`
   - `iot:Subscribe`
   - `iot:Receive`
4. Resource: `*`
5. 保存。

---

## 4. 証明書・ポリシー管理

### 4.1 ブートストラップ証明書登録
1. IoT Core → **Secure → Certificates → Create**
2. 「CA 証明書を登録」を選択。
3. OpenSSL で作成した **20年有効のブートストラップ証明書**をアップロード。
4. ステータス: `ACTIVE`

### 4.2 デバイス証明書の発行権限
- ポリシーに `iot:CreateKeysAndCertificate` を追加。
- デバイス起動時にブートストラップ証明書で認証 → 新規デバイス証明書を発行可能。

---

## 5. ブートストラップ証明書方式の運用

1. AMR 工場出荷時:  
   - 20年有効のブートストラップ証明書を搭載。  

2. 初回起動時:  
   - IoT Core に接続し、新規デバイス証明書を発行。  

3. 運用中:  
   - 定期的にデバイス証明書をローテーション（例: 1年）。  
   - 二重証明書運用により切替時もダウンタイムなし。  

---

## 6. サーバ機（ベッドサーバ相当）

1. EC2 or On-prem サーバ機から IoT Core へ接続。  
2. 認証には管理者証明書を利用。  
3. **IntegratorRole** により運用。  

---

## 7. モバイル端末 / PC（UIアクセス用）

### 7.1 API Gateway
1. API Gateway → **Create API**
2. Type: HTTP API
3. 名前: `AMR-UI-API`
4. Integration: IoT Core エンドポイント
5. 認証: **IAM + Cognito (将来拡張)**
6. ルート例:  
   - `GET /status` → IoT Core → AMR デバイス影  
   - `POST /command` → IoT Core Publish  

### 7.2 WAF 設定
1. WAF → Web ACL → `AMR-UI-WAF`
2. ルール:
   - SQL Injection protection
   - XSS protection
   - Rate limit: 100 req/min per IP
3. API Gateway にアタッチ。

---

## 8. CloudWatch / ログ監視

1. CloudWatch Logs → **Log groups** → `/aws/iot/AMR`
2. IoT Core のアクションログを出力。
3. アラーム設定:
   - Unauthorized access → SNS 通知
   - 証明書失効 → SNS 通知

---

## 9. 動作確認手順

1. モバイル端末から `https://<api-id>.execute-api.ap-northeast-1.amazonaws.com/status` にアクセス
2. AMR の状態を JSON で取得できるか確認。
3. `POST /command` で動作命令を送信。
4. IoT Core → AMR が応答することを確認。

---

## 10. 想定コスト（東京リージョン）

| サービス | 構成 | 月額目安 |
|----------|------|---------|
| IoT Core | 1,000,000 メッセージ/月 | 約 $5 |
| API Gateway | 1M リクエスト/月 | 約 $3.5 |
| WAF | WebACL 1つ + 2ルール | 約 $6 |
| CloudWatch Logs | 5GB/月 | 約 $5 |
| **合計** | 中小規模利用 | **約 $20/月** |

---

# 付録: 図（更新版）

```mermaid
flowchart TD
  subgraph Device["設備・端末"]
    AMR1["AMR（ブートストラップ証明書 20年）"]
    AMR2["設備端末"]
    Mobile["モバイル端末（UI共有アカウント）"]
    PC["PC（UI共有アカウント）"]
  end

  subgraph AWS["AWS（ap-northeast-1）"]
    IoTCore["AWS IoT Core"]
    Cert["ブートストラップ証明書（20年）"]
    API["API Gateway + WAF"]
    CloudWatch["CloudWatch Logs / SNS"]
  end

  AMR1 -->|Bootstrap Cert| IoTCore
  AMR2 --> IoTCore
  IoTCore --> CloudWatch
  Mobile -->|HTTPS| API
  API --> IoTCore
  PC -->|HTTPS| API

````

---

