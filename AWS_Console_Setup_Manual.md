# Iot-gateway-net 最終手順書（完全版 / 2025-08 / 日本語メニュー準拠）

> 本書は **CloudFront + WAF + S3（静的配信）** でカスタムUIを配信し、**Cognito（ユーザープール + IDプール）** と **IoT Core** を直接呼び出す構成を、**上から順番に実施すれば完了**するようにまとめたものです。
> IoT 側は **Fleet Provisioning by claim**（ブートストラップ証明書で新規本番証明書を取得 → RegisterThing）を採用します。ブラウザは **パスキー（WebAuthn）** を用いた**カスタムUI**方式でサインインします。
>
> ※ 画面ラベルは日本語UIに合わせていますが、併記の **（英語UI名）** と一致する項目を選べば他言語でも対応できます。

---

## 0. 前提と命名

* リージョン：**アジアパシフィック（東京） `ap-northeast-1`**
* アカウントID：`ACCOUNT_ID`（以降この表記を置き換え）
* 代表命名：

  * Thing 名：`AMR-001`（量産時は `AMR-<serial>`）
  * 本番ポリシー：`AMR-Prod-Policy`
  * claim ポリシー：`AMR-Claim-Policy`
  * フリートプロビジョニング・テンプレート：`amr-prod-template`
  * プロビジョニング・ロールエイリアス：`amr-provisioning-role-alias`
  * ブラウザ用 ID プールの認証ロール：`Cognito-IoTBrowserRole`

---

## 1. IoT Core（ポリシー → claim 証明書 → テンプレート → ロール）

> 左ナビ構成（日本語/英語）：**接続（Connect）／管理（Manage）／モニタリング（Monitor）／セキュリティ（Security）／設定（Settings）**。

### 1-1. 本番用 IoT ポリシー（Thing/トピック最小権限）

1. **IoT Core** → 左ナビ **セキュリティ（Security）→ ポリシー（Policies）→ 作成（Create）**。
2. 名前：`AMR-Prod-Policy`。
3. **JSON** に以下を貼付（`ACCOUNT_ID` を置換）。Thingに紐付くクライアントIDのみ許可し、対象トピックを最小化します。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iot:Connect"],
      "Resource": ["arn:aws:iot:ap-northeast-1:ACCOUNT_ID:client/${iot:Connection.Thing.ThingName}"],
      "Condition": {"Bool": {"iot:Connection.Thing.IsAttached": "true"}}
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Publish", "iot:Receive"],
      "Resource": [
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/amr/${iot:Connection.Thing.ThingName}/*",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/things/${iot:Connection.Thing.ThingName}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Subscribe"],
      "Resource": [
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/amr/${iot:Connection.Thing.ThingName}/*",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/$aws/things/${iot:Connection.Thing.ThingName}/*"
      ]
    }
  ]
}
```

> ヒント：`Publish/Receive` は `topic/…`、`Subscribe` は `topicfilter/…` の ARN を使います。

### 1-2. ブートストラップ（claim）用 IoT ポリシー（更新専用トピック）

> 目的：claim 証明書（20年）で **新しい本番鍵/証明書の作成** と **RegisterThing（provision）** を実行するための **MQTT トピック権限のみ** を付与します（制御プレーンAPI権限は不要）。

1. **セキュリティ → ポリシー → 作成**。
2. 名前：`AMR-Claim-Policy`。
3. JSON（テンプレート名は後段 1-4 で作成するものと一致させます）：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["iot:Connect"], "Resource": ["*"] },
    {
      "Effect": "Allow",
      "Action": ["iot:Publish", "iot:Receive"],
      "Resource": [
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/certificates/create/json",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/certificates/create/json/accepted",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/certificates/create/json/rejected",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/provisioning-templates/amr-prod-template/provision/json",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/provisioning-templates/amr-prod-template/provision/json/accepted",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/provisioning-templates/amr-prod-template/provision/json/rejected"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Subscribe"],
      "Resource": [
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/$aws/certificates/create/json",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/$aws/certificates/create/json/*",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/$aws/provisioning-templates/amr-prod-template/provision/json",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/$aws/provisioning-templates/amr-prod-template/provision/json/*"
      ]
    }
  ]
}
```

> 注意：**publish する前に受信トピックへ Subscribe** しておきます（`…/accepted|rejected` を取りこぼさない）。

### 1-3. claim 証明書（20年）の登録とポリシー付与

1. **セキュリティ → 証明書（Certificates）→ 登録/作成**。

   * 既存の `claim.crt/claim.key` がある場合：\*\*「デバイス証明書の登録（Register a device certificate）」\*\*でアップロード。
   * 新規作成する場合：\*\*「ワンクリック証明書の作成（Create certificate）」\*\*で作成しダウンロード（安全に保管）。
2. 証明書詳細 → **アクション → ポリシーのアタッチ（Attach policy）** → `AMR-Claim-Policy` を付与。
3. **Thing へのアタッチは不要**（claim は更新専用運用）。

### 1-4. フリートプロビジョニング・テンプレートの作成（ウィザード）

> メニュー導線：**接続（Connect）→ 複数のデバイスの接続（Connect many devices）→ Provisioning templates → Create provisioning template → 「クレーム証明書を使用したデバイスのプロビジョニング（Provisioning devices with a claim certificate）」**。

ウィザード入力：

* **Describe provisioning template**

  * ステータス：`Active`
  * テンプレート名：`amr-prod-template`
  * 説明：任意
* **Provisioning method**：クレーム証明書を使用した… を選択
* **Configure resources and permissions**（テンプレート本文）

  * **IoT ポリシーのアタッチ**：`AMR-Prod-Policy`
  * **Thing 作成**：名前規則 `AMR-{serial}`（属性やグループは要件に応じて指定）
  * **（任意）事前プロビジョニングフック**：検証用 Lambda を指定可能
* **Create provisioning role and role alias**：**ロールエイリアス** `amr-provisioning-role-alias` と、信頼先 `iot.amazonaws.com` の **IAMロール**（`iot:CreateThing`, `iot:AttachThingPrincipal`, `iot:AttachPolicy`, `iot:DescribeCertificate`, `iot:UpdateCertificate` など）をウィザードで作成
* **Review and create** → 作成

> 作成後、`$aws/provisioning-templates/amr-prod-template/provision/json` などのトピックが有効になります。

---

## 2. デバイス側の動作テスト（claim → 新本番証明書 → RegisterThing）

> 以降はテスト端末で実施します。**publish 前に必ず `…/accepted|rejected` へ Subscribe** してください。

1. **エンドポイントの確認**：左ナビ **接続 → ドメイン設定（Domain configurations）** → **デバイスデータエンドポイント**（`xxxxx-ats.iot.ap-northeast-1.amazonaws.com`）を控える。
2. **Subscribe**：

   * `$aws/certificates/create/json/accepted|rejected`
   * `$aws/provisioning-templates/amr-prod-template/provision/json/accepted|rejected`
3. **CreateKeysAndCertificate**：空ペイロードで **`$aws/certificates/create/json` に Publish**。受領ペイロードに `certificatePem / privateKey / certificateOwnershipToken`。
4. **RegisterThing（provision）**：

   * **Publish** → `$aws/provisioning-templates/amr-prod-template/provision/json`
   * 例ペイロード：

```json
{
  "certificateOwnershipToken": "<token-from-step3>",
  "parameters": {"serial": "001"}
}
```

5. `accepted` で `thingName` を受領。**新・本番証明書で再接続**し、`amr/AMR-001/*` 等へ Publish/Subscribe を確認。

> 失敗時の確認ポイント：テンプレート名、ロールエイリアスとIAMロール権限、ポリシーARN（`topic` と `topicfilter` の取り違い）、先に Subscribe 済みか。

---

## 3. Cognito（カスタムUIでパスキー／IDプールでAWS資格情報）

> ここでは **マネージドログインは使わず**、**ユーザープールAPI**を直接呼ぶ前提です（“選択式サインイン”＝`USER_AUTH` フロー）。

### 3-1. ユーザープール（パスキー有効化）

1. **Cognito** → 対象 **ユーザープール** を開く。
2. 左メニュー **認証 → サインイン**：

   * **「選択式サインイン（Choice-based）」** を有効化。
   * **パスキー（WebAuthn）** を有効化（RP ID は \*\*ユーザープールドメイン（推奨：カスタムドメイン）\*\*と一致させる）。
3. 左メニュー **アプリケーションクライアント**：

   * 対象クライアントの **認証フロー**で **サインイン方法を選択（ALLOW\_USER\_AUTH）** を有効化。
   * クライアントは **シークレットなし（public client）** を使用。

> 注：Cognito の WebAuthn は **チャレンジ開始前に `USERNAME` が必須**です。初回のみユーザー名（メール/電話/任意ID）を入力 → 以後は**ローカル保存して自動投入**する設計にします。

### 3-2. パスキー登録API（初回サインイン直後）

* **StartWebAuthnRegistration**（アクセストークンで呼出）→ `PublicKeyCreationOptions` を受領
* ブラウザで `navigator.credentials.create({ publicKey })` を実行
* **CompleteWebAuthnRegistration** に結果を送信して登録完了

### 3-3. パスキーでサインイン（カスタムUI）

1. **InitiateAuth（USER\_AUTH）** に `USERNAME` と `PREFERRED_CHALLENGE=WEB_AUTHN` を指定して呼び出し、`ChallengeName=WEB_AUTHN` と `CredentialRequestOptions` 相当を受領。
2. ブラウザで `navigator.credentials.get({ publicKey, mediation: 'conditional' })`。
3. **RespondToAuthChallenge（WEB\_AUTHN）** に結果と `USERNAME` を送信し、ID/Access/Refresh トークンを取得。
4. 初回で入力した `USERNAME` は端末ローカルに保存し、**次回以降は画面表示直後に（保存済みの）`USERNAME` を使って 1→2→3 を自動開始**します（体感“ユーザー名入力なし”）。

### 3-4. ID プールで AWS 資格情報（IoT 用）を取得

1. **Cognito → ID プール（Identity pools）** → **ID プールを作成**。
2. **ID プロバイダー**に上記ユーザープールを関連付け。
3. **認証済みロール**（例：`Cognito-IoTBrowserRole`）に **IoT 最小権限** を付与（clientId とトピックを厳密に）。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iot:Connect"],
      "Resource": ["arn:aws:iot:ap-northeast-1:ACCOUNT_ID:client/${cognito-identity.amazonaws.com:sub}-*"],
      "Condition": {"StringLike": {"iot:ClientId": "${cognito-identity.amazonaws.com:sub}-*"}}
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Subscribe"],
      "Resource": [
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/amr/AMR-001/*",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topicfilter/$aws/things/AMR-001/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Publish", "iot:Receive"],
      "Resource": [
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/amr/AMR-001/*",
        "arn:aws:iot:ap-northeast-1:ACCOUNT_ID:topic/$aws/things/AMR-001/*"
      ]
    }
  ]
}
```

---

## 4. フロントエンド配信（S3 + CloudFront + OAC + WAF / CSP）

> 追加のサーバ（API Gateway / Lambda）は不要。**静的配信**のみで成立します。

### 4-1. S3 バケット

* 静的サイト用バケットを作成。**パブリックアクセスはすべてブロック**（アカウント既定を推奨）。

### 4-2. CloudFront ディストリビューション + OAC

1. **CloudFront → ディストリビューション作成**。オリジンは S3 バケットを指定。
2. **オリジンアクセスコントロール（OAC）** を作成してオリジンに関連付け。
3. 案内に従って **S3 バケットポリシー**へ OAC を許可（テンプレ自動挿入）。

### 4-3. WAF（推奨）

* CloudFront ディストリビューションに **WAF（Web ACL）** をアタッチ。まずは **マネージドルール**をカウント→調整→ブロックへ切替。

### 4-4. CSP（Content-Security-Policy）

* `connect-src` に **Cognito と IoT** のドメインを明示許可。例：

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  connect-src 'self' https://cognito-idp.ap-northeast-1.amazonaws.com https://cognito-identity.ap-northeast-1.amazonaws.com wss://*.iot.ap-northeast-1.amazonaws.com;
  frame-ancestors 'none';
  object-src 'none';
```

---

## 5. ブラウザ実装（最小骨子）

> すべて **フロントのみ（JS）** で完結します。クレデンシャルやシークレットはフロントに埋め込まない設計にします。

### 5-1. 構成ファイル `config.js`（例）

```js
export const region = 'ap-northeast-1';
export const userPoolId = 'ap-northeast-1_XXXXXXXXX';
export const appClientId = 'xxxxxxxxxxxxxxxxxxxxxxxxxx'; // secret なし
export const idPoolId = 'ap-northeast-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx';
export const iotEndpoint = 'xxxxx-ats.iot.ap-northeast-1.amazonaws.com';
```

### 5-2. サインイン（パスキー）→ 資格情報 → IoT へ接続（擬似コード）

```js
// 1) 初回のみユーザー名を入力して保存
const username = loadOrAskAndPersistUsername();

// 2) InitiateAuth(USER_AUTH) で WEB_AUTHN を要求
const init = await callInitiateAuth({ username, preferredChallenge: 'WEB_AUTHN' });

// 3) WebAuthn（Conditional UI 対応）
const options = toPublicKeyCredentialRequestOptions(init.challengeParams);
const assertion = await navigator.credentials.get({ publicKey: options, mediation: 'conditional' });

// 4) RespondToAuthChallenge でトークン入手
const tokens = await callRespondToAuthChallenge({ username, assertion, session: init.session });

// 5) ID プールで AWS 資格情報
const creds = await getAwsCredentialsFromIdPool(tokens.idToken);

// 6) IoT Device SDK (browser) で SigV4 WSS 接続
const mqtt = await connectIotOverWss({ endpoint: iotEndpoint, region, credentials: creds });
```

---

## 6. 運用・監視（推奨）

* **Device Defender（Detect）**：異常メッセージ量・接続異常などの挙動を検知 → アラーム。
* **ミティゲーション**：違反時に **「証明書を無効化」** や **「デフォルトポリシーに差し替え」** を自動実行するアクションを紐付け（暴走端末の即時隔離）。
* **証明書運用**：通常は **本番（1年）**。期限切れ・失効時は **claim（20年）** で接続 → `CreateKeysAndCertificate` → `RegisterThing` → 新本番証明書へ切替 → 旧本番を INACTIVE/Detach。

---

## 7. トラブルシュート

* **claim でレスポンスが来ない**：先に `…/accepted|rejected` へ Subscribe 済みか／トピックの `json`/`cbor` が一致しているか。
* **provision が rejected**：テンプレート名、ロールエイリアス、IAM ロール権限（`AttachPolicy`/`AttachThingPrincipal` 等）、ポリシーの `topic`/`topicfilter` を再確認。
* **ブラウザ接続が 403**：ID プールのロール（`clientId` 制限と対象トピック範囲）、Cognito ドメインと RP ID の一致、WSS のエンドポイント名を確認。
* **CloudFront 経由で 403**：OAC を S3 に正しく関連付け／S3 は**パブリックブロックを維持**。

---

## 付録 A：OpenSSL（claim：自己署名 20 年 の例）

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout claim.key -out claim.crt \
  -subj "/CN=device-claim" -days 7300
```

* 端末ごとに個別の claim を推奨（漏洩時の影響最小化）。

## 付録 B：ディレクトリ構成（推奨）

```
Iot-gateway-net/
├─ README.md
├─ AWS_Console_Setup_Manual.md   # 本ドキュメント
├─ app/
│  ├─ index.html
│  ├─ app.js
│  └─ config.js
└─ sample/
   ├─ thing/
   │  ├─ client.py
   │  └─ certs/
   └─ README.md
```

## 付録 C：ポリシーの設計メモ

* `iot:Connection.Thing.ThingName` 等の **ポリシー変数**で、**Thing連動の最小権限**を構成。
* `iot:DomainName` を `Connect` 条件に追加し、**特定の IoT データエンドポイント**のみに接続を限定するのも有効。
* `Publish/Receive` は `topic/…`、`Subscribe` は `topicfilter/…` を使い分け。

---

> 以上で、**上から順に進めれば** IoT 側のフリートプロビジョニング（claim）と、ブラウザのパスキー認証 + IoT 直結（SigV4 WSS）が構築できます。追加のサーバは不要です。
