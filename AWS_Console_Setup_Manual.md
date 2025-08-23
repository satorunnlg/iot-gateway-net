# AWS設定手順書
## 目次

* [0. 前提と完成像](#0-前提と完成像)
* [1. 事前準備（ツール・前提リソース）](#1-事前準備ツール前提リソース)
* [2. S3（静的サイト）を準備](#2-s3静的サイトを準備)
* [3. CloudFront をS3にOACで接続し配信](#3-cloudfront-をs3にoacで接続し配信)
* [4. CloudFront 応答ヘッダー（CSP等）とキャッシュ設計](#4-cloudfront-応答ヘッダーcsp等とキャッシュ設計)
* [5. CloudFront（任意）独自ドメイン/証明書/ログ/無効化](#5-cloudfront任意独自ドメイン証明書ログ無効化)
* [6. AWS WAF WebACL を作成し CloudFront にアタッチ](#6-aws-waf-webacl-を作成し-cloudfront-にアタッチ)
* [7. Amazon Cognito: ユーザープール（パスキー対応の本丸）](#7-amazon-cognito-ユーザープールパスキー対応の本丸)
* [8. Cognito アプリクライアント（選択式サインイン＝ALLOW\_USER\_AUTH）](#8-cognito-アプリクライアント選択式サインインallow_user_auth)
* [9. （必要なら）ユーザー作成と初回パスワード確定](#9-必要ならユーザー作成と初回パスワード確定)
* [10. Cognito IDプール（IoT 用のAWS認証を得る）](#10-cognito-idプールiot-用のaws認証を得る)
* [11. AWS IoT Core（WebSocket/MQTT でブラウザ接続）](#11-aws-iot-corewebsocketmqtt-でブラウザ接続)
* [12. フロントエンド配置と外部ライブラリの取り扱い](#12-フロントエンド配置と外部ライブラリの取り扱い)
* [13. 運用ポイント（キャッシュ更新・無効化・ログ）](#13-運用ポイントキャッシュ更新無効化ログ)
* [14. 仕上げ：check\_aws\_environment.py で環境検証](#14-仕上げcheck_aws_environmentpy-で環境検証)

---

## 0. 前提と完成像

* **静的フロントエンド**を S3（バケット非公開）に置き、**CloudFront + OAC** 経由で配信。
* **Cognito（ユーザープール）**で**パスキー（WebAuthn）**を使ったサインイン。**RP ID は“サードパーティドメイン”＝あなたの配信FQDN**（CloudFrontのドメインまたは独自ドメイン）を指定します。最新UIでは**Passkeys 画面で「サードパーティドメイン」を選択**してRP IDを入力する点が重要。([AWS ドキュメント][1])
* \*\*アプリクライアントはパブリック（シークレット無し）**かつ**`ALLOW_USER_AUTH`（選択式サインイン）\*\*を有効化。([AWS ドキュメント][2])
* **Cognito IDプール**でAWS認証（クレデンシャル）を発行し、**IoT Core**へ**MQTT over WSS**で接続。**IAM/Iotポリシー**で権限を最小化。([AWS ドキュメント][3])
* CloudFront に **CSPやセキュリティヘッダー**を**レスポンスヘッダーポリシー**で付与。([AWS ドキュメント][4])

> 以降は **すべて手動**の操作手順です。CLI 併記部分はミスなく一気に設定したい時に使えます。

---

## 1. 事前準備（ツール・前提リソース）

1. 管理者権限の AWS アカウント。リージョンは\*\*東京（ap-northeast-1）\*\*想定。
2. **AWS CLI v2**（WindowsはMSIで導入/更新）。**WebAuthn設定のCLIオプションは v2 で利用可能**。([AWS ドキュメント][5])

   * `aws --version` で v2 を確認。
3. **証明書**（独自ドメインをCloudFrontに設定する場合）

   * CloudFrontに割り当てる**ACM証明書は必ず us-east-1**で発行/インポート。([AWS ドキュメント][6])

---

## 2. S3（静的サイト）を準備

1. バケット作成（例：`my-static-site-bucket`）

   * **ブロックパブリックアクセスはON（公開しない）**。
2. 静的コンテンツ（`index.html` / `app.js` / `config.js` など）をアップロード。
3. **コンテンツタイプ**（`text/html`, `text/javascript`, `text/css`, `image/x-icon` など）を適切に設定。
4. **公開はCloudFront経由のみ**にするため、後で**OAC**を設定して**S3バケットポリシーをCloudFrontのみに許可**します。([AWS ドキュメント][7])

---

## 3. CloudFront をS3にOACで接続し配信

1. **ディストリビューション作成**

   * **オリジン**＝S3 バケット（**ウェブサイトエンドポイントは使わない**。通常のバケットエンドポイントでOK。OACに必須）。([AWS ドキュメント][7])
   * **OAC（Origin Access Control）**を新規作成してこのオリジンに割り当て。後で自動提案される**S3バケットポリシー**（`AWS:SourceArn` がこのディストリビューション）を適用。([AWS ドキュメント][7])
   * **デフォルトビヘイビア**

     * Viewer protocol policy: Redirect HTTP to HTTPS
     * Allowed HTTP methods: GET, HEAD（必要に応じてOPTIONS）
     * **キャッシュポリシー**：後述（HTMLは短/0秒、アセットは長期）
     * **オリジンリクエストポリシー**：後述（必要なヘッダ/クエリのみ）([AWS ドキュメント][8])
   * **Default root object**：`index.html` を設定。ルートアクセス `/` で `index.html` を返します。([AWS ドキュメント][9])
2. （任意）\*\*ログ（Standard logging v2）\*\*を有効化して CloudWatch Logs / Firehose / S3 に配送。([AWS ドキュメント][10])

---

## 4. CloudFront 応答ヘッダー（CSP等）とキャッシュ設計

### 4.1 応答ヘッダー（Response Headers Policy）

* **Policies → Create response headers policy** から以下のようなセキュリティヘッダーを追加：

  * `Content-Security-Policy`（例）

    ```
    default-src 'self';
    connect-src 'self' https://cognito-idp.ap-northeast-1.amazonaws.com wss://<あなたのIoT-ATSエンドポイント>;
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    frame-ancestors 'none';
    base-uri 'self';
    object-src 'none';
    ```

    ※ 外部CDNを使わない前提（後述の[12](#12-フロントエンド配置と外部ライブラリの取り扱い)参照）。
  * `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  * `X-Content-Type-Options: nosniff`
  * `X-Frame-Options: DENY`
  * `Referrer-Policy: no-referrer`
    CloudFront の**レスポンスヘッダーポリシー**で安全に付与できます。([AWS ドキュメント][4], [Repost][11])

### 4.2 キャッシュ方針（Cache Policy / Origin Request Policy）

* **HTML（index.html等）：短命 or 0秒**

  * **Minimum/Default/Maximum TTL を 0** にして**常にオリジン確認**（または `Cache-Control: no-store` を付与）。([AWS CLI][12], [Repost][13])
* **静的アセット（.js/.css/画像）：長期キャッシュ**

  * ファイル名に**ハッシュ版管理**（`app.abcd1234.js`）を推奨。`Cache-Control: public, max-age=31536000, immutable`。
* **Origin Request Policy** は**キャッシュキー**（Cache Policy）と連携して、**必要なヘッダ/クエリ/クッキーのみ**をオリジンへ。キャッシュヒット率に効きます。([AWS ドキュメント][8])

---

## 5. CloudFront（任意）独自ドメイン/証明書/ログ/無効化

* **独自ドメイン**を使う場合は、**ACM 証明書を us-east-1 で発行/インポート**してディストリビューションに割り当て。Route53 などでCNAMEを張る。([AWS ドキュメント][6])
* **標準ログ v2**は前述のとおり有効化可能。([AWS ドキュメント][10])
* **無効化（Invalidation）**

  * 更新時は `/*` や `/index.html` を無効化。**ワイルドカードは末尾のみ**有効。([AWS ドキュメント][14])

---

## 6. AWS WAF WebACL を作成し CloudFront にアタッチ

1. \*\*WebACL（グローバル）\*\*を作成し、**CloudFront ディストリビューション**に関連付け。
2. **AWS Managed Rules（推奨）**

   * **Core rule set (CRS)**、**Known bad inputs**、**Amazon IP reputation list** などのベースラインを有効化。([AWS ドキュメント][15])
3. **Rate-based rule（しきい値レート制限）**

   * 評価ウィンドウは **1/2/5/10 分**から選択（**既定は5分**）。軽いDDoSやクローリング対策に有効。([AWS ドキュメント][16])

---

## 7. Amazon Cognito: ユーザープール（パスキー対応の本丸）

> **最新UIの誘導**：
> コンソール → **Cognito** → **ユーザープール** →（対象プール）→ **認証（Authentication / サインイン設定）** → **Passkeys（パスキー）**。
> ここで **「サードパーティドメイン」** を選んで **RP ID にあなたの配信FQDN**（例：`dg029bjh15kpm.cloudfront.net` または独自FQDN）を入力。これが**今回ハマりどころ**でした。([AWS ドキュメント][1])

1. **ユーザープール新規作成**（既存でも可）

   * サインインで使う識別子：**ユーザー名**（またはメール）
   * ユーザー属性：必要に応じて Email を必須など
2. **Passkeys（WebAuthn）設定**

   * **Relying party（RP）**＝**あなたの配信FQDN**
   * UI で **「サードパーティドメイン」** を選択 → **FQDN を入力**
   * **User Verification**：`required` を推奨（ブラウザ側で生体認証等が必須）。
   * **注意**：**カスタムドメインをユーザープールに設定している場合、RP ID はその**カスタムドメインに制約されるケースがある**ため、**プレフィックスドメインをRPにしたい時は「サードパーティドメイン」にFQDNを入力**する、というのが**最新仕様\*\*です。([AWS ドキュメント][1])
3. **CLI での設定確認/変更**（必要時）

   * `set-user-pool-mfa-config` の `--web-authn-configuration` で **RP ID と検証レベル**を設定可能（CLI v2）。([AWS ドキュメント][5])
4. **注意（PSL）**：RPに**パブリックサフィックス（PSL）**は指定不可（`example.co.jp` のような**TLD/レジストリ扱いドメイン**はNG）。**自分が所有するFQDN**を使う。([AWS ドキュメント][17])

---

## 8. Cognito アプリクライアント（選択式サインイン＝ALLOW\_USER\_AUTH）

1. **アプリクライアント**（Applications → App clients）を作成/編集

   * **パブリッククライアント（シークレット無し）**
   * **Authentication flows**：**Choice-based sign-in: `ALLOW_USER_AUTH`** を有効化。

     * 併用するなら `ALLOW_USER_SRP_AUTH` / `ALLOW_USER_PASSWORD_AUTH` / `ALLOW_REFRESH_TOKEN_AUTH` も追加。([AWS ドキュメント][2])
2. **Hosted UI を使わない**（カスタムUI）場合

   * ドメイン設定は必須ではありません（この手順書では**自前UI**前提）。
3. **APIの動作上の注意**

   * `InitiateAuth`/`RespondToAuthChallenge` は**パスキー（`WEB_AUTHN`）**を含む**選択式**で動く。クライアントにシークレットがある場合は\*\*`SECRET_HASH` が必須\*\*になるので、\*\*ブラウザ用は“シークレット無し”\*\*が鉄則。([AWS ドキュメント][18])

---

## 9. （必要なら）ユーザー作成と初回パスワード確定

* 管理者がユーザーを作った直後は **`FORCE_CHANGE_PASSWORD`**。**初回ログインで新パスワード**を求められるか、**管理者が恒久パスワードに変更**して即ログイン可能にできます。([sdk.amazonaws.com][19])

  * 例：`admin-set-user-password --permanent` で確定。
* その後、**アプリUIからパスキー登録**（`StartWebAuthnRegistration` → `CompleteWebAuthnRegistration`）で**信頼済みデバイス**を作るのが一般的です。([AWS ドキュメント][20])

---

## 10. Cognito IDプール（IoT 用のAWS認証を得る）

> 目的：**Webブラウザ**で**MQTT over WSS**に接続するための**一時的なAWSクレデンシャル**を発行。

1. **IDプール作成**（Federated Identities）

   * 認証プロバイダに **User Pool** を追加：
     `ProviderName = cognito-idp.<region>.amazonaws.com/<UserPoolId>` / `ClientId = <AppClientId>`
2. **ロール設定**

   * **Authenticated role**（例：`Cognito-IoTBrowserRole`）を設定。
3. **ロールにポリシー付与（最小権限）**

   * 例：**IoT への接続/購読/発行/受信**を必要なトピックにだけ許可（`iot:Connect`, `iot:Subscribe`, `iot:Publish`, `iot:Receive`）。
   * **IAM と IoT ポリシーの両方で最小権限**を与える設計が推奨（両方の合算で**最小権限**が適用されます）。([AWS ドキュメント][21])

---

## 11. AWS IoT Core（WebSocket/MQTT でブラウザ接続）

1. **エンドポイント**の取得

   * CLI: `aws iot describe-endpoint --endpoint-type iot:Data-ATS`
   * 応答 `endpointAddress` を **WSSのホスト**として使います（`*-ats.iot.<region>.amazonaws.com`）。**このAPIには `iot:DescribeEndpoint` 権限**が必要。([AWS ドキュメント][22])
2. **プロトコル**

   * ブラウザ→**MQTT over WSS**（443/TLS）で接続。([AWS ドキュメント][3])
3. **認可**

   * クレデンシャルは **Cognito IDプール**から取得（`GetId`/`GetCredentialsForIdentity`）→ SigV4 署名で接続。
   * **IAM/Iotポリシー**で許可された**トピックとアクションのみ**が通ります。([AWS ドキュメント][23])

---

## 12. フロントエンド配置と外部ライブラリの取り扱い

* **スクリプトは極力セルフホスト**にしてください（S3→CloudFront配信）。CDN由来の**CORSやアクセス制限**で読み込めない事象を避けます（先日の `sdk.amazonaws.com` / `cdnjs` 事象）。
* **CSP** の `script-src 'self'` 前提で、AWS SDK for JS（必要部分だけ）や MQTT クライアントなどを\*\*`/vendor/`\*\*に置きます。
* **`favicon.ico`** は `assets/favicon.ico` で配置し、**Content-Type: image/x-icon** を付与（403/404 回避のため）。

---

## 13. 運用ポイント（キャッシュ更新・無効化・ログ）

* **HTMLは0秒キャッシュ**＋**`/index.html`（または `/*`）の無効化**で即反映。([AWS ドキュメント][14])
* **アセットは長期キャッシュ**＋**ファイル名にハッシュ**でキャッシュ破棄。
* \*\*ログ（標準ログ v2）\*\*は CloudWatch Logs / Firehose / S3 へ。可視化や監査に活用。([AWS ドキュメント][10])

---

## 14. 仕上げ：check\_aws\_environment.py で環境検証

> すでに共有した `.env` 連携版（`python-dotenv`）を **`check_aws_environment.py`** という名前で保存している前提。

1. 依存導入

```powershell
pip install boto3 python-dotenv
```

2. `.env` をプロジェクト直下に配置（例）

```env
AWS_PROFILE=default
AWS_REGION=ap-northeast-1

COGNITO_USER_POOL_ID=ap-northeast-1_XXXXXXXXX
COGNITO_APP_CLIENT_ID=yyyyyyyyyyyyyyyyyyyyyyyyyy      # ← IDのみ。末尾にコメントを入れない
COGNITO_USERNAME=org-operator

COGNITO_USER_POOL_DOMAIN=           # カスタムUIのみなら空でOK
COGNITO_IDENTITY_POOL_ID=ap-northeast-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

S3_BUCKET=my-static-site-bucket
S3_FAVICON_KEY=assets/favicon.ico
```

3. 実行

```powershell
python .\check_aws_environment.py
```

**PASS になるべき要点**

* **Cognito: WebAuthn (RP ID / UserVerification)** … **RP ID** に **CloudFront/独自FQDN** が表示（`UserVerification=required` 推奨）。([AWS ドキュメント][5])
* **App Client: `ALLOW_USER_AUTH` & Secretなし**（シークレット付きにするとブラウザから `SECRET_HASH` 必須で失敗）。([AWS ドキュメント][2])
* **User: org-operator** … `Enabled & CONFIRMED`（新規作成直後は `FORCE_CHANGE_PASSWORD`。`admin-set-user-password --permanent` で確定可能）。([sdk.amazonaws.com][19])
* **Identity Pool** … `ProviderName=cognito-idp.<region>.amazonaws.com/<UserPoolId>` に **AppClientId** が一致。
* **S3 favicon** … `image/x-icon` などが付与されて存在。

---

### 参考（主要ドキュメント）

* **WebAuthn 設定（RP ID/第三者ドメイン）**：ユーザープールドメインとRPの関係／第三者ドメインの入力方法。([AWS ドキュメント][1])
* **WebAuthnConfigurationType**（RP IDと検証レベルのAPI仕様）。([AWS ドキュメント][24])
* **Passkeys と RP ID（PSL不可／自ドメイン使用）**。([AWS ドキュメント][17])
* **CLI: set-user-pool-mfa-config（WebAuthn設定をCLIで）**。([AWS ドキュメント][5])
* \*\*選択式サインイン（ALLOW\_USER\_AUTH）\*\*の有効化と位置（App clients → Authentication flows）。([AWS ドキュメント][2])
* **InitiateAuth の `WEB_AUTHN` チャレンジ／SECRET\_HASH の注意**。([AWS ドキュメント][18])
* **FORCE\_CHANGE\_PASSWORD → CONFIRMED の流れ**。([sdk.amazonaws.com][19])
* **CloudFront と OAC（S3 私有＋配信）**。([AWS ドキュメント][7])
* **CloudFront 応答ヘッダー（CSPなど）**。([AWS ドキュメント][4])
* **ACM 証明書は us-east-1（CloudFront用）**。([AWS ドキュメント][6])
* **Default Root Object** 設定。([AWS ドキュメント][9])
* **WAF マネージドルール/レート制限**。([AWS ドキュメント][15])
* **IoT MQTT over WSS と DescribeEndpoint**。([AWS ドキュメント][3])
* **Cognito × IoT のポリシー例／最小権限**。([AWS ドキュメント][21])

---

[1]: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html?utm_source=chatgpt.com "Configuring a user pool domain - Amazon Cognito"
[2]: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow-methods.html?utm_source=chatgpt.com "Authentication flows - Amazon Cognito - AWS Documentation"
[3]: https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html?utm_source=chatgpt.com "Device communication protocols - AWS IoT Core"
[4]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/creating-response-headers-policies.html?utm_source=chatgpt.com "Create response headers policies - Amazon CloudFront"
[5]: https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/set-user-pool-mfa-config.html?utm_source=chatgpt.com "set-user-pool-mfa-config — AWS CLI 2.28.13 Command Reference"
[6]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html?utm_source=chatgpt.com "Requirements for using SSL/TLS certificates with CloudFront"
[7]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html?utm_source=chatgpt.com "Restrict access to an Amazon S3 origin - Amazon CloudFront"
[8]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-how-origin-request-policies-and-cache-policies-work-together.html?utm_source=chatgpt.com "Understand how origin request policies and cache ..."
[9]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DefaultRootObject.html?utm_source=chatgpt.com "Specify a default root object - Amazon CloudFront"
[10]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logging.html?utm_source=chatgpt.com "Configure standard logging (v2) - Amazon CloudFront"
[11]: https://repost.aws/knowledge-center/cloudfront-http-security-headers?utm_source=chatgpt.com "Add HTTP security headers to CloudFront responses"
[12]: https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudfront/create-cache-policy.html?utm_source=chatgpt.com "create-cache-policy — AWS CLI 2.27.29 Command Reference"
[13]: https://repost.aws/questions/QUXETfrRb1SGaZGGlr1uOKzA/why-are-my-files-still-being-requested-after-setting-cache-control-with-cloudfront?utm_source=chatgpt.com "Why Are My Files Still Being Requested After Setting ..."
[14]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Invalidation_Requests.html?utm_source=chatgpt.com "Invalidate files - Amazon CloudFront"
[15]: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html?utm_source=chatgpt.com "AWS Managed Rules rule groups list"
[16]: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-high-level-settings.html?utm_source=chatgpt.com "Rate-based rule high-level settings in AWS WAF"
[17]: https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html?utm_source=chatgpt.com "Authentication with Amazon Cognito user pools"
[18]: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html?utm_source=chatgpt.com "InitiateAuth - Amazon Cognito User Pools"
[19]: https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/services/cognitoidentityprovider/CognitoIdentityProviderClient.html?utm_source=chatgpt.com "CognitoIdentityProviderClient (AWS SDK for Java - 2.32.26)"
[20]: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CompleteWebAuthnRegistration.html?utm_source=chatgpt.com "CompleteWebAuthnRegistration - Amazon Cognito User ..."
[21]: https://docs.aws.amazon.com/iot/latest/developerguide/pub-sub-policy.html?utm_source=chatgpt.com "Publish/Subscribe policy examples - AWS IoT Core"
[22]: https://docs.aws.amazon.com/cli/latest/reference/iot/describe-endpoint.html?utm_source=chatgpt.com "describe-endpoint — AWS CLI 2.28.12 Command Reference"
[23]: https://docs.aws.amazon.com/iot/latest/developerguide/iot-authorization.html?utm_source=chatgpt.com "Authorization - AWS IoT Core"
[24]: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_WebAuthnConfigurationType.html?utm_source=chatgpt.com "WebAuthnConfigurationType - Amazon Cognito User Pools"
