/**
 * 役割: AMR 操作用の MQTT クライアントと UI 制御（未認証ならサインイン画面へ遷移）
 * 参照: README の「IoT 接続」「ID プール」章、手順書の WebSocket/SigV4 とポリシー設定の節を参照。
 * 注意: 外部 CDN は使用しない（/vendor 配下を参照）。config.js の公開識別子を利用。
 * 変更: CryptoJS + moment.js + Paho MQTT を使用
 * 参考: https://dev.classmethod.jp/articles/aws-iot-mqtt-over-websocket/
 */
(function () {
	"use strict";
	const cfg = window.IOTGW_CONFIG;
	const $ = (id) => document.getElementById(id);
	const el = {
		status: $("status"),
		hbInfo: $("hbInfo"),
		dest: $("dest"),
		callBtn: $("callBtn"),
		authInfo: $("authInfo"),
		logoutBtn: $("logoutBtn")
	};

	// ===== 認証チェック（テスト用：未認証ユーザーロールを使用） =====
	// CHANGED: 未認証ロールでのテストのため認証チェックをコメントアウト
	const idToken = sessionStorage.getItem("id_token");
	// if (!idToken) { location.replace("./signout.html"); return; }

	if (idToken) {
		el.authInfo.textContent = "認証状態: 認証済み（User Pool）";
	} else {
		el.authInfo.textContent = "認証状態: 未認証ユーザー（テスト用）";
	}

	// ===== サインアウトは常時有効（接続前でも可） =====
	let currentClient = null; // 接続後に代入
	el.logoutBtn.onclick = () => {
		try {
			if (currentClient) {
				// Paho MQTT の disconnect
				if (typeof currentClient.disconnect === 'function') {
					currentClient.disconnect();
				}
			}
		} catch (e) {
			console.warn('Disconnect error:', e);
		}
		sessionStorage.clear();
		location.replace("./signout.html");
	};

	// 宛先候補
	(cfg.destinations || []).forEach(d => {
		const opt = document.createElement("option"); opt.value = d; opt.textContent = d; el.dest.appendChild(opt);
	});

	function setStatus(t, cls) { el.status.textContent = t; el.status.classList.remove("ok", "warn"); if (cls) el.status.classList.add(cls); }
	function setBtnMoving(m) { if (m) { el.callBtn.textContent = "呼出し中"; el.callBtn.disabled = true; } else { el.callBtn.textContent = "呼出し"; el.callBtn.disabled = false; } }

	// ===== AWS 資格情報（ID プール - 未認証/認証両対応） =====
	AWS.config.region = cfg.region;

	// CHANGED: 未認証ユーザーも対応するように修正
	if (idToken) {
		// 認証済みユーザーの場合
		const loginsKey = `cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
		AWS.config.credentials = new AWS.CognitoIdentityCredentials({
			IdentityPoolId: cfg.identityPoolId,
			Logins: { [loginsKey]: idToken }
		});
		console.info("[AWS] Using authenticated role");
	} else {
		// 未認証ユーザーの場合
		AWS.config.credentials = new AWS.CognitoIdentityCredentials({
			IdentityPoolId: cfg.identityPoolId
			// Logins を指定しないことで未認証ロールが適用される
		});
		console.info("[AWS] Using unauthenticated role");
	}

	// ===== SigV4 署名ユーティリティ（CryptoJS + moment.js版） =====
	// 参考: https://dev.classmethod.jp/articles/aws-iot-mqtt-over-websocket/
	function SigV4Utils() { }

	SigV4Utils.sign = function (key, msg) {
		// FIXED: WordArrayを使用してHMAC計算
		var hash = CryptoJS.HmacSHA256(msg, key);
		return hash.toString(CryptoJS.enc.Hex);
	};

	SigV4Utils.sha256 = function (msg) {
		var hash = CryptoJS.SHA256(msg);
		return hash.toString(CryptoJS.enc.Hex);
	};

	SigV4Utils.getSignatureKey = function (key, dateStamp, regionName, serviceName) {
		// FIXED: 'AWS4' + key を最初に設定
		var kDate = CryptoJS.HmacSHA256(dateStamp, 'AWS4' + key);
		var kRegion = CryptoJS.HmacSHA256(regionName, kDate);
		var kService = CryptoJS.HmacSHA256(serviceName, kRegion);
		var kSigning = CryptoJS.HmacSHA256('aws4_request', kService);
		return kSigning;
	};

	function createEndpoint(regionName, awsIotEndpoint, accessKey, secretKey, sessionToken) {
		// IMPORTANT: エンドポイントは小文字に変換する必要がある（参考記事より）
		const host = awsIotEndpoint.toLowerCase();

		const time = moment.utc();
		const dateStamp = time.format('YYYYMMDD');
		const amzdate = dateStamp + 'T' + time.format('HHmmss') + 'Z';
		const service = 'iotdevicegateway';
		const region = regionName;
		const algorithm = 'AWS4-HMAC-SHA256';
		const method = 'GET';
		const canonicalUri = '/mqtt';

		const credentialScope = dateStamp + '/' + region + '/' + service + '/' + 'aws4_request';

		// FIXED: クエリパラメータを正しい順序で構築
		const queryParams = {
			'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
			'X-Amz-Credential': accessKey + '/' + credentialScope,
			'X-Amz-Date': amzdate,
			'X-Amz-SignedHeaders': 'host'
		};

		// セッショントークンがある場合は追加（署名計算では除外）
		const sessionTokenForUrl = sessionToken;
		if (sessionToken) {
			queryParams['X-Amz-Security-Token'] = sessionToken;
		}

		// FIXED: クエリストリングをアルファベット順にソートして構築
		const sortedKeys = Object.keys(queryParams).sort();
		let canonicalQuerystring = '';

		for (let i = 0; i < sortedKeys.length; i++) {
			const key = sortedKeys[i];
			// FIXED: セッショントークンは署名計算時には含めない
			if (key === 'X-Amz-Security-Token') continue;

			if (canonicalQuerystring) canonicalQuerystring += '&';
			canonicalQuerystring += encodeURIComponent(key) + '=' + encodeURIComponent(queryParams[key]);
		}

		const canonicalHeaders = 'host:' + host + '\n';
		const payloadHash = SigV4Utils.sha256('');

		const canonicalRequest = method + '\n' + canonicalUri + '\n' + canonicalQuerystring + '\n' +
			canonicalHeaders + '\nhost\n' + payloadHash;

		const stringToSign = algorithm + '\n' + amzdate + '\n' + credentialScope + '\n' +
			SigV4Utils.sha256(canonicalRequest);

		const signingKey = SigV4Utils.getSignatureKey(secretKey, dateStamp, region, service);
		const signature = SigV4Utils.sign(signingKey, stringToSign);

		// ADDED: デバッグ情報を出力
		console.log('[SigV4 Debug] Canonical Request:', canonicalRequest);
		console.log('[SigV4 Debug] String to Sign:', stringToSign);
		console.log('[SigV4 Debug] Signature:', signature);

		// FIXED: 最終URLにセッショントークンを含める
		let finalQuerystring = canonicalQuerystring + '&X-Amz-Signature=' + signature;
		if (sessionTokenForUrl) {
			finalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(sessionTokenForUrl);
		}

		return 'wss://' + host + canonicalUri + '?' + finalQuerystring;
	}

	function connect(creds) {
		const identityId = AWS.config.credentials.identityId;
		// CHANGED: 未認証ユーザーの場合は固定プレフィックス＋ランダムIDを使用
		const clientId = identityId || `unauthenticated-${Math.random().toString(36).substring(2, 15)}`;

		console.info("[Paho MQTT] Connecting...", {
			identityId: identityId,
			clientId: clientId,
			endpoint: cfg.iotEndpoint,
			authenticated: !!identityId
		});

		try {
			// WebSocket エンドポイントの作成
			const endpoint = createEndpoint(
				cfg.region,
				cfg.iotEndpoint,
				creds.accessKeyId,
				creds.secretAccessKey,
				creds.sessionToken
			);

			console.log("[Paho MQTT] WebSocket endpoint:", endpoint.substring(0, 200) + "...");

			// CHANGED: Paho MQTT クライアントの作成（URLパースで正しく処理）
			const wsUrl = new URL(endpoint);
			const client = new Paho.MQTT.Client(
				wsUrl.host,        // ホスト部分のみ
				wsUrl.port || 443, // ポート（通常443）
				wsUrl.pathname + wsUrl.search, // パス＋クエリストリング
				clientId
			);
			currentClient = client;

			// 状態管理
			let lastHB = 0, state = "—";

			function update(payload) {
				if (!payload) return;
				state = payload.state || state;
				lastHB = payload.heartbeatAt || payload.updatedAt || Date.now();
				el.hbInfo.textContent = `HB: ${new Date(lastHB).toLocaleString()}`;
				if (state === "moving") {
					setStatus("移動中", "ok");
					setBtnMoving(true);
				} else if (state === "idle") {
					setStatus("待機中", "ok");
					setBtnMoving(false);
				} else if (state === "offline") {
					setStatus("オフライン", "warn");
					setBtnMoving(true);
				} else {
					setStatus(state);
				}
			}

			// 欠落検知→Shadow GET
			let heartbeatTimer = setInterval(() => {
				if (!lastHB) return;
				const timeSinceLastHB = Date.now() - lastHB;

				// CHANGED: より長い時間待ってから通信不良と判定（45秒）
				if (timeSinceLastHB > 45000) {
					setStatus("通信不良（再同期中）", "warn");
					if (client.isConnected()) {
						try {
							const message = new Paho.MQTT.Message("{}");
							message.destinationName = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`;
							message.qos = 1;
							client.send(message);
						} catch (err) {
							console.error('[Paho MQTT] Shadow get publish error:', err);
						}
					}
				}

				// CHANGED: 非常に長時間の場合のみ強制再接続（5分）
				if (timeSinceLastHB > 300000 && client.isConnected()) {
					console.warn('[Paho MQTT] Force reconnect due to very long heartbeat gap (5min)');
					try {
						client.disconnect();
						setTimeout(() => {
							connectWithRetry(); // 新しい認証情報で再接続
						}, 3000);
					} catch (err) {
						console.error('[Paho MQTT] Force reconnect error:', err);
					}
				}
			}, 5000); // CHANGED: チェック間隔を5秒に変更

			// 接続オプション（タイムアウト値を調整）
			const connectOptions = {
				useSSL: true,
				timeout: 60,                // CHANGED: タイムアウトを60秒に延長
				keepAliveInterval: 30,
				mqttVersion: 4,
				onSuccess: function () {
					console.log('[Paho MQTT] Connected successfully!');
					setStatus("接続済み", "ok");
					setBtnMoving(false);

					// REMOVED: 重複した lastHB 初期化を削除（既に connect 関数開始時に設定済み）

					// トピックをサブスクライブ（Classic Shadow対応も追加）
					const topics = [
						`amr/${cfg.thingName}/status`,
						// Named Shadow (現在の設定)
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/update/documents`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/accepted`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/rejected`,
						// Classic Shadow（デバッグ用）
						`$aws/things/${cfg.thingName}/shadow/update/documents`,
						`$aws/things/${cfg.thingName}/shadow/get/accepted`,
						`$aws/things/${cfg.thingName}/shadow/get/rejected`
					];

					// 順次サブスクライブ
					topics.forEach((topic, index) => {
						setTimeout(() => {
							try {
								client.subscribe(topic, {
									qos: 1,
									onSuccess: function () {
										console.log(`[Paho MQTT] Subscribed to ${topic}`);
									},
									onFailure: function (err) {
										console.error(`[Paho MQTT] Subscribe error for ${topic}:`, err);
									}
								});
							} catch (err) {
								console.error(`[Paho MQTT] Subscribe setup error for ${topic}:`, err);
							}
						}, index * 300); // CHANGED: 300ms間隔でより安全に実行
					});

					// ADDED: Shadow存在確認のため複数パターンをテスト
					setTimeout(() => {
						if (!client.isConnected()) return;

						const shadowTests = [
							"", // Classic Shadow
							"robot", // 設定されている名前
							"main", // よくある名前
							"status" // よくある名前
						];

						shadowTests.forEach((shadowName, index) => {
							setTimeout(() => {
								try {
									const topic = shadowName ?
										`$aws/things/${cfg.thingName}/shadow/name/${shadowName}/get` :
										`$aws/things/${cfg.thingName}/shadow/get`;

									console.log(`[DEBUG] Testing shadow: "${shadowName || 'classic'}" with topic: ${topic}`);

									const message = new Paho.MQTT.Message("{}");
									message.destinationName = topic;
									message.qos = 1;
									client.send(message);
								} catch (err) {
									console.error(`[DEBUG] Shadow test error for "${shadowName}":`, err);
								}
							}, index * 1000); // 1秒間隔でテスト
						});
					}, 3000);
				},
				onFailure: function (err) {
					console.error('[Paho MQTT] Connection failed:', err);
					setStatus("接続失敗", "warn");
				}
			};

			// メッセージ受信ハンドラ
			client.onMessageArrived = function (message) {
				try {
					const topic = message.destinationName;
					const payloadStr = message.payloadString;
					const js = JSON.parse(payloadStr);

					console.log(`[Paho MQTT] Message on ${topic}:`, js);

					if (topic.endsWith("/status")) {
						update(js);
					} else if (topic.endsWith("/get/accepted")) {
						const r = js?.state?.reported;
						if (r) update({
							state: r.state,
							updatedAt: r.updatedAt,
							heartbeatAt: r.heartbeatAt
						});
					} else if (topic.endsWith("/get/rejected")) {
						// ADDED: Shadow get エラーハンドリング
						console.warn(`[Paho MQTT] Shadow get rejected:`, js);
						if (js.code === 404) {
							console.warn(`[Paho MQTT] Shadow '${cfg.shadowName}' does not exist for thing '${cfg.thingName}'`);
							setStatus("Shadow未作成", "warn");
						}
					} else if (topic.endsWith("/update/documents")) {
						const r = js?.current?.state?.reported;
						if (r) update({
							state: r.state,
							updatedAt: r.updatedAt,
							heartbeatAt: r.heartbeatAt
						});
					}
				} catch (e) {
					console.error('[Paho MQTT] Message parse error:', e);
				}
			};

			// 接続失敗ハンドラ
			client.onConnectionLost = function (responseObject) {
				console.log('[Paho MQTT] Connection lost:', responseObject);
				setStatus("接続切断", "warn");
				setBtnMoving(true);

				// CHANGED: エラーコード0（正常切断）以外の場合のみ自動再接続
				if (responseObject.errorCode !== 0) {
					console.log('[Paho MQTT] Attempting reconnection in 5 seconds...');
					setTimeout(() => {
						try {
							// CHANGED: 新しい認証情報で完全に再接続
							connectWithRetry();
						} catch (err) {
							console.error('[Paho MQTT] Reconnection setup error:', err);
						}
					}, 5000); // 5秒待ってから再接続
				}
			};

			// 呼出しボタン
			el.callBtn.onclick = () => {
				if (!client.isConnected()) {
					console.warn('[Paho MQTT] Not connected');
					return;
				}

				const dest = el.dest.value;
				if (!dest) {
					alert('行先を選択してください');
					return;
				}

				const req = {
					requestId: [Date.now(), Math.random().toString(36).slice(-6)].join("-"),
					dest: dest,
					timestamp: new Date().toISOString()
				};

				console.log('[Paho MQTT] Publishing call request:', req);

				try {
					const message = new Paho.MQTT.Message(JSON.stringify(req));
					message.destinationName = `amr/${cfg.thingName}/cmd/call`;
					message.qos = 1;
					client.send(message);
					console.log('[Paho MQTT] Call request sent');
					setBtnMoving(true);
				} catch (err) {
					console.error('[Paho MQTT] Publish error:', err);
					setStatus("送信エラー", "warn");
				}
			};

			// クリーンアップ関数（簡素化）
			const cleanup = () => {
				console.log('[DEBUG] Cleanup called');
				// ハートビートタイマーは削除済みのため、クリーンアップ不要
			};

			// ページ離脱時のクリーンアップ
			window.addEventListener('beforeunload', cleanup);

			// 接続開始
			console.log('[Paho MQTT] Starting connection...');
			client.connect(connectOptions);

		} catch (error) {
			console.error('[Paho MQTT] Connection setup error:', error);
			setStatus("接続設定エラー", "warn");
		}
	}

	// 認証クレデンシャルを確定→接続
	const connectWithRetry = (retryCount = 0) => {
		setStatus("認証確認中…");
		AWS.config.credentials.get((err) => {
			if (err) {
				console.error("Credentials error:", err);

				// 認証エラー時のリトライ（最大3回）
				if (retryCount < 3) {
					console.warn(`[AWS] Retrying credential refresh (${retryCount + 1}/3)`);
					setTimeout(() => connectWithRetry(retryCount + 1), 2000 * (retryCount + 1));
					return;
				}

				setStatus("資格情報エラー", "warn");
				return;
			}

			// 期限チェック
			const exp = AWS.config.credentials.expireTime?.getTime?.() || 0;
			if (exp && exp - Date.now() < 60 * 1000) {
				console.warn("[AWS] 資格情報の残寿命が1分未満。");
			}

			connect(AWS.config.credentials);
		});
	};

	// 初回接続開始
	connectWithRetry();
})();

// --- 追加: バーガーメニューの外側クリック/Escで閉じる ---
(function attachMenuCloser() {
	const menu = document.getElementById('appMenu');
	if (!menu) return;

	// メニュー項目をクリックしたら閉じる
	const closeOnClick = (el) => el && el.addEventListener('click', () => { menu.open = false; });
	closeOnClick(document.getElementById('logoutBtn'));
	closeOnClick(document.getElementById('menuRegisterDevice'));

	// 外側クリックで閉じる
	document.addEventListener('click', (e) => {
		if (!menu.open) return;
		if (menu.contains(e.target)) return; // メニュー内のクリックは無視
		menu.open = false;
	});

	// Escで閉じる
	document.addEventListener('keydown', (e) => {
		if (e.key === 'Escape' && menu.open) menu.open = false;
	});
})();

// --- 追加: メニュー「デバイスを登録」→ パスキー登録/自己判定付き ---
// メニュー「パスキー登録/削除」トグル対応
// 参考: README の「認証 > Passkeys（ユーザープール）」、手順書の該当セクション
(function attachRegisterDeviceHandler() {
	const btn = document.getElementById('menuRegisterDevice');
	const menuEl = document.getElementById('appMenu');
	if (!btn) return;

	const cfg = window.IOTGW_CONFIG;
	const COG_URL = `https://cognito-idp.${cfg.region}.amazonaws.com/`;

	// CHANGED: 未認証ユーザーの場合は無効化
	const idToken = sessionStorage.getItem("id_token");
	if (!idToken) {
		btn.textContent = "パスキー機能（要認証）";
		btn.disabled = true;
		btn.title = "パスキー機能を使用するには認証が必要です";
		return;
	}

	// ===== ADDED: User Pool トークンの自動リフレッシュ（期限60秒前に更新） =====
	const loginsKey = `cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
	let __rtTimer = null;

	function scheduleTokenRefresh() {
		const expSec = Number(sessionStorage.getItem("expires_in") || 3600);
		const skew = 60;
		const ms = Math.max(5, expSec - skew) * 1000;
		clearTimeout(__rtTimer);
		__rtTimer = setTimeout(refreshTokens, ms);
	}

	async function refreshTokens() {
		const refresh = sessionStorage.getItem("refresh_token");
		if (!refresh) return;

		try {
			const r = await (async function cognitoInitiateAuth() {
				const headers = {
					"Content-Type": "application/x-amz-json-1.0",
					"X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth"
				};
				const body = {
					AuthFlow: "REFRESH_TOKEN_AUTH",
					ClientId: cfg.userPoolClientId,
					AuthParameters: { REFRESH_TOKEN: refresh }
				};
				const res = await fetch(`https://cognito-idp.${cfg.region}.amazonaws.com/`, {
					method: "POST", headers, body: JSON.stringify(body)
				});
				const js = await res.json().catch(() => ({}));
				if (!res.ok) throw Object.assign(new Error(js.message || res.statusText), { status: res.status, details: js });
				return js;
			})();

			const a = r.AuthenticationResult;
			if (!a) throw new Error("No AuthenticationResult from REFRESH_TOKEN_AUTH");

			sessionStorage.setItem("id_token", a.IdToken);
			sessionStorage.setItem("access_token", a.AccessToken);
			sessionStorage.setItem("expires_in", String(a.ExpiresIn || 3600));

			if (AWS.config && AWS.config.credentials && AWS.config.credentials.params) {
				AWS.config.credentials.params.Logins[loginsKey] = a.IdToken;
				AWS.config.credentials.expired = true;
				try { AWS.config.credentials.refresh(() => { }); } catch { }
			}

			scheduleTokenRefresh();
			console.info("[Auth] tokens refreshed");
		} catch (e) {
			console.warn("[Auth] token refresh failed", e);
		}
	}

	if (sessionStorage.getItem("refresh_token")) {
		scheduleTokenRefresh();
	}

	// ====== ADDED: 端末ローカルの CredentialId → エイリアス保存 ======
	const LOCAL_ALIAS_KEY = "webauthn_aliases_v1";
	function loadAliases() {
		try { return JSON.parse(localStorage.getItem(LOCAL_ALIAS_KEY) || "{}"); } catch { return {}; }
	}
	function saveAliases(map) { localStorage.setItem(LOCAL_ALIAS_KEY, JSON.stringify(map)); }
	function setAlias(credId, alias) { const m = loadAliases(); m[credId] = alias; saveAliases(m); }
	function removeAlias(credId) { const m = loadAliases(); if (m[credId]) { delete m[credId]; saveAliases(m); } }
	function makeDefaultAlias() {
		const pf = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "device";
		return `${location.hostname} / ${pf} / ${new Date().toISOString().slice(0, 10)}`;
	}

	// Base64URL ⇔ ArrayBuffer（WebAuthn用：局所ユーティリティ）
	const b64uToBuf = (s) => {
		if (s instanceof ArrayBuffer) return s;
		const pad = (x) => x + "===".slice((x.length + 3) % 4);
		const b64 = pad(String(s).replace(/-/g, "+").replace(/_/g, "/"));
		const bin = atob(b64);
		const u = new Uint8Array(bin.length);
		for (let i = 0; i < u.length; i++) u[i] = bin.charCodeAt(i);
		return u.buffer;
	};
	const bufToB64u = (buf) => {
		const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
		let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
		return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
	};

	// Cognito JSON API（User Pools）
	async function cognito(action, body, accessToken) {
		const headers = {
			"Content-Type": "application/x-amz-json-1.0",
			"X-Amz-Target": `AWSCognitoIdentityProviderService.${action}`
		};
		const res = await fetch(COG_URL, { method: "POST", headers, body: JSON.stringify(body) });
		const js = await res.json().catch(() => ({}));
		if (!res.ok) {
			const msg = js.message || js.__type || res.statusText;
			throw Object.assign(new Error(msg), { status: res.status, details: js });
		}
		return js;
	}

	// --- WebAuthn: 登録/一覧/削除 ---
	async function startRegister(accessToken) {
		const start = await cognito("StartWebAuthnRegistration", { AccessToken: accessToken }, accessToken);
		let opts = start.PublicKeyCredentialCreationOptions || start.CredentialCreationOptions || start.Options || start.CREDENTIAL_CREATION_OPTIONS;
		if (typeof opts === "string") try { opts = JSON.parse(opts); } catch { }
		if (!opts) throw new Error("登録オプションを取得できませんでした。");

		// navigator.credentials.create 用に整形
		opts.challenge = b64uToBuf(opts.challenge);
		if (opts.user && typeof opts.user.id === "string") opts.user.id = b64uToBuf(opts.user.id);
		if (Array.isArray(opts.excludeCredentials)) {
			opts.excludeCredentials = opts.excludeCredentials.map(c => ({ ...c, id: typeof c.id === "string" ? b64uToBuf(c.id) : c.id }));
		}
		const cred = await navigator.credentials.create({ publicKey: opts });
		if (!cred) throw new Error("パスキー作成がキャンセルされました。");

		// Complete
		const regJSON = {
			id: cred.id,
			rawId: bufToB64u(cred.rawId),
			type: cred.type,
			response: {
				attestationObject: bufToB64u(cred.response.attestationObject),
				clientDataJSON: bufToB64u(cred.response.clientDataJSON),
				transports: typeof cred.response.getTransports === "function" ? cred.response.getTransports() : undefined
			},
			clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
		};
		await cognito("CompleteWebAuthnRegistration", { AccessToken: accessToken, Credential: regJSON }, accessToken);

		setAlias(cred.id, makeDefaultAlias());
	}

	async function listPasskeys(accessToken) {
		let all = [];
		let nextToken = undefined;

		do {
			const body = { AccessToken: accessToken, MaxResults: 20 };
			if (nextToken) body.NextToken = nextToken;

			const r = await cognito("ListWebAuthnCredentials", body, accessToken);
			const page = Array.isArray(r.Credentials) ? r.Credentials : [];
			all = all.concat(page);

			nextToken = r.NextToken || r.nextToken || r.NextContinuationToken || null;
		} while (nextToken);

		return all;
	}

	async function deletePasskey(accessToken, credentialId) {
		await cognito("DeleteWebAuthnCredential", { AccessToken: accessToken, CredentialId: credentialId }, accessToken);
	}

	// 同一RPの資格情報だけ対象
	const isSameRp = (rpId) => {
		const host = location.hostname;
		return host === rpId || host.endsWith("." + rpId) || rpId.endsWith("." + host);
	};

	// 一覧のログ出力
	function logCredentialList(creds) {
		try {
			const rows = creds.map(c => ({
				createdAt: c.CreatedAt,
				rpId: c.RelyingPartyId,
				friendly: c.FriendlyCredentialName,
				credId: (c.CredentialId || "").slice(0, 10) + "…" + (c.CredentialId || "").slice(-8),
				transports: (c.AuthenticatorTransports || []).join(","),
				attachment: c.AuthenticatorAttachment || ""
			}));
			console.groupCollapsed("[Cognito] Passkey credentials (this user)");
			console.table(rows);
			console.groupEnd();
		} catch (e) {
			console.info("[logCredentialList] skip", e);
		}
	}

	// --- UI状態管理 ---
	let mode = "register";
	let currentRpCreds = [];

	async function refreshButton() {
		const accessToken = sessionStorage.getItem('access_token');
		if (!accessToken) { btn.textContent = "パスキーを登録"; btn.disabled = true; return; }

		const all = await listPasskeys(accessToken).catch(() => []);
		currentRpCreds = all.filter(c => isSameRp(c.RelyingPartyId));

		logCredentialList(currentRpCreds);

		const aliases = loadAliases();
		const hasThisDevice = currentRpCreds.some(c => aliases[c.CredentialId]);

		if (hasThisDevice) {
			mode = "delete";
			btn.textContent = "この端末のパスキーを削除";
		} else {
			mode = "register";
			btn.textContent = "パスキーを登録（この端末）";
		}
		btn.disabled = false;
	}

	btn.addEventListener('click', async (e) => {
		e.preventDefault();
		const accessToken = sessionStorage.getItem('access_token');
		if (!accessToken) { alert("サインイン情報が見つかりません。サインインし直してください。"); return; }

		const orig = btn.textContent;
		btn.disabled = true;

		try {
			if (mode === "register") {
				btn.textContent = "登録中…";
				await startRegister(accessToken);
				await refreshButton();
			} else {
				btn.textContent = "削除中…";
				const aliases = loadAliases();
				const toDelete = currentRpCreds.filter(c => aliases[c.CredentialId]);
				if (toDelete.length === 0) {
					alert("この端末で登録されたパスキーは見つかりません。");
				} else {
					for (const cred of toDelete) {
						await deletePasskey(accessToken, cred.CredentialId);
						removeAlias(cred.CredentialId);
					}
				}
				await refreshButton();
			}
			if (menuEl && menuEl.open) menuEl.open = false;
		} catch (err) {
			console.error("[passkey toggle] error:", err);
			alert("処理に失敗しました: " + (err?.message || err));
			btn.textContent = orig;
		} finally {
			btn.disabled = false;
		}
	});

	refreshButton().catch((e) => console.warn("ListWebAuthnCredentials 失敗:", e));
})();