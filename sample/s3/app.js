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

	// ===== 認証チェック（未認証はリダイレクト） =====
	const idToken = sessionStorage.getItem("id_token");
	if (!idToken) { location.replace("./signout.html"); return; }
	el.authInfo.textContent = "認証状態: 認証済み";

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

	// ===== AWS 資格情報（ID プール） =====
	AWS.config.region = cfg.region;
	const loginsKey = `cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
	AWS.config.credentials = new AWS.CognitoIdentityCredentials({
		IdentityPoolId: cfg.identityPoolId,
		Logins: { [loginsKey]: idToken }
	});

	// ===== SigV4 署名ユーティリティ（CryptoJS + moment.js版） =====
	// 参考: https://dev.classmethod.jp/articles/aws-iot-mqtt-over-websocket/
	function SigV4Utils() { }

	SigV4Utils.sign = function (key, msg) {
		var hash = CryptoJS.HmacSHA256(msg, key);
		return hash.toString(CryptoJS.enc.Hex);
	};

	SigV4Utils.sha256 = function (msg) {
		var hash = CryptoJS.SHA256(msg);
		return hash.toString(CryptoJS.enc.Hex);
	};

	SigV4Utils.getSignatureKey = function (key, dateStamp, regionName, serviceName) {
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

		// クエリストリングの構築
		let canonicalQuerystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256';
		canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(accessKey + '/' + credentialScope);
		canonicalQuerystring += '&X-Amz-Date=' + amzdate;
		canonicalQuerystring += '&X-Amz-SignedHeaders=host';

		// セッショントークンがある場合は追加
		if (sessionToken) {
			canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(sessionToken);
		}

		const canonicalHeaders = 'host:' + host + '\n';
		const payloadHash = SigV4Utils.sha256('');

		const canonicalRequest = method + '\n' + canonicalUri + '\n' + canonicalQuerystring + '\n' +
			canonicalHeaders + '\nhost\n' + payloadHash;

		const stringToSign = algorithm + '\n' + amzdate + '\n' + credentialScope + '\n' +
			SigV4Utils.sha256(canonicalRequest);

		const signingKey = SigV4Utils.getSignatureKey(secretKey, dateStamp, region, service);
		const signature = SigV4Utils.sign(signingKey, stringToSign);

		canonicalQuerystring += '&X-Amz-Signature=' + signature;

		return 'wss://' + host + canonicalUri + '?' + canonicalQuerystring;
	}

	function connect(creds) {
		const identityId = AWS.config.credentials.identityId;
		const clientId = identityId;

		console.info("[Paho MQTT] Connecting...", {
			identityId: identityId,
			clientId: clientId,
			endpoint: cfg.iotEndpoint
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

			// CHANGED: Paho MQTT クライアントの作成
			const client = new Paho.MQTT.Client(endpoint, clientId);
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

				if (timeSinceLastHB > 25000) {
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

				// 長時間通信不良の場合は強制再接続
				if (timeSinceLastHB > 60000 && client.isConnected()) {
					console.warn('[Paho MQTT] Force reconnect due to long heartbeat gap');
					try {
						client.disconnect();
						setTimeout(() => {
							client.connect(connectOptions);
						}, 2000);
					} catch (err) {
						console.error('[Paho MQTT] Force reconnect error:', err);
					}
				}
			}, 1000);

			// CHANGED: Paho MQTT のイベントハンドラ
			const connectOptions = {
				useSSL: true,
				timeout: 30,
				keepAliveInterval: 30,
				mqttVersion: 4,
				onSuccess: function () {
					console.log('[Paho MQTT] Connected successfully!');
					setStatus("接続済み", "ok");
					setBtnMoving(false);

					// トピックをサブスクライブ
					const topics = [
						`amr/${cfg.thingName}/status`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/update/documents`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/accepted`
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
						}, index * 200); // 200ms間隔で順次実行
					});

					// 初期Shadow取得
					setTimeout(() => {
						try {
							const message = new Paho.MQTT.Message("{}");
							message.destinationName = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`;
							message.qos = 1;
							client.send(message);
							console.log('[Paho MQTT] Initial shadow get sent');
						} catch (err) {
							console.error('[Paho MQTT] Initial shadow get error:', err);
						}
					}, 1000);
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

				// 自動再接続（エラーコードに応じて）
				if (responseObject.errorCode !== 0) {
					console.log('[Paho MQTT] Attempting reconnection...');
					setTimeout(() => {
						try {
							// 認証情報を更新してから再接続
							AWS.config.credentials.refresh(() => {
								const newEndpoint = createEndpoint(
									cfg.region,
									cfg.iotEndpoint,
									AWS.config.credentials.accessKeyId,
									AWS.config.credentials.secretAccessKey,
									AWS.config.credentials.sessionToken
								);
								const newClient = new Paho.MQTT.Client(newEndpoint, clientId);
								currentClient = newClient;
								newClient.onMessageArrived = client.onMessageArrived;
								newClient.onConnectionLost = client.onConnectionLost;
								newClient.connect(connectOptions);
							});
						} catch (err) {
							console.error('[Paho MQTT] Reconnection error:', err);
						}
					}, 5000);
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

			// クリーンアップ関数
			const cleanup = () => {
				if (heartbeatTimer) {
					clearInterval(heartbeatTimer);
					heartbeatTimer = null;
				}
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