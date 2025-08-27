/**
 * 役割: AMR操作用のMQTTクライアントとUI制御（シンプル版）
 * 基本的なフローで接続し、AMR状態管理を行う
 */
(function () {
	"use strict";

	// ========== 設定とDOM要素 ==========
	const cfg = window.IOTGW_CONFIG;
	const $ = (id) => document.getElementById(id);

	const elements = {
		status: $("status"),
		hbInfo: $("hbInfo"),
		dest: $("dest"),
		callBtn: $("callBtn"),
		authInfo: $("authInfo"),
		logoutBtn: $("logoutBtn"),
		connBadge: $("conn-badge"),
		connText: $("conn-text") || $("conn-badge")?.querySelector("span:not(.dot)")
	};

	// ========== 状態管理 ==========
	let isConnected = false;
	let currentClient = null;
	let lastHeartbeat = null;
	let deviceState = "offline";

	// ========== ユーティリティ関数 ==========
	function setStatus(text, className = '') {
		if (elements.status) {
			elements.status.textContent = text;
			elements.status.className = 'status ' + className;
		}
	}

	function setButtonState(disabled, text) {
		if (elements.callBtn) {
			elements.callBtn.disabled = disabled;
			elements.callBtn.textContent = text || "呼出し";
		}
	}

	function updateConnectionBadge(connected, state = 'offline') {
		if (elements.connBadge) {
			const dot = elements.connBadge.querySelector('.dot');
			if (dot) {
				dot.className = `dot ${connected ? (state === 'moving' ? 'warn' : 'ok') : 'danger'}`;
			}
		}
		if (elements.connText) {
			elements.connText.textContent = connected ? '接続済み' : 'オフライン';
		}
	}

	function updateDeviceStatus(payload) {
		if (!payload) return;

		deviceState = payload.state || deviceState;
		lastHeartbeat = payload.heartbeatAt || payload.updatedAt || Date.now();

		// ハートビート表示更新
		if (elements.hbInfo) {
			elements.hbInfo.textContent = `最終通信: ${new Date(lastHeartbeat).toLocaleString("ja-JP")}`;
		}

		// 状態に応じたUI更新
		switch (deviceState) {
			case "moving":
				setStatus("移動中", "warn");
				setButtonState(true, "呼出し中");
				updateConnectionBadge(true, "moving");
				break;
			case "idle":
				setStatus("待機中", "ok");
				setButtonState(false, "呼出し");
				updateConnectionBadge(true, "idle");
				break;
			case "offline":
				setStatus("オフライン", "danger");
				setButtonState(true, "呼出し");
				updateConnectionBadge(false);
				break;
			default:
				setStatus(deviceState);
		}

		console.log(`[UI] 状態更新: ${deviceState}`);
	}

	// ========== 認証チェック ==========
	const idToken = sessionStorage.getItem("id_token");
	if (!idToken) {
		console.warn("認証情報なし - サインイン画面へリダイレクト");
		location.replace("./signout.html");
		return;
	}

	if (elements.authInfo) {
		elements.authInfo.textContent = "認証状態: 認証済み（User Pool）";
	}

	// ========== 目的地選択肢の設定 ==========
	if (elements.dest && cfg.destinations) {
		cfg.destinations.forEach(dest => {
			const option = document.createElement("option");
			option.value = dest;
			option.textContent = dest;
			elements.dest.appendChild(option);
		});
	}

	// ========== サインアウト処理 ==========
	if (elements.logoutBtn) {
		elements.logoutBtn.onclick = () => {
			if (currentClient && isConnected) {
				try {
					currentClient.disconnect();
				} catch (e) {
					console.warn('切断エラー:', e);
				}
			}
			sessionStorage.clear();
			location.replace("./signout.html");
		};
	}

	// ========== AWS認証設定 ==========
	AWS.config.region = cfg.region;
	const loginsKey = `cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
	AWS.config.credentials = new AWS.CognitoIdentityCredentials({
		IdentityPoolId: cfg.identityPoolId,
		Logins: { [loginsKey]: idToken }
	});

	console.info("[AWS] 認証済みロール設定完了");

	// ========== SigV4署名処理 ==========
	function createSignedUrl(credentials) {
		const host = cfg.iotEndpoint.toLowerCase();
		const time = moment.utc();
		const dateStamp = time.format('YYYYMMDD');
		const amzdate = dateStamp + 'T' + time.format('HHmmss') + 'Z';
		const credentialScope = dateStamp + '/' + cfg.region + '/iotdevicegateway/aws4_request';

		const queryParams = {
			'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
			'X-Amz-Credential': credentials.accessKeyId + '/' + credentialScope,
			'X-Amz-Date': amzdate,
			'X-Amz-SignedHeaders': 'host'
		};

		if (credentials.sessionToken) {
			queryParams['X-Amz-Security-Token'] = credentials.sessionToken;
		}

		// クエリストリング作成（セッショントークンは署名計算から除外）
		let canonicalQuerystring = '';
		const sortedKeys = Object.keys(queryParams).filter(k => k !== 'X-Amz-Security-Token').sort();

		for (let key of sortedKeys) {
			if (canonicalQuerystring) canonicalQuerystring += '&';
			canonicalQuerystring += encodeURIComponent(key) + '=' + encodeURIComponent(queryParams[key]);
		}

		// 署名作成
		const canonicalRequest = 'GET\n/mqtt\n' + canonicalQuerystring + '\nhost:' + host + '\n\nhost\n' +
			CryptoJS.SHA256('').toString();
		const stringToSign = 'AWS4-HMAC-SHA256\n' + amzdate + '\n' + credentialScope + '\n' +
			CryptoJS.SHA256(canonicalRequest).toString();

		const kDate = CryptoJS.HmacSHA256(dateStamp, 'AWS4' + credentials.secretAccessKey);
		const kRegion = CryptoJS.HmacSHA256(cfg.region, kDate);
		const kService = CryptoJS.HmacSHA256('iotdevicegateway', kRegion);
		const kSigning = CryptoJS.HmacSHA256('aws4_request', kService);
		const signature = CryptoJS.HmacSHA256(stringToSign, kSigning).toString();

		// 最終URL作成
		let finalQuerystring = canonicalQuerystring + '&X-Amz-Signature=' + signature;
		if (credentials.sessionToken) {
			finalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
		}

		return 'wss://' + host + '/mqtt?' + finalQuerystring;
	}

	// ========== MQTT接続処理 ==========
	function connectMqtt() {
		const clientId = AWS.config.credentials.identityId;
		console.info("[MQTT] 接続開始:", clientId);
		setStatus("接続中...");

		try {
			const endpoint = createSignedUrl(AWS.config.credentials);
			const wsUrl = new URL(endpoint);
			const client = new Paho.MQTT.Client(
				wsUrl.host,
				wsUrl.port || 443,
				wsUrl.pathname + wsUrl.search,
				clientId
			);

			currentClient = client;

			// 通信監視タイマー
			const heartbeatMonitor = setInterval(() => {
				if (!lastHeartbeat || !isConnected) return;

				const timeSinceLastHB = Date.now() - lastHeartbeat;
				if (timeSinceLastHB > 45000) { // 45秒以上通信なし
					setStatus("通信不良", "warn");
					// Shadow GETで再同期
					if (client.isConnected()) {
						const message = new Paho.MQTT.Message("{}");
						message.destinationName = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`;
						message.qos = 1;
						client.send(message);
						console.log("[MQTT] 再同期実行");
					}
				}
			}, 10000); // 10秒ごとにチェック

			// 接続成功時
			client.onConnectionLost = function (response) {
				console.log("[MQTT] 接続断:", response.errorMessage);
				isConnected = false;
				setStatus("接続断", "warn");
				updateConnectionBadge(false);
				setButtonState(true, "呼出し");
				clearInterval(heartbeatMonitor);

				// 自動再接続（異常切断時のみ）
				if (response.errorCode !== 0) {
					console.log("[MQTT] 5秒後に再接続");
					setTimeout(initializeConnection, 5000);
				}
			};

			// メッセージ受信
			client.onMessageArrived = function (message) {
				try {
					const topic = message.destinationName;
					const payload = JSON.parse(message.payloadString);

					console.log(`[MQTT] 受信: ${topic}`);

					if (topic.endsWith("/status")) {
						updateDeviceStatus(payload);
					} else if (topic.endsWith("/get/accepted")) {
						const reported = payload?.state?.reported;
						if (reported) {
							updateDeviceStatus({
								state: reported.state,
								updatedAt: reported.updatedAt,
								heartbeatAt: reported.heartbeatAt
							});
						}
					} else if (topic.endsWith("/get/rejected")) {
						if (payload.code === 404) {
							setStatus("Shadow未作成", "warn");
						}
					} else if (topic.endsWith("/update/documents")) {
						const reported = payload?.current?.state?.reported;
						if (reported) {
							updateDeviceStatus({
								state: reported.state,
								updatedAt: reported.updatedAt,
								heartbeatAt: reported.heartbeatAt
							});
						}
					}
				} catch (e) {
					console.error('[MQTT] メッセージ解析エラー:', e);
				}
			};

			// 接続実行
			client.connect({
				useSSL: true,
				timeout: 30,
				keepAliveInterval: 30,
				mqttVersion: 4,
				onSuccess: function () {
					console.log("[MQTT] 接続成功");
					isConnected = true;
					setStatus("接続済み", "ok");
					updateConnectionBadge(true);

					// 購読
					const topics = [
						`amr/${cfg.thingName}/status`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/update/documents`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/accepted`,
						`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/rejected`
					];

					topics.forEach(topic => {
						client.subscribe(topic, { qos: 1 });
						console.log(`[MQTT] 購読: ${topic.split('/').pop()}`);
					});

					// Shadow状態確認
					setTimeout(() => {
						if (client.isConnected()) {
							const message = new Paho.MQTT.Message("{}");
							message.destinationName = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`;
							message.qos = 1;
							client.send(message);
							console.log("[MQTT] Shadow状態確認");
						}
					}, 1000);

					setButtonState(false, "呼出し");
				},
				onFailure: function (err) {
					console.error("[MQTT] 接続失敗:", err);
					setStatus("接続失敗", "danger");
					updateConnectionBadge(false);
				}
			});

		} catch (error) {
			console.error("[MQTT] 設定エラー:", error);
			setStatus("接続設定エラー", "danger");
		}
	}

	// ========== 呼出し処理 ==========
	if (elements.callBtn) {
		elements.callBtn.onclick = () => {
			if (!currentClient || !currentClient.isConnected()) {
				alert('MQTTに接続されていません');
				return;
			}

			const dest = elements.dest?.value;
			if (!dest) {
				alert('目的地を選択してください');
				return;
			}

			const request = {
				requestId: Date.now() + "-" + Math.random().toString(36).slice(-6),
				dest: dest,
				timestamp: new Date().toISOString()
			};

			try {
				const message = new Paho.MQTT.Message(JSON.stringify(request));
				message.destinationName = `amr/${cfg.thingName}/cmd/call`;
				message.qos = 1;
				currentClient.send(message);

				console.log(`[CALL] 呼出し送信: ${dest}`);
				setButtonState(true, "呼出し中");
			} catch (err) {
				console.error('[CALL] 送信エラー:', err);
				alert('呼出し要求の送信に失敗しました');
			}
		};
	}

	// ========== 初期化処理 ==========
	function initializeConnection() {
		setStatus("認証確認中...");

		AWS.config.credentials.get((err) => {
			if (err) {
				console.error("認証エラー:", err);
				setStatus("認証エラー", "danger");
				return;
			}

			console.info("[AWS] 認証情報取得完了");
			connectMqtt();
		});
	}

	// ========== バーガーメニュー処理 ==========
	const menu = document.getElementById('appMenu');
	if (menu) {
		// メニュー外クリックで閉じる
		document.addEventListener('click', (e) => {
			if (menu.open && !menu.contains(e.target)) {
				menu.open = false;
			}
		});

		// Escキーで閉じる
		document.addEventListener('keydown', (e) => {
			if (e.key === 'Escape' && menu.open) {
				menu.open = false;
			}
		});

		// パスキー登録状態の確認と表示更新（元のrefreshButton()を復活）
		const registerBtn = document.getElementById('menuRegisterDevice');
		if (registerBtn) {
			const COG_URL = `https://cognito-idp.${cfg.region}.amazonaws.com/`;
			const LOCAL_ALIAS_KEY = "webauthn_aliases_v1";

			let mode = "register";
			let currentRpCreds = [];

			// ローカルエイリアス管理
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

			// 同一RPチェック
			const isSameRp = (rpId) => {
				const host = location.hostname;
				return host === rpId || host.endsWith("." + rpId) || rpId.endsWith("." + host);
			};

			// Cognito API
			async function cognito(action, body) {
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

			// パスキー一覧取得
			async function listPasskeys(accessToken) {
				let all = [];
				let nextToken = undefined;

				do {
					const body = { AccessToken: accessToken, MaxResults: 20 };
					if (nextToken) body.NextToken = nextToken;

					const r = await cognito("ListWebAuthnCredentials", body);
					const page = Array.isArray(r.Credentials) ? r.Credentials : [];
					all = all.concat(page);

					nextToken = r.NextToken || r.nextToken || r.NextContinuationToken || null;
				} while (nextToken);

				return all;
			}

			// パスキー登録
			async function startRegister(accessToken) {
				const start = await cognito("StartWebAuthnRegistration", { AccessToken: accessToken });
				let opts = start.PublicKeyCredentialCreationOptions || start.CredentialCreationOptions || start.Options || start.CREDENTIAL_CREATION_OPTIONS;
				if (typeof opts === "string") try { opts = JSON.parse(opts); } catch { }
				if (!opts) throw new Error("登録オプションを取得できませんでした。");

				// Base64URL変換
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

				// navigator.credentials.create用に整形
				opts.challenge = b64uToBuf(opts.challenge);
				if (opts.user && typeof opts.user.id === "string") opts.user.id = b64uToBuf(opts.user.id);
				if (Array.isArray(opts.excludeCredentials)) {
					opts.excludeCredentials = opts.excludeCredentials.map(c => ({
						...c,
						id: typeof c.id === "string" ? b64uToBuf(c.id) : c.id
					}));
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
				await cognito("CompleteWebAuthnRegistration", { AccessToken: accessToken, Credential: regJSON });

				setAlias(cred.id, makeDefaultAlias());
			}

			// パスキー削除
			async function deletePasskey(accessToken, credentialId) {
				await cognito("DeleteWebAuthnCredential", { AccessToken: accessToken, CredentialId: credentialId });
			}

			// 一覧のログ出力（元のlogCredentialList）
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

			// refreshButton()を復活
			async function refreshButton() {
				const accessToken = sessionStorage.getItem('access_token');
				if (!accessToken) {
					registerBtn.textContent = "パスキーを登録";
					registerBtn.disabled = true;
					return;
				}

				try {
					const all = await listPasskeys(accessToken);
					currentRpCreds = all.filter(c => isSameRp(c.RelyingPartyId));

					logCredentialList(currentRpCreds);

					const aliases = loadAliases();
					const hasThisDevice = currentRpCreds.some(c => aliases[c.CredentialId]);

					if (hasThisDevice) {
						mode = "delete";
						registerBtn.textContent = "この端末のパスキーを削除";
					} else {
						mode = "register";
						registerBtn.textContent = "この端末にパスキーを登録";
					}
					registerBtn.disabled = false;
				} catch (e) {
					console.warn("refreshButton error:", e);
					registerBtn.textContent = "パスキーを登録";
					registerBtn.disabled = false;
				}
			}

			// ボタンクリック処理
			registerBtn.addEventListener('click', async (e) => {
				e.preventDefault();
				const accessToken = sessionStorage.getItem('access_token');
				if (!accessToken) {
					alert("サインイン情報が見つかりません。サインインし直してください。");
					return;
				}

				const orig = registerBtn.textContent;
				registerBtn.disabled = true;

				try {
					if (mode === "register") {
						registerBtn.textContent = "登録中…";
						await startRegister(accessToken);

						// remember_username保存
						const idToken = sessionStorage.getItem('id_token');
						if (idToken) {
							try {
								const payload = JSON.parse(atob(idToken.split('.')[1]));
								const username = payload.email || payload['cognito:username'] || payload.sub;
								if (username) {
									localStorage.setItem("remember_username", username);
								}
							} catch (e) {
								console.warn('ID tokenからユーザー名取得失敗:', e);
							}
						}

						await refreshButton();
					} else {
						registerBtn.textContent = "削除中…";
						const aliases = loadAliases();
						const toDelete = currentRpCreds.filter(c => aliases[c.CredentialId]);
						if (toDelete.length === 0) {
							alert("この端末で登録されたパスキーは見つかりません。");
						} else {
							for (const cred of toDelete) {
								await deletePasskey(accessToken, cred.CredentialId);
								removeAlias(cred.CredentialId);
							}
							// remember_username削除
							localStorage.removeItem("remember_username");
						}
						await refreshButton();
					}
					if (menu.open) menu.open = false;

				} catch (err) {
					console.error("[passkey toggle] error:", err);
					alert("処理に失敗しました: " + (err?.message || err));
					registerBtn.textContent = orig;
				} finally {
					registerBtn.disabled = false;
				}
			});

			// 初回refreshButton実行
			refreshButton();
		}
	}

	// ========== 初期化実行 ==========
	console.info('[AMR App] 初期化開始');
	initializeConnection();

})();