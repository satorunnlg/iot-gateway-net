(function () {
	"use strict";

	const cfg = window.IOTGW_CONFIG;

	// ===== Hosted UI（implicit）URL組み立て =====
	function buildAuthorizeUrl(registerOnly) {
		const base = `https://${cfg.userPoolDomain}/oauth2/authorize`;
		const q = new URLSearchParams({
			response_type: cfg.oauth.responseType, // token（implicit）
			client_id: cfg.userPoolClientId,
			redirect_uri: cfg.redirectUri,
			scope: cfg.oauth.scope,
			// ヒント: registerOnly のときは "signup" 相当のUI導線に遷移したい場合があるが、
			// Hosted UI の Passkey では同じ画面で「この端末を登録」を選べるためここでは同一。
		});
		return `${base}?${q.toString()}`;
	}

	function buildLogoutUrl() {
		const base = `https://${cfg.userPoolDomain}/logout`;
		const q = new URLSearchParams({
			client_id: cfg.userPoolClientId,
			logout_uri: cfg.redirectUri
		});
		return `${base}?${q.toString()}`;
	}

	// ===== URL ハッシュ（implicit）からトークン抽出 =====
	function captureTokensFromHash() {
		if (!location.hash) return null;
		const p = new URLSearchParams(location.hash.slice(1));
		const idToken = p.get("id_token");
		const accessToken = p.get("access_token");
		const expiresIn = p.get("expires_in");
		if (idToken) {
			sessionStorage.setItem("id_token", idToken);
			if (accessToken) sessionStorage.setItem("access_token", accessToken);
			if (expiresIn) sessionStorage.setItem("expires_in", expiresIn);
			// ハッシュ除去
			history.replaceState(null, "", location.pathname + location.search);
			return idToken;
		}
		return null;
	}

	function getIdToken() {
		return sessionStorage.getItem("id_token") || null;
	}

	function clearTokens() {
		sessionStorage.removeItem("id_token");
		sessionStorage.removeItem("access_token");
		sessionStorage.removeItem("expires_in");
	}

	// ===== AWS 認証情報（Cognito Identity）=====
	async function getCognitoIdentityCredentials(idToken) {
		AWS.config.region = cfg.region;
		const loginsKey = `cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
		AWS.config.credentials = new AWS.CognitoIdentityCredentials({
			IdentityPoolId: cfg.identityPoolId,
			Logins: { [loginsKey]: idToken }
		});
		return new Promise((resolve, reject) => {
			AWS.config.credentials.clearCachedId();
			AWS.config.credentials.get(function (err) {
				if (err) return reject(err);
				resolve(AWS.config.credentials);
			});
		});
	}

	// ===== SigV4 署名付き WebSocket URL を作成（IoT Core /mqtt）=====
	function toAmzDate(date) {
		const pad = n => (n < 10 ? "0" + n : "" + n);
		return date.getUTCFullYear().toString() +
			pad(date.getUTCMonth() + 1) +
			pad(date.getUTCDate()) + "T" +
			pad(date.getUTCHours()) +
			pad(date.getUTCMinutes()) +
			pad(date.getUTCSeconds()) + "Z";
	}
	function toDateStamp(amzDate) { return amzDate.slice(0, 8); }

	function hmac(key, string, hex) {
		const res = AWS.util.crypto.hmac(key, string, "buffer");
		return hex ? AWS.util.crypto.toHex(res) : res;
	}
	function sha256(data, hex) {
		const res = AWS.util.crypto.sha256(data, "buffer");
		return hex ? AWS.util.crypto.toHex(res) : res;
	}

	function buildSignedUrlForIotMqtt(creds) {
		const host = cfg.iotEndpoint; // xxxxx-ats.iot.ap-northeast-1.amazonaws.com
		const service = "iotdevicegateway";
		const region = cfg.region;
		const algorithm = "AWS4-HMAC-SHA256";
		const method = "GET";
		const canonicalUri = "/mqtt";

		const amzDate = toAmzDate(new Date());
		const dateStamp = toDateStamp(amzDate);
		const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

		// Query params
		const params = {
			"X-Amz-Algorithm": algorithm,
			"X-Amz-Credential": encodeURIComponent(`${creds.accessKeyId}/${credentialScope}`),
			"X-Amz-Date": amzDate,
			"X-Amz-SignedHeaders": "host"
		};
		if (creds.sessionToken) {
			params["X-Amz-Security-Token"] = encodeURIComponent(creds.sessionToken);
		}

		// Canonical query string（キーで昇順ソート／エンコード済の値を連結）
		const sortedKeys = Object.keys(params).sort();
		const canonicalQuerystring = sortedKeys.map(k => `${k}=${params[k]}`).join("&");

		const canonicalHeaders = `host:${host}\n`;
		const signedHeaders = "host";
		const payloadHash = sha256("", true);
		const canonicalRequest = [
			method, canonicalUri, canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash
		].join("\n");
		const stringToSign = [
			algorithm, amzDate, credentialScope, sha256(canonicalRequest, true)
		].join("\n");

		// 署名鍵
		const kDate = hmac("AWS4" + creds.secretAccessKey, dateStamp);
		const kRegion = hmac(kDate, region);
		const kService = hmac(kRegion, service);
		const kSigning = hmac(kService, "aws4_request", true);
		const signature = hmac(kSigning, stringToSign, true);

		const requestUrl = `wss://${host}${canonicalUri}?${canonicalQuerystring}&X-Amz-Signature=${signature}`;
		return requestUrl;
	}

	// ===== UI / MQTT =====
	const el = {
		status: document.getElementById("status"),
		hbInfo: document.getElementById("hbInfo"),
		dest: document.getElementById("dest"),
		callBtn: document.getElementById("callBtn"),
		loginBtn: document.getElementById("loginBtn"),
		registerBtn: document.getElementById("registerBtn"),
		logoutBtn: document.getElementById("logoutBtn"),
		authInfo: document.getElementById("authInfo")
	};

	cfg.destinations.forEach(d => {
		const opt = document.createElement("option");
		opt.value = d; opt.textContent = d;
		el.dest.appendChild(opt);
	});

	let pahoClient = null;
	let lastHeartbeatMs = 0;
	let currentState = "—";
	let reconnectDelay = 1000; // backoff

	function setStatus(text, cls) {
		el.status.textContent = text;
		el.status.classList.remove("ok", "warn");
		if (cls) el.status.classList.add(cls);
	}

	function setButtonMoving(moving) {
		if (moving) {
			el.callBtn.textContent = "呼出し中";
			el.callBtn.disabled = true;
		} else {
			el.callBtn.textContent = "呼出し";
			el.callBtn.disabled = false;
		}
	}

	function updateFromStatusPayload(payload) {
		// payload: {state, updatedAt, heartbeatAt, requestId?}
		if (!payload) return;
		currentState = payload.state || currentState;
		lastHeartbeatMs = payload.heartbeatAt || payload.updatedAt || Date.now();
		el.hbInfo.textContent = `HB: ${new Date(lastHeartbeatMs).toLocaleString()}`;

		if (currentState === "moving") {
			setStatus("移動中", "ok");
			setButtonMoving(true);
		} else if (currentState === "idle") {
			setStatus("待機中", "ok");
			setButtonMoving(false);
		} else if (currentState === "offline") {
			setStatus("オフライン", "warn");
			setButtonMoving(true);
		} else {
			setStatus(currentState, "");
		}
	}

	// 心拍欠落監視（25秒）
	setInterval(() => {
		if (!lastHeartbeatMs) return;
		const diff = Date.now() - lastHeartbeatMs;
		if (diff > 25000) {
			setStatus("通信不良（再同期中）", "warn");
			// Shadow GET を保険で叩く
			if (pahoClient && pahoClient.isConnected()) {
				const topic = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`;
				pahoClient.send(topic, "{}", 1, false);
			}
		}
	}, 1000);

	function subscribeTopics() {
		const statusTopic = `amr/${cfg.thingName}/status`;
		const docTopic = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/update/documents`;
		const getAccepted = `$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/accepted`;

		pahoClient.subscribe(statusTopic, { qos: 1 });
		pahoClient.subscribe(docTopic, { qos: 1 });
		pahoClient.subscribe(getAccepted, { qos: 1 });

		// 初期同期: Shadow GET
		pahoClient.send(`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`, "{}", 1, false);
	}

	function onMessageArrived(message) {
		try {
			const topic = message.destinationName;
			const txt = message.payloadString;
			if (!txt) return;
			const data = JSON.parse(txt);

			if (topic.endsWith("/status")) {
				updateFromStatusPayload(data);
			} else if (topic.endsWith("/get/accepted")) {
				const rep = data && data.state && data.state.reported;
				if (rep) {
					updateFromStatusPayload({
						state: rep.state,
						updatedAt: rep.updatedAt,
						heartbeatAt: rep.heartbeatAt
					});
				}
			} else if (topic.endsWith("/update/documents")) {
				// 最新 reported を採用
				const rep = data && data.current && data.current.state && data.current.state.reported;
				if (rep) {
					updateFromStatusPayload({
						state: rep.state,
						updatedAt: rep.updatedAt,
						heartbeatAt: rep.heartbeatAt
					});
				}
			}
		} catch (e) {
			console.error("onMessage error", e);
		}
	}

	function connectMqtt(signedUrl, clientId) {
		// Paho は host, port, path を別指定するため、URL を分解
		const u = new URL(signedUrl);
		const host = u.host;
		const path = u.pathname + u.search;

		pahoClient = new Paho.MQTT.Client(host, 443, path, clientId);

		pahoClient.onConnectionLost = (resp) => {
			console.warn("connection lost", resp);
			setStatus("切断（再接続待ち）", "warn");
			setButtonMoving(true);
			// バックオフ再接続（認証が有効なうちは同じURLでOK）
			setTimeout(() => {
				try {
					pahoClient.connect(connectOptions);
				} catch (e) { console.error(e); }
				reconnectDelay = Math.min(reconnectDelay * 2, 30000);
			}, reconnectDelay);
		};

		pahoClient.onMessageArrived = onMessageArrived;

		const connectOptions = {
			useSSL: true,
			timeout: 10,
			mqttVersion: 4,
			cleanSession: true,
			onSuccess: function () {
				console.log("mqtt connected");
				reconnectDelay = 1000;
				setStatus("接続済み", "ok");
				setButtonMoving(false);
				subscribeTopics();
			},
			onFailure: function (err) {
				console.error("mqtt failed", err);
				setStatus("接続失敗", "warn");
			}
		};

		pahoClient.connect(connectOptions);
	}

	function randomSuffix(n) {
		return Math.random().toString(36).slice(-(n || 5));
	}

	// ===== UI ハンドラ =====
	el.loginBtn.onclick = function () {
		location.href = buildAuthorizeUrl(false);
	};
	el.registerBtn.onclick = function () {
		// Hosted UIで Passkey の追加登録フローへ（同じ authorize に遷移）
		location.href = buildAuthorizeUrl(true);
	};
	el.logoutBtn.onclick = function () {
		clearTokens();
		location.href = buildLogoutUrl();
	};

	el.callBtn.onclick = function () {
		if (!pahoClient || !pahoClient.isConnected()) return;
		const dest = el.dest.value;
		const req = {
			requestId: ([Date.now(), randomSuffix(6)].join("-")),
			dest
		};
		const topic = `amr/${cfg.thingName}/cmd/call`;
		const msg = new Paho.MQTT.Message(JSON.stringify(req));
		msg.destinationName = topic;
		msg.qos = 1;
		pahoClient.send(msg);
		setButtonMoving(true);
	};

	// ===== 起動フロー =====
	(async function bootstrap() {
		try {
			captureTokensFromHash();
			const idToken = getIdToken();
			if (!idToken) {
				setStatus("未認証（サインインしてください）");
				el.authInfo.textContent = "未認証";
				el.callBtn.disabled = true;
				return;
			}
			el.authInfo.textContent = "認証済み（共有: org-operator）";

			// Cognito Identity 資格情報を取得
			const creds = await getCognitoIdentityCredentials(idToken);

			// SigV4 署名URL作成
			const url = buildSignedUrlForIotMqtt(creds);

			// clientId は identityId ベースで一意化
			const identityId = AWS.config.credentials.identityId || "anon";
			const clientId = `${identityId}-${randomSuffix(6)}`;

			// 接続
			connectMqtt(url, clientId);
			el.callBtn.disabled = false;

		} catch (e) {
			console.error(e);
			setStatus("初期化失敗（認証または接続）", "warn");
			el.authInfo.textContent = "エラー";
			el.callBtn.disabled = true;
		}
	})();

})();
