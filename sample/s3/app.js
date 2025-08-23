/**
 * 役割: AMR 操作用の MQTT クライアントと UI 制御（未認証ならサインイン画面へ遷移）
 * 参照: README の「IoT 接続」「ID プール」章、手順書の WebSocket/SigV4 とポリシー設定の節を参照。
 * 注意: 外部 CDN は使用しない（/vendor 配下を参照）。config.js の公開識別子を利用。
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
	if (!idToken) { location.replace("./index.html"); return; }
	el.authInfo.textContent = "認証状態: 認証済み";

	// ===== サインアウトは常時有効（接続前でも可） =====
	let currentClient = null; // 接続後に代入
	el.logoutBtn.onclick = () => {
		try { if (currentClient && currentClient.isConnected()) currentClient.disconnect(); } catch { }
		sessionStorage.clear();
		location.replace("./index.html");
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

	// ===== SigV4 署名ユーティリティ（AWS SDK v2 ユーティリティを使用） =====
	function hmac(key, s, hex) { const res = AWS.util.crypto.hmac(key, s, "buffer"); return hex ? AWS.util.crypto.toHex(res) : res; }
	function sha256(d, hex) { const res = AWS.util.crypto.sha256(d, "buffer"); return hex ? AWS.util.crypto.toHex(res) : res; }
	function amzDate(d) { const p = n => n < 10 ? "0" + n : "" + n; return d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + "T" + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + "Z"; }
	function dateStamp(z) { return z.slice(0, 8); }
	function buildSignedUrl(creds) {
		const host = cfg.iotEndpoint, service = "iotdevicegateway", region = cfg.region, method = "GET", uri = "/mqtt";
		const amz = amzDate(new Date()), date = dateStamp(amz), scope = `${date}/${region}/${service}/aws4_request`;
		const params = { "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": encodeURIComponent(`${creds.accessKeyId}/${scope}`), "X-Amz-Date": amz, "X-Amz-SignedHeaders": "host" };
		if (creds.sessionToken) params["X-Amz-Security-Token"] = encodeURIComponent(creds.sessionToken);
		const q = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join("&");
		const canonicalReq = [method, uri, q, `host:${host}\n`, "host", sha256("", true)].join("\n");
		const stringToSign = ["AWS4-HMAC-SHA256", amz, scope, sha256(canonicalReq, true)].join("\n");
		const kDate = hmac("AWS4" + creds.secretAccessKey, date), kRegion = hmac(kDate, region), kService = hmac(kRegion, service), kSigning = hmac(kService, "aws4_request", true);
		const sig = hmac(kSigning, stringToSign, true);
		return `wss://${host}${uri}?${q}&X-Amz-Signature=${sig}`;
	}

	function connect(creds) {
		const url = buildSignedUrl(creds);
		const id = AWS.config.credentials.identityId || "anon";
		const clientId = `${id}-${Math.random().toString(36).slice(-6)}`;
		const u = new URL(url), host = u.host, path = u.pathname + u.search;
		const client = new Paho.MQTT.Client(host, 443, path, clientId);
		currentClient = client; // ← サインアウトで参照

		let lastHB = 0, state = "—";
		function update(payload) {
			if (!payload) return;
			state = payload.state || state; lastHB = payload.heartbeatAt || payload.updatedAt || Date.now();
			el.hbInfo.textContent = `HB: ${new Date(lastHB).toLocaleString()}`;
			if (state === "moving") { setStatus("移動中", "ok"); setBtnMoving(true); }
			else if (state === "idle") { setStatus("待機中", "ok"); setBtnMoving(false); }
			else if (state === "offline") { setStatus("オフライン", "warn"); setBtnMoving(true); }
			else setStatus(state);
		}
		// 欠落検知→Shadow GET
		setInterval(() => { if (!lastHB) return; if (Date.now() - lastHB > 25000) { setStatus("通信不良（再同期中）", "warn"); if (client.isConnected()) { client.send(`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`, "{}", 1, false); } } }, 1000);

		client.onConnectionLost = () => { setStatus("切断（再接続待ち）", "warn"); setBtnMoving(true); setTimeout(() => { try { client.connect(opts); } catch { } }, 1500); };
		client.onMessageArrived = (m) => {
			try {
				const t = m.destinationName, js = m.payloadString && JSON.parse(m.payloadString);
				if (t.endsWith("/status")) update(js);
				else if (t.endsWith("/get/accepted")) { const r = js?.state?.reported; if (r) update({ state: r.state, updatedAt: r.updatedAt, heartbeatAt: r.heartbeatAt }); }
				else if (t.endsWith("/update/documents")) { const r = js?.current?.state?.reported; if (r) update({ state: r.state, updatedAt: r.updatedAt, heartbeatAt: r.heartbeatAt }); }
			} catch (e) { console.error(e); }
		};

		const opts = {
			useSSL: true, timeout: 10, mqttVersion: 4, cleanSession: true, onSuccess: () => {
				setStatus("接続済み", "ok"); setBtnMoving(false);
				client.subscribe(`amr/${cfg.thingName}/status`, { qos: 1 });
				client.subscribe(`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/update/documents`, { qos: 1 });
				client.subscribe(`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get/accepted`, { qos: 1 });
				client.send(`$aws/things/${cfg.thingName}/shadow/name/${cfg.shadowName}/get`, "{}", 1, false);
			}, onFailure: (e) => { console.error("mqtt connect failed", e); setStatus("接続失敗（再試行可）", "warn"); }
		};
		client.connect(opts);

		// 呼出し（Publish）
		el.callBtn.onclick = () => {
			if (!client.isConnected()) return;
			const dest = el.dest.value;
			const req = { requestId: [Date.now(), Math.random().toString(36).slice(-6)].join("-"), dest };
			const msg = new Paho.MQTT.Message(JSON.stringify(req)); msg.qos = 1; msg.destinationName = `amr/${cfg.thingName}/cmd/call`;
			client.send(msg); setBtnMoving(true);
		};
	}

	// 認証クレデンシャルを確定→接続
	setStatus("認証確認中…");
	AWS.config.credentials.clearCachedId();
	AWS.config.credentials.get((err) => {
		if (err) { console.error(err); setStatus("資格情報エラー", "warn"); return; }
		connect(AWS.config.credentials);
	});
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

// --- 追加: メニュー「デバイスを登録」→ パスキー登録フロー（最小追記） ---
// メニュー「パスキー登録/削除」トグル対応
// 参照: README の「認証 > Passkeys（ユーザープール）」、手順書の該当セクション
(function attachRegisterDeviceHandler() {
	const btn = document.getElementById('menuRegisterDevice');
	const menuEl = document.getElementById('appMenu');
	if (!btn) return;

	const cfg = window.IOTGW_CONFIG;
	const COG_URL = `https://cognito-idp.${cfg.region}.amazonaws.com/`;

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
		if (accessToken) headers["Authorization"] = accessToken; // AccessToken を Authorization に
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
		// 1) Start
		const start = await cognito("StartWebAuthnRegistration", { AccessToken: accessToken }, accessToken); // :contentReference[oaicite:1]{index=1}
		let opts = start.PublicKeyCredentialCreationOptions || start.CredentialCreationOptions || start.Options || start.CREDENTIAL_CREATION_OPTIONS;
		if (typeof opts === "string") try { opts = JSON.parse(opts); } catch { }
		if (!opts) throw new Error("登録オプションを取得できませんでした。");

		// 2) navigator.credentials.create のために各フィールドを整形
		opts.challenge = b64uToBuf(opts.challenge);
		if (opts.user && typeof opts.user.id === "string") opts.user.id = b64uToBuf(opts.user.id);
		if (Array.isArray(opts.excludeCredentials)) {
			opts.excludeCredentials = opts.excludeCredentials.map(c => ({ ...c, id: typeof c.id === "string" ? b64uToBuf(c.id) : c.id }));
		}
		const cred = await navigator.credentials.create({ publicKey: opts });
		if (!cred) throw new Error("パスキー作成がキャンセルされました。");

		// 3) Complete
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
		await cognito("CompleteWebAuthnRegistration", { AccessToken: accessToken, Credential: regJSON }, accessToken); // :contentReference[oaicite:2]{index=2}
	}
	async function listPasskeys(accessToken) {
		const r = await cognito("ListWebAuthnCredentials", { AccessToken: accessToken, MaxResults: 20 }, accessToken); // :contentReference[oaicite:3]{index=3}
		return Array.isArray(r.Credentials) ? r.Credentials : [];
	}
	async function deletePasskey(accessToken, credentialId) {
		await cognito("DeleteWebAuthnCredential", { AccessToken: accessToken, CredentialId: credentialId }, accessToken); // :contentReference[oaicite:4]{index=4}
	}

	// 同一RPの資格情報だけ対象（rpId は location.hostname のサブドメイン許容）
	const isSameRp = (rpId) => {
		const host = location.hostname;
		return host === rpId || host.endsWith("." + rpId) || rpId.endsWith("." + host);
	};

	// --- UI状態管理 ---
	let mode = "register";      // "register" | "delete"
	let currentRpCreds = [];    // このRPに紐づく既存パスキー（0個以上）

	async function refreshButton() {
		const accessToken = sessionStorage.getItem('access_token');
		if (!accessToken) { btn.textContent = "パスキーを登録"; btn.disabled = true; return; }
		const all = await listPasskeys(accessToken);
		currentRpCreds = all.filter(c => isSameRp(c.RelyingPartyId));
		if (currentRpCreds.length > 0) {
			mode = "delete";
			btn.textContent = "パスキーを削除";
		} else {
			mode = "register";
			btn.textContent = "パスキーを登録";
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
				await refreshButton();                   // → 「削除」に切替
			} else {
				btn.textContent = "削除中…";
				for (const cred of currentRpCreds) {     // 同一RPの登録を全削除
					await deletePasskey(accessToken, cred.CredentialId);
				}
				localStorage.removeItem("remember_username"); // 次回はPW画面に
				await refreshButton();                   // → 「登録」に切替
			}
			if (menuEl && menuEl.open) menuEl.open = false; // 操作後はメニューを閉じる
		} catch (err) {
			console.error("[passkey toggle] error:", err);
			alert("処理に失敗しました: " + (err?.message || err));
			btn.textContent = orig;
		} finally {
			btn.disabled = false;
		}
	});

	// 初期化：登録有無でラベル設定
	refreshButton().catch((e) => console.warn("ListWebAuthnCredentials 失敗:", e));
})();

