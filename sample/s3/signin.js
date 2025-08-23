/**
 * 役割: サインイン画面（初回=PW/必要なら変更, 2回目以降=パスキー）→ 成功後は直接 AMR 操作画面へ遷移
 * 参照: README の「認証 / Passkeys / ID プール / 画面遷移」章、手順書の Cognito 設定章
 * 注意: Public クライアント前提（SECRET_HASH は使わない）。外部 CDN は使わない（CSP 'self'）。
 */
(function () {
	"use strict";
	const cfg = window.IOTGW_CONFIG;

	// ---------- ユーティリティ ----------
	const $ = (id) => document.getElementById(id);
	const state = {
		panes: {
			passkey: $("passkeyPane"),
			password: $("passwordPane"),
			newpw: $("newPwPane"),
		},
		statusEl: $("status"),
		remembered: localStorage.getItem("remember_username") || "",
		accessToken: null,
	};
	function show(which) {
		Object.values(state.panes).forEach(el => el.classList.add("hidden"));
		state.panes[which].classList.remove("hidden");
	}
	function setStatus(msg, cls) {
		state.statusEl.textContent = msg || "—";
		state.statusEl.classList.remove("ok", "warn");
		if (cls) state.statusEl.classList.add(cls);
	}
	const b64uToBuf = (s) => { const pad = (x) => x + "===".slice((x.length + 3) % 4); const b64 = pad(s.replace(/-/g, "+").replace(/_/g, "/")); const bin = atob(b64); const u = new Uint8Array(bin.length); for (let i = 0; i < u.length; i++)u[i] = bin.charCodeAt(i); return u.buffer; };
	const bufToB64u = (buf) => { const u = new Uint8Array(buf); let s = ""; for (let i = 0; i < u.length; i++)s += String.fromCharCode(u[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); };
	const assert = (c, m) => { if (!c) throw new Error(m || "assert"); };

	// ---------- Cognito User Pools（REST JSON 1.0） ----------
	const COG_URL = `https://cognito-idp.${cfg.region}.amazonaws.com/`;
	async function cognito(action, body, accessToken) {
		const headers = { "Content-Type": "application/x-amz-json-1.0", "X-Amz-Target": `AWSCognitoIdentityProviderService.${action}` };
		if (accessToken) headers["Authorization"] = accessToken;
		const res = await fetch(COG_URL, { method: "POST", headers, body: JSON.stringify(body) });
		const js = await res.json().catch(() => ({}));
		if (!res.ok) {
			const msg = js.message || js.__type || res.statusText;
			throw Object.assign(new Error(msg), { details: js, status: res.status });
		}
		return js;
	}

	// ---------- ChallengeParameters から PublicKeyCredentialRequestOptions を抽出 ----------
	function extractRequestOptions(params) {
		// 1) ベンダ差異に強い順で拾う
		let opt =
			params.CREDENTIAL_REQUEST_OPTIONS ||
			params.PublicKeyCredentialRequestOptions ||
			params.publicKeyCredentialRequestOptions ||
			params.WEBAUTHN_PUBLIC_KEY_CREDENTIAL_REQUEST_OPTIONS ||
			params.options ||
			null;

		// 文字列なら JSON に
		if (typeof opt === "string") {
			try { opt = JSON.parse(opt); }
			catch { /* 後段のフォールバックへ */ }
		}

		// 2) まだ取れない場合は、旧フィールド名から組み立て
		if (!opt || typeof opt !== "object") {
			const fromFields = {
				challenge: params.challenge,
				rpId: params.rpId,
				allowCredentials: (() => {
					if (!params.allowCredentials) return undefined;
					try { return typeof params.allowCredentials === "string" ? JSON.parse(params.allowCredentials) : params.allowCredentials; }
					catch { return undefined; }
				})(),
				userVerification: params.userVerification,
				timeout: params.timeout ? Number(params.timeout) : undefined
			};
			if (fromFields.challenge && (fromFields.rpId || params.rpId)) {
				opt = fromFields;
			}
		}

		if (!opt || !opt.challenge) {
			console.debug("[extractRequestOptions] unexpected params =", params);
			return null;
		}
		return opt;
	}

	// ---------- サインイン（パスキー） ----------
	async function signInWithPasskey(username) {
		assert(username, "ユーザー名が未入力です。");
		// 1) USER_AUTH を開始
		let init = await cognito("InitiateAuth", {
			AuthFlow: "USER_AUTH",
			ClientId: cfg.userPoolClientId,
			AuthParameters: { USERNAME: username, PREFERRED_CHALLENGE: "WEB_AUTHN" }
		});

		// 1-α) もし即ログインなら終了
		if (init.AuthenticationResult?.IdToken) {
			return init.AuthenticationResult;
		}

		// 2) SELECT_CHALLENGE → WEB_AUTHN を選択してから、WebAuthn のオプションを受け取る
		let session = init.Session;
		let chalName = init.ChallengeName;
		let params = init.ChallengeParameters || {};

		if (chalName === "SELECT_CHALLENGE") {
			const chosen = await cognito("RespondToAuthChallenge", {
				ClientId: cfg.userPoolClientId,
				Session: session,
				ChallengeName: "SELECT_CHALLENGE",
				ChallengeResponses: { USERNAME: username, ANSWER: "WEB_AUTHN" }
			});
			if (chosen.AuthenticationResult?.IdToken) {
				return chosen.AuthenticationResult; // まれにここで完結
			}
			session = chosen.Session;
			chalName = chosen.ChallengeName;
			params = chosen.ChallengeParameters || {};
		}

		if (chalName !== "WEB_AUTHN") {
			console.debug("Unexpected challenge:", chalName, params);
			throw new Error("このユーザーにパスキー認証が有効化されていない可能性があります。");
		}

		// 3) ここで WebAuthn の RequestOptions を取得できるはず
		let pubKey = extractRequestOptions(params);
		if (!pubKey) throw new Error("WebAuthn オプションを取得できませんでした。");

		// RP ID の安全確認（トラブルシュート用）
		if (pubKey.rpId && pubKey.rpId !== location.hostname) {
			console.warn(`[WebAuthn] rpId mismatch: expected=${location.hostname}, got=${pubKey.rpId}`);
			// ※ Cognito の「パスキー → サードパーティドメイン」に現在の FQDN が入っているか確認してください
		}

		// 4) 変換（Base64URL → ArrayBuffer）
		pubKey.challenge = typeof pubKey.challenge === "string" ? b64uToBuf(pubKey.challenge) : pubKey.challenge;
		if (Array.isArray(pubKey.allowCredentials)) {
			pubKey.allowCredentials = pubKey.allowCredentials.map(c => {
				const id = typeof c.id === "string" ? b64uToBuf(c.id) : c.id;
				return { type: c.type || "public-key", id, transports: c.transports };
			});
		}
		if (pubKey.timeout) pubKey.timeout = Number(pubKey.timeout);

		// 5) ブラウザでパスキー認証
		const cred = await navigator.credentials.get({ publicKey: pubKey });
		const authnJSON = {
			id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
			response: {
				authenticatorData: bufToB64u(cred.response.authenticatorData),
				clientDataJSON: bufToB64u(cred.response.clientDataJSON),
				signature: bufToB64u(cred.response.signature),
				userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
			},
			clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
		};

		// 6) WEB_AUTHN チャレンジに回答して最終トークンを受領
		const resp = await cognito("RespondToAuthChallenge", {
			ClientId: cfg.userPoolClientId,
			Session: session,
			ChallengeName: "WEB_AUTHN",
			ChallengeResponses: { USERNAME: username, CREDENTIAL: JSON.stringify(authnJSON) }
		});
		assert(resp.AuthenticationResult?.IdToken, "サインインに失敗しました。");
		return resp.AuthenticationResult;
	}

	// ---------- サインイン（メール/パスワード） ----------
	async function signInWithPassword(username, password) {
		const init = await cognito("InitiateAuth", {
			AuthFlow: "USER_PASSWORD_AUTH", ClientId: cfg.userPoolClientId,
			AuthParameters: { USERNAME: username, PASSWORD: password }
		});
		if (init.AuthenticationResult) return { auth: init.AuthenticationResult };
		if (init.ChallengeName === "NEW_PASSWORD_REQUIRED") return { challenge: init };
		throw new Error("予期しないチャレンジです: " + init.ChallengeName);
	}
	async function respondNewPassword(challenge, newPassword, username) {
		const resp = await cognito("RespondToAuthChallenge", {
			ClientId: cfg.userPoolClientId,
			Session: challenge.Session,
			ChallengeName: "NEW_PASSWORD_REQUIRED",
			ChallengeResponses: { USERNAME: username, NEW_PASSWORD: newPassword }
		});
		if (!resp.AuthenticationResult) throw new Error("パスワード変更に失敗しました。");
		return resp.AuthenticationResult;
	}

	// ---------- トークン保存／遷移 ----------
	function saveTokens(auth) {
		sessionStorage.setItem("id_token", auth.IdToken);
		sessionStorage.setItem("access_token", auth.AccessToken);
		if (auth.RefreshToken) sessionStorage.setItem("refresh_token", auth.RefreshToken);
		sessionStorage.setItem("expires_in", String(auth.ExpiresIn || 3600));
		state.accessToken = auth.AccessToken;
	}
	function gotoApp() { location.href = "./amr-control.html"; }

	// ---------- 画面初期化（2回目以降は自動パスキー → 成功なら直遷移） ----------
	if (state.remembered) {
		$("rememberedUser").value = state.remembered;
		show("passkey");
		// --- 追加: 自動的にパスキー起動 ---
		(async () => {
			try {
				setStatus("パスキー自動サインイン中…");
				const auth = await signInWithPasskey(state.remembered.trim());
				saveTokens(auth);
				// ここを直接遷移に変更（register 画面は経由しない）
				gotoApp();
			} catch (e) {
				console.error(e);
				setStatus("自動パスキーサインインに失敗しました。手動でお試しください。", "warn");
			}
		})();
	} else {
		show("password");
	}
	$("switchToPw").onclick = () => show("password");

	// パスキーサインイン（手動）— 成功時は直遷移
	$("btnPasskey").onclick = async () => {
		try {
			$("btnPasskey").disabled = true;
			setStatus("パスキーでサインイン中…");
			const auth = await signInWithPasskey($("rememberedUser").value.trim());
			saveTokens(auth);
			gotoApp(); // 直遷移
		} catch (e) { console.error(e); setStatus("サインインに失敗しました", "warn"); }
		finally { $("btnPasskey").disabled = false; }
	};

	// パスワードサインイン — 成功時は直遷移、NPR は更新後に直遷移
	$("btnPassword").onclick = async () => {
		const u = ($("inUser").value || "").trim(); const p = $("inPw").value || "";
		if (!u || !p) { setStatus("メールとパスワードを入力してください。", "warn"); return; }
		try {
			$("btnPassword").disabled = true;
			setStatus("サインイン中…");
			const r = await signInWithPassword(u, p);
			if (r.auth) {
				saveTokens(r.auth); localStorage.setItem("remember_username", u);
				gotoApp(); // 直遷移
			} else if (r.challenge) {
				show("newpw"); setStatus("新しいパスワードを設定してください。", "warn");
				$("btnNewPw").onclick = async () => {
					try {
						const newPw = $("inNewPw").value || ""; if (!newPw) { setStatus("新しいパスワードを入力してください。", "warn"); return; }
						const auth = await respondNewPassword(r.challenge, newPw, u);
						saveTokens(auth); localStorage.setItem("remember_username", u);
						gotoApp(); // 直遷移
					} catch (e) { console.error(e); setStatus("パスワード更新に失敗しました", "warn"); }
				};
			}
		} catch (e) { console.error(e); setStatus("サインインに失敗しました", "warn"); }
		finally { $("btnPassword").disabled = false; }
	};

	// 操作画面へ（UI 残置）
	$("btnGotoApp").onclick = gotoApp;
})();
