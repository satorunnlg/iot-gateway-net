// ===== ログ補助 =====
const logEl = () => document.getElementById('log');
function log(...args) { logEl().textContent += args.map(String).join(' ') + "\n"; }
function setResult(ok, msg) {
	const el = document.getElementById('result');
	el.innerHTML = `<span class="${ok ? 'ok' : 'ng'}">${ok ? '✅' : '❌'} ${msg}</span>`;
}

// ===== UTF-8 / HEX =====
const enc = new TextEncoder();
function toHex(buf) {
	const u8 = new Uint8Array(buf);
	return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== WebCrypto: SHA256 / HMAC-SHA256 =====
async function sha256Hex(str) {
	const h = await crypto.subtle.digest('SHA-256', enc.encode(str));
	return toHex(h);
}
async function hmacSha256Raw(keyRaw, dataStr) {
	const keyData = (typeof keyRaw === 'string') ? enc.encode(keyRaw) : keyRaw;
	const cryptoKey = await crypto.subtle.importKey(
		'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
	);
	return await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(dataStr));
}
async function hmacSha256Hex(keyRaw, dataStr) {
	return toHex(await hmacSha256Raw(keyRaw, dataStr));
}

// ===== RFC3986 準拠エンコード =====
function rfc3986Encode(str) {
	return encodeURIComponent(str).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

// ===== Cognito Identity（未認証）=====
async function cognitoGetId(region, identityPoolId) {
	const url = `https://cognito-identity.${region}.amazonaws.com/`;
	const body = { IdentityPoolId: identityPoolId };
	const res = await fetch(url, {
		method: 'POST',
		headers: {
			'X-Amz-Target': 'AWSCognitoIdentityService.GetId',
			'Content-Type': 'application/x-amz-json-1.1'
		},
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`GetId failed: HTTP ${res.status}`);
	const json = await res.json();
	return json.IdentityId;
}

async function cognitoGetCredentials(region, identityId) {
	const url = `https://cognito-identity.${region}.amazonaws.com/`;
	const body = { IdentityId: identityId };
	const res = await fetch(url, {
		method: 'POST',
		headers: {
			'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
			'Content-Type': 'application/x-amz-json-1.1'
		},
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`GetCredentialsForIdentity failed: HTTP ${res.status}`);
	const json = await res.json();
	const c = json.Credentials;
	if (!c) throw new Error('No Credentials in response');
	return {
		accessKeyId: c.AccessKeyId,
		secretAccessKey: c.SecretKey,
		sessionToken: c.SessionToken,
		expiration: c.Expiration
	};
}

// ===== SigV4 署名付き WebSocket URL (/mqtt) =====
async function buildSignedMqttWssUrl({ accessKeyId, secretAccessKey, sessionToken }, host, region) {
	const service = 'iotdevicegateway';
	const method = 'GET';
	const canonicalUri = '/mqtt';
	const now = new Date();
	const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD
	const amzdate = dateStamp + 'T' + now.toISOString().slice(11, 19).replace(/:/g, '') + 'Z';

	const q = {
		'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
		'X-Amz-Credential': `${accessKeyId}/${dateStamp}/${region}/${service}/aws4_request`,
		'X-Amz-Date': amzdate,
		'X-Amz-Expires': '300',
		'X-Amz-SignedHeaders': 'host'
	};
	if (sessionToken) q['X-Amz-Security-Token'] = sessionToken;

	const canonicalQuery = Object.keys(q).sort().map(k =>
		`${rfc3986Encode(k)}=${rfc3986Encode(q[k])}`
	).join('&');

	const canonicalHeaders = `host:${host}\n`;
	const payloadHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // SHA256("")
	const canonicalRequest = [
		method, canonicalUri, canonicalQuery, canonicalHeaders, 'host', payloadHash
	].join('\n');

	const scope = `${dateStamp}/${region}/${service}/aws4_request`;
	const stringToSign = [
		'AWS4-HMAC-SHA256', amzdate, scope, await sha256Hex(canonicalRequest)
	].join('\n');

	const kDate = await hmacSha256Raw('AWS4' + secretAccessKey, dateStamp);
	const kRegion = await hmacSha256Raw(kDate, region);
	const kService = await hmacSha256Raw(kRegion, service);
	const kSigning = await hmacSha256Raw(kService, 'aws4_request');
	const signature = await hmacSha256Hex(kSigning, stringToSign);

	const finalQuery = `${canonicalQuery}&X-Amz-Signature=${signature}`;
	return `wss://${host}${canonicalUri}?${finalQuery}`;
}

// ===== WebSocket（ハンドシェイクのみ）=====
function openWebSocket(url) {
	return new Promise((resolve, reject) => {
		let ws;
		try { ws = new WebSocket(url, ['mqtt']); } catch (e) { reject(e); return; }

		const t = setTimeout(() => {
			try { ws.close(); } catch { }
			reject(new Error('WebSocket timeout'));
		}, 15000);

		ws.onopen = () => {
			clearTimeout(t);
			log('[WS] OPEN (handshake success) — すぐ閉じます');
			try { ws.close(1000, 'test-done'); } catch { }
			resolve();
		};
		ws.onerror = () => { clearTimeout(t); reject(new Error('WebSocket onerror')); };
		ws.onclose = e => log('[WS] CLOSE code=', e.code, 'reason=', e.reason || '(none)');
	});
}

// ===== メイン =====
document.getElementById('btn').addEventListener('click', async () => {
	logEl().textContent = '';
	setResult(false, '実行中…');

	const region = document.getElementById('region').value.trim();
	const identityIdIn = document.getElementById('identityId').value.trim();
	const identityPoolId = document.getElementById('identityPoolId').value.trim();
	const iotHost = document.getElementById('iotHost').value.trim();

	try {
		log('[info] region =', region);
		log('[info] identityId(input) =', identityIdIn || '(none)');
		log('[info] identityPoolId =', identityPoolId || '(unused)');
		log('[info] iotHost =', iotHost);
		log('[clock] browser now (ISO)=', new Date().toISOString());

		// 1) IdentityId を決める
		let identityId = identityIdIn;
		if (!identityId) {
			if (!identityPoolId) throw new Error('IdentityId か Identity Pool ID を入力してください');
			identityId = await cognitoGetId(region, identityPoolId);
			log('[cognito] GetId -> IdentityId =', identityId);
		} else {
			log('[cognito] IdentityId を入力で利用します');
		}

		// 2) 一時クレデンシャル
		const creds = await cognitoGetCredentials(region, identityId);
		log('[cognito] got STS creds: accessKeyId=', creds.accessKeyId, ' exp=', creds.expiration);

		// 3) 署名URL
		const url = await buildSignedMqttWssUrl(creds, iotHost, region);
		const hasToken = url.includes('X-Amz-Security-Token=');
		const amzDateMatch = /X-Amz-Date=([^&]+)/.exec(url);
		log('[sigv4] url built. X-Amz-Date=', amzDateMatch ? amzDateMatch[1] : '(n/a)', ' has STS token=', hasToken);

		// 4) WebSocket ハンドシェイク
		await openWebSocket(url);

		setResult(true, 'WebSocket ハンドシェイク成功（署名/権限/時刻はOK）');
	} catch (e) {
		log('[error]', e && e.stack ? e.stack : String(e));
		setResult(false, '失敗: ' + e.message);
	}
});
