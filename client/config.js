/* 公開識別子のみ（秘匿情報は置かない） */
window.IOTGW_CONFIG = {
	region: "ap-northeast-1", // 東京
	userPoolId: "ap-northeast-1_XXXXXXXXX",            // TODO: User Pool ID
	userPoolClientId: "XXXXXXXXXXXXXXXXXXXXXXXXXX",    // TODO: App client (public client)
	userPoolDomain: "your-domain.auth.ap-northeast-1.amazoncognito.com", // TODO
	identityPoolId: "ap-northeast-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", // TODO
	redirectUri: "https://your.cloudfront.domain/index.html", // TODO: Hosted UI リダイレクト先（ホワイトリストに登録）
	iotEndpoint: "xxxxxxxxxxxxxx-ats.iot.ap-northeast-1.amazonaws.com",   // TODO
	thingName: "AMR-001",
	shadowName: "robot",
	// UI
	destinations: ["A-01", "B-02", "C-03"],

	// Hosted UI（implicit flow）パラメータ
	oauth: {
		responseType: "token", // implicit
		scope: "openid",
	}
};
