/* 公開識別子のみ（秘匿情報は置かない） */
window.IOTGW_CONFIG = {
	region: "ap-northeast-1", // 東京
	// ユーザープール（パスキー / USER_AUTH を有効化済み想定）
	userPoolId: "ap-northeast-1_2jfmfM2GA",                 // 必須: ユーザープールID
	userPoolClientId: "l8r960o0rgade8fbdppdghr04",         // 必須: アプリクライアントID（クライアントシークレットなし推奨）
	// IDプール（未認証は無効 / 認証ユーザーのみ）
	identityPoolId: "ap-northeast-1:4b39a8fb-49d2-429f-9523-a5c7534d9ab0", // 必須
	// IoT
	iotEndpoint: "a2osrgpri6xnln-ats.iot.ap-northeast-1.amazonaws.com",    // 必須
	thingName: "AMR-001",
	shadowName: "robot",
	// UI
	destinations: ["A-01", "B-02", "C-03"]
};
