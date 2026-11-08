#[derive(Debug)]
pub enum Error {
    /// Nostr関連のエラー
    Nostr(nostr::error::Error),
    /// serde_json関連のエラー
    Json(serde_json::error::Error),
    /// NIP-44のペイロードが大きすぎる
    PayloadTooLarge,
    /// 自分宛ではないイベント
    NotForUs,
    /// 不正なパラメータ―
    InvalidParams,
    /// 未認可の要求
    Unauthorized,
    /// 未対応のメソッド
    UnsupportedMethod,
}

impl From<nostr::error::Error> for Error {
    fn from(value: nostr::error::Error) -> Self {
        Self::Nostr(value)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(value: serde_json::error::Error) -> Self {
        Self::Json(value)
    }
}

impl Error {
    /// クライアントに通知するメッセージ
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid params",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedMethod => "unsupported method",
            Self::PayloadTooLarge => "payload too large",
            _ => "internal error",
        }
    }
}
