#[derive(Debug)]
pub enum Error {
    /// Nostr関連のエラー
    Nostr(nostr::error::Error),
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
