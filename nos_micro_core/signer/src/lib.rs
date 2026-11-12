#![cfg_attr(not(test), no_std)]

use nostr::key::SecretKey;

extern crate alloc;

pub mod bunker;
pub mod error;
pub mod nip46;
pub mod signer;

pub trait RngGenerator {
    /// 乱数で配列を埋める
    /// 真乱数を用いること
    fn fill(&mut self, dest: &mut [u8]);

    fn byte32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.fill(&mut bytes);
        bytes
    }
}

/// 乱数から秘密鍵を作る（範囲外の値ならやり直す）
pub fn generate_secret_key<R: RngGenerator>(rng: &mut R) -> SecretKey {
    loop {
        if let Ok(sk) = SecretKey::from_slice(&rng.byte32()) {
            return sk;
        }
    }
}
