#![cfg_attr(not(test), no_std)]

extern crate alloc;

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
