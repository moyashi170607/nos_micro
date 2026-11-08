use nostr::{
    event::{Event, UnsignedEvent},
    key::{Keys, PublicKey, SecretKey},
    nips::nip44::{self, Nonce},
};
use secp256k1::{All, Secp256k1};

use crate::error::Error;
use alloc::string::String;

const MAX_NIP44_PAYLOAD_LEN: usize = 64 * 1024;

/// 署名器
pub struct Signer {
    secp: Secp256k1<All>,
    keys: Keys,
}

impl Signer {
    pub fn new(secret_key: SecretKey, seed: &[u8; 32]) -> Self {
        let mut secp = Secp256k1::new();
        secp.seeded_randomize(seed);

        let keys = Keys::new_with_ctx(&secp, secret_key);

        Self { secp, keys }
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn sign(&self, unsigned: UnsignedEvent, aux: &[u8; 32]) -> Result<Event, Error> {
        if unsigned.pubkey != self.pubkey() {
            return Err(Error::InvalidParams);
        }

        let id = unsigned.id.unwrap_or_else(|| unsigned.compute_id());
        let sig = self
            .keys
            .sign_schnorr_with_aux_rand(&self.secp, id.as_bytes(), aux);

        // 署名の検証も行われる
        Ok(unsigned.add_signature_with_ctx(&self.secp, sig)?)
    }

    pub fn verify(&self, event: &Event) -> Result<(), Error> {
        Ok(event.verify_with_ctx(&self.secp)?)
    }

    pub fn nip44_decrypt(&self, peer: &PublicKey, payload: &str) -> Result<String, Error> {
        if payload.len() > MAX_NIP44_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }

        Ok(nip44::decrypt(self.keys.secret_key(), peer, payload)?)
    }

    /// `nonce` は毎回TRNGから取得する。再利用してはいけない。
    pub fn nip44_encrypt(
        &self,
        peer: &PublicKey,
        text: &str,
        nonce: [u8; 32],
    ) -> Result<String, Error> {
        Ok(nip44::encrypt_with_nonce(
            self.keys.secret_key(),
            peer,
            text,
            Nonce::V2(nonce),
        )?)
    }
}
