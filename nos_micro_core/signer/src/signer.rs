use alloc::string::String;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nostr::{
    event::{Event, Kind, Tag, UnsignedEvent},
    key::{Keys, PublicKey, SecretKey},
    nips::nip44::{
        self, Nonce,
        v2::{self, ConversationKey},
    },
    types::Timestamp,
};
use secp256k1::{All, Secp256k1};

use crate::error::Error;

const MAX_NIP44_PAYLOAD_LEN: usize = 64 * 1024;

/// 署名器
pub struct Signer {
    secp: Secp256k1<All>,
    /// ユーザーの鍵
    /// イベントの署名とユーザーとしてのNIP-44に使う
    user_keys: Keys,
    /// 通信用の鍵
    /// NIP-46の通信にのみ使う
    transport_keys: Keys,
}

impl Signer {
    pub fn new(user_secret: SecretKey, transport_secret: SecretKey, seed: &[u8; 32]) -> Self {
        let mut secp = Secp256k1::new();
        secp.seeded_randomize(seed);

        let user_keys = Keys::new_with_ctx(&secp, user_secret);

        let transport_keys = Keys::new_with_ctx(&secp, transport_secret);

        Self {
            secp,
            user_keys,
            transport_keys,
        }
    }

    pub fn user_pubkey(&self) -> PublicKey {
        self.user_keys.public_key()
    }

    pub fn transport_pubkey(&self) -> PublicKey {
        self.transport_keys.public_key()
    }

    pub fn verify(&self, event: &Event) -> Result<(), Error> {
        Ok(event.verify_with_ctx(&self.secp)?)
    }

    fn sign_with(
        &self,
        keys: &Keys,
        unsigned: UnsignedEvent,
        aux: &[u8; 32],
    ) -> Result<Event, Error> {
        if unsigned.pubkey != keys.public_key() {
            return Err(Error::InvalidParams);
        }

        let id = unsigned.id.unwrap_or_else(|| unsigned.compute_id());
        let sig = keys.sign_schnorr_with_aux_rand(&self.secp, id.as_bytes(), aux);

        // 署名の検証
        Ok(unsigned.add_signature_with_ctx(&self.secp, sig)?)
    }

    // ---- ユーザーの鍵 ----

    /// クライアントから頼まれたイベントにユーザーの鍵で署名する
    pub fn sign(&self, unsigned: UnsignedEvent, aux: &[u8; 32]) -> Result<Event, Error> {
        self.sign_with(&self.user_keys, unsigned, aux)
    }

    pub fn nip44_decrypt(&self, peer: &PublicKey, payload: &str) -> Result<String, Error> {
        if payload.len() > MAX_NIP44_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }

        Ok(nip44::decrypt(self.user_keys.secret_key(), peer, payload)?)
    }

    /// `nonce` は毎回TRNGから取得する。再利用してはいけない。
    pub fn nip44_encrypt(
        &self,
        peer: &PublicKey,
        text: &str,
        nonce: [u8; 32],
    ) -> Result<String, Error> {
        Ok(nip44::encrypt_with_nonce(
            self.user_keys.secret_key(),
            peer,
            text,
            Nonce::V2(nonce),
        )?)
    }

    // ---- 通信用の鍵 ----

    /// クライアントとの通信に使う鍵を導出する（重いので Session に保存して使い回す）
    pub fn conversation_key(&self, client: &PublicKey) -> Result<ConversationKey, Error> {
        Ok(ConversationKey::derive(
            self.transport_keys.secret_key(),
            client,
        )?)
    }

    pub fn transport_decrypt(
        &self,
        conv_key: &ConversationKey,
        payload: &str,
    ) -> Result<String, Error> {
        if payload.len() > MAX_NIP44_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }

        let bytes = STANDARD.decode(payload).map_err(|_| Error::InvalidParams)?;
        let plain = v2::decrypt_to_bytes(conv_key, &bytes)?;
        String::from_utf8(plain).map_err(|_| Error::InvalidParams)
    }

    /// `nonce` は毎回TRNGから取得する。再利用してはいけない。
    pub fn transport_encrypt(
        &self,
        conv_key: &ConversationKey,
        text: &str,
        nonce: [u8; 32],
    ) -> Result<String, Error> {
        let bytes = v2::encrypt_to_bytes_with_nonce(conv_key, text.as_bytes(), nonce)?;
        Ok(STANDARD.encode(bytes))
    }

    /// NIP-46 の返信イベントを作って署名する
    /// 通信用の鍵は kind:24133 の返信にしか署名しない
    pub fn sign_response(
        &self,
        client: &PublicKey,
        content: String,
        now: Timestamp,
        aux: &[u8; 32],
    ) -> Result<Event, Error> {
        let unsigned = UnsignedEvent::new(
            self.transport_pubkey(),
            now,
            Kind::NostrConnect,
            [Tag::public_key(*client)],
            content,
        );
        self.sign_with(&self.transport_keys, unsigned, aux)
    }
}
