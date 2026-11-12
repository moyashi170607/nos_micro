use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use nostr::event::{Event, Kind};
use nostr::key::PublicKey;
use nostr::nips::nip44::v2::ConversationKey;
use nostr::types::Timestamp;

use crate::RngGenerator;
use crate::error::Error;
use crate::nip46::{Permission, RawRequest, Request, Response};
use crate::signer::Signer;

/// 接続済みのクライアント
#[derive(Clone)]
pub struct Session {
    pub client: PublicKey,
    pub permissions: Vec<Permission>,
    conv_key: ConversationKey, // connect 時に1回だけ導出する
}

pub struct Bunker {
    signer: Signer,
    secret: Option<String>,
    session: Vec<Session>,
    relay: Vec<String>,
}

impl Bunker {
    pub fn handle<R: RngGenerator>(
        &mut self,
        event: &Event,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Event, Error> {
        let transport_pubkey = self.signer.transport_pubkey();
        let user_pubkey = self.signer.user_pubkey();

        if event.kind != Kind::NostrConnect
            || !event.tags.public_keys().any(|p| p == transport_pubkey)
        {
            return Err(Error::NotForUs);
        }

        self.signer.verify(event)?;

        let client = event.pubkey;

        // セッションがあれば保存済みの鍵を使う
        let conv_key = match self.session.iter().find(|s| s.client == client) {
            Some(s) => s.conv_key,
            None => self.signer.conversation_key(&client)?,
        };

        let plain = self.signer.transport_decrypt(&conv_key, &event.content)?;
        let raw: RawRequest = serde_json::from_str(&plain)?;

        let outcome = Request::parse(&raw, user_pubkey, now)
            .and_then(|req| self.dispatch(client, conv_key, req, rng));

        let (result, error) = match &outcome {
            Ok(s) => (s.as_str(), None),
            Err(e) => ("", Some(e.message())),
        };

        let json = serde_json::to_string(&Response {
            id: &raw.id,
            result,
            error,
        })?;

        let content = self
            .signer
            .transport_encrypt(&conv_key, &json, rng.byte32())?;

        self.signer
            .sign_response(&client, content, now, &rng.byte32())
    }

    fn dispatch<R: RngGenerator>(
        &mut self,
        client: PublicKey,
        conv_key: ConversationKey,
        req: Request,
        rng: &mut R,
    ) -> Result<String, Error> {
        if !matches!(req, Request::Connect { .. }) {
            let session = self
                .session
                .iter()
                .find(|s| s.client == client)
                .ok_or(Error::Unauthorized)?;

            if !req.is_permitted(&session.permissions) {
                return Err(Error::Unauthorized);
            }
        }

        match req {
            Request::Connect {
                signer_pubkey,
                secret,
                permissions,
            } => self.connect(client, conv_key, signer_pubkey, secret, permissions),
            Request::SignEvent(unsigned) => {
                let event = self.signer.sign(unsigned, &rng.byte32())?;
                Ok(event.try_as_json()?)
            }
            Request::Ping => Ok("pong".into()),
            Request::GetPublicKey => Ok(self.signer.user_pubkey().to_hex()),
            Request::Nip44Encrypt { peer, text } => {
                self.signer.nip44_encrypt(&peer, &text, rng.byte32())
            }
            Request::Nip44Decrypt { peer, payload } => self.signer.nip44_decrypt(&peer, &payload),
            Request::SwitchRelays => Ok(serde_json::to_string(&self.relay)?),
            Request::Logout => {
                self.session.retain(|s| s.client != client);
                Ok("ack".into())
            }
        }
    }

    fn connect(
        &mut self,
        client: PublicKey,
        conv_key: ConversationKey,
        signer_pubkey: PublicKey,
        secret: Option<String>,
        permissions: Vec<Permission>,
    ) -> Result<String, Error> {
        if signer_pubkey != self.signer.transport_pubkey() {
            return Err(Error::InvalidParams);
        }

        if self.session.iter().any(|s| s.client == client) {
            return Ok("ack".into());
        }

        match (&self.secret, &secret) {
            (Some(expec), Some(given)) if expec == given => {}
            _ => return Err(Error::Unauthorized),
        }

        // 使い捨てにする
        self.secret = None;

        // 権限の指定がなければ、secret を知っていることをユーザーの承認とみなして全部許可する
        let permissions = permissions.unwrap_or_else(|| {
            vec![
                Permission::SignEvent(None),
                Permission::Nip44Encrypt,
                Permission::Nip44Decrypt,
            ]
        });

        self.session.push(Session {
            client,
            permissions,
            conv_key,
        });

        Ok("ack".into())
    }
}
