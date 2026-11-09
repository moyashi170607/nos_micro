use alloc::string::String;
use alloc::vec::Vec;

use nostr::event::{Kind, Tag, Tags, UnsignedEvent};
use nostr::key::PublicKey;
use nostr::types::Timestamp;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// リクエストそのまま
#[derive(Deserialize)]
pub struct RawRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Vec<String>,
}

/// パースした後のリクエスト
pub enum Request {
    Connect {
        signer_pubkey: PublicKey,
        secret: Option<String>,
        permision: Vec<Permission>,
        // 第4引数のmetadataは表示先がないため読まない
    },
    SignEvent(UnsignedEvent),
    Ping,
    GetPublicKey,
    Nip44Encrypt {
        peer: PublicKey,
        text: String,
    },
    Nip44Decrypt {
        peer: PublicKey,
        payload: String,
    },
    SwitchRelays,
    Logout,
}

/// クライアントが要求する権限
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// `None` は全kindへの署名
    SignEvent(Option<u16>),
    Nip44Encrypt,
    Nip44Decrypt,
}

impl Permission {
    /// `method[:params]` をパースする
    /// 未対応のメソッドや不正な値は `None`
    fn parse(s: &str) -> Option<Self> {
        match s {
            "sign_event" => Some(Self::SignEvent(None)),
            "nip44_encrypt" => Some(Self::Nip44Encrypt),
            "nip44_decrypt" => Some(Self::Nip44Decrypt),
            _ => {
                let kind = s.strip_prefix("sign_event:")?.parse::<u16>().ok()?;
                Some(Self::SignEvent(Some(kind)))
            }
        }
    }
}

/// 返答
#[derive(Serialize)]
pub struct Response<'a> {
    pub id: &'a str,
    pub result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
}

/// Nostrの署名前Event
#[derive(Deserialize)]
struct EventTemplate {
    kind: u16,
    content: String,
    #[serde(default)]
    tags: Vec<Vec<String>>,
    /// 署名時に代入される
    created_at: Option<u64>,
}

/// paramから値を取り出す
fn param(p: &[String], i: usize) -> Result<&String, Error> {
    p.get(i).ok_or(Error::InvalidParams)
}

/// paramからpubkeyを取り出し、hex形式に
fn pubkey_param(p: &[String], i: usize) -> Result<PublicKey, Error> {
    PublicKey::from_hex(param(p, i)?).map_err(|_| Error::InvalidParams)
}

/// paramから要求された権限を取り出す
fn permission_param(p: &[String], i: usize) -> Vec<Permission> {
    let Some(perms) = p.get(i) else {
        return Vec::new();
    };

    perms.split(',').filter_map(Permission::parse).collect()
}

impl Request {
    pub fn parse(raw: &RawRequest, user_pubkey: PublicKey, now: Timestamp) -> Result<Self, Error> {
        let p = &raw.params[..];

        match raw.method.as_str() {
            "connect" => Ok(Self::Connect {
                signer_pubkey: pubkey_param(p, 0)?,
                secret: p.get(1).filter(|s| !s.is_empty()).cloned(),
                permision: permission_param(p, 2),
                // 第4引数のmetadataは表示先がないため読まない
            }),
            "sign_event" => {
                let template: EventTemplate =
                    serde_json::from_str(param(p, 0)?).map_err(|_| Error::InvalidParams)?;

                let tags = Tags::parse(template.tags).map_err(|_| Error::InvalidParams)?;

                Ok(Self::SignEvent(UnsignedEvent::new(
                    user_pubkey,
                    template.created_at.map_or(now, Timestamp::from_secs),
                    Kind::from(template.kind),
                    tags.to_vec(),
                    template.content,
                )))
            }
            "ping" => Ok(Self::Ping),
            "get_public_key" => Ok(Self::GetPublicKey),
            "nip44_encrypt" => Ok(Self::Nip44Encrypt {
                peer: pubkey_param(p, 0)?,
                text: param(p, 1)?.clone(),
            }),
            "nip44_decrypt" => Ok(Self::Nip44Decrypt {
                peer: pubkey_param(p, 0)?,
                payload: param(p, 1)?.clone(),
            }),
            "switch_relays" => Ok(Self::SwitchRelays),
            "logout" => Ok(Self::Logout),
            "nip04_encrypt" | "nip04_decrypt" => Err(Error::Nip04Unsupported),
            _ => Err(Error::UnsupportedMethod),
        }
    }
}
