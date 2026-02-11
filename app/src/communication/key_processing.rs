use serde::{Deserialize, Serialize};

use crate::models::KeyId;

#[derive(Serialize, Deserialize)]
pub struct RegisterKey(pub KeyId, pub usize);

impl RegisterKey {
    pub fn key_id(&self) -> KeyId {
        self.0
    }

    pub fn len(&self) -> usize {
        self.1
    }
}

#[derive(Serialize, Deserialize)]
pub struct Abort(pub KeyId);

#[derive(Serialize, Deserialize)]
pub enum RegisterReply {
    KeyFound(KeyId),
    KeyNotFound(KeyId),
    LengthMismatch(KeyId),
}

impl RegisterReply {
    pub fn found(key_id: KeyId) -> Self {
        RegisterReply::KeyFound(key_id)
    }

    pub fn not_found(key_id: KeyId) -> Self {
        RegisterReply::KeyNotFound(key_id)
    }

    pub fn get_id(&self) -> &KeyId {
        match self {
            Self::KeyFound(id) => id,
            Self::KeyNotFound(id) => id,
            Self::LengthMismatch(id) => id,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StartReconciliation(pub KeyId);

#[derive(Serialize, Deserialize)]
pub enum StartReconReply {
    Start(KeyId),
    Abort(Abort),
}

#[derive(Serialize, Deserialize)]
pub struct RevealSymbols(Vec<Vec<usize>>);

#[derive(Serialize, Deserialize)]
pub enum RevealSymbolsReply {
    Ok(Vec<Vec<usize>>),
    Err,
}
