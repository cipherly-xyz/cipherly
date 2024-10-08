use base64::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccount {
    pub username: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecret {
    pub ciphertext: String,
    pub encapsulated_sym_key: String,
    pub expiration: Option<u32>,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretCreated {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSecret {
    pub id: i64,
    pub ciphertext: String,
    pub encapsulated_sym_key: String,
    pub nonce: String,
}

pub fn decode_base64(payload: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::prelude::BASE64_STANDARD.decode(payload)
}

pub fn encode_bas64(payload: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD.encode(payload)
}
