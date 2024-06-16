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
    pub enc_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretCreated {
    pub id: String,
}

pub fn decode_public_key(payload: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::prelude::BASE64_STANDARD.decode(payload)
}

pub fn encode_public_key(payload: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD.encode(payload)
}
