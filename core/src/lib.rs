use serde::{Deserialize, Serialize};
use base64::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccount {
    pub username: String,
    pub public_key: String,
}

pub fn decode_public_key(payload: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::prelude::BASE64_STANDARD.decode(payload)
}

pub fn encode_public_key(payload: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD.encode(payload)
}