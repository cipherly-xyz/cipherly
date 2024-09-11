use core::Account;
use std::fmt::Debug;

use crypto::EncryptionResult;
use ml_kem::EncodedSizeUser;
use reqwest::StatusCode;
use secretshare::{format_date, FrontendError};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

mod crypto;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistrationSuccessViewModel {
    username: String,
    encapsulation_key_fingerprint: String,
    profile_url: String,
    profile_url_with_fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RegistrationModel {
    username: String,
    username_error: Option<String>,
    password_error: Option<String>,
    password: String,
    error: Option<String>,
    success: Option<RegistrationSuccessViewModel>,
}

#[wasm_bindgen]
pub async fn register(store: JsValue) -> JsValue {
    let mut model: RegistrationModel = serde_wasm_bindgen::from_value(store).unwrap();
    log(&format!("register: {:?}", model));

    if model.username.is_empty() {
        model.username_error = Some("Username cannot be empty".to_string())
    } else {
        model.username_error = None;
    }

    if model.password.is_empty() {
        model.password_error = Some("Password cannot be empty".to_string())
    } else {
        model.password_error = None;
    }

    if model.username_error.is_some() || model.password_error.is_some() {
        model.success = None;
        return serde_wasm_bindgen::to_value(&model).unwrap();
    }

    let res = register_internal(&model.username, &model.password).await;

    match res {
        Ok(vm) => {
            model.error = None;
            model.success = Some(vm);
        }
        Err(FrontendError::UsernameTaken) => {
            model.success = None;
            model.username_error = Some("Username is already taken".to_string())
        }
        Err(e) => {
            log(&format!("{e:?}"));
            model.success = None;
            model.error = Some(format!("{e:?}"))
        }
    }

    serde_wasm_bindgen::to_value(&model).unwrap()
}

async fn register_internal(
    username: &str,
    password: &str,
) -> Result<RegistrationSuccessViewModel, FrontendError> {
    log("registering");

    let (_, ek) = crypto::generate_keys::<crypto::MlKem1024>(password);

    let ek_bytes = ek.as_bytes();

    let encapsulation_key_fingerprint = crypto::encapsulation_key_fingerprint(&ek_bytes);

    let acc = core::CreateAccount {
        username: username.to_string(),
        public_key: core::encode_bas64(&ek_bytes).to_string(),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("http://localhost:8080/api/accounts")
        .json(&acc)
        .send()
        .await
        .map_err(|e| FrontendError::GeneralBackendError(e.to_string()))?;

    match resp.status() {
        reqwest::StatusCode::CREATED => {
            let profile_url = format!("http://localhost:8080/?username={username}");
            let profile_url_with_fingerprint =
                format!("http://localhost:8080/?username={username}&fingerprint={encapsulation_key_fingerprint}");

            Ok(RegistrationSuccessViewModel {
                username: username.to_string(),
                encapsulation_key_fingerprint,
                profile_url,
                profile_url_with_fingerprint,
            })
        }
        reqwest::StatusCode::CONFLICT => {
            log("username taken");
            Err(FrontendError::UsernameTaken)
        }
        _ => Err(FrontendError::Unknown(
            "Unknown error from server".to_owned(),
        )),
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SearchRecipientModel {
    pub recipient: Option<Account>,
    pub search: String,
    pub secret: String,
    pub timeout: String,
    success: Option<ShareSecretSuccessViewModel>,
    error: Option<String>,
    expected_fingerprint: Option<String>,
    expected_fingerprint_user: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub username: String,
    pub encapsulation_key: String,
}

#[wasm_bindgen]
pub async fn find_recipient(store: JsValue) -> JsValue {
    let mut model: SearchRecipientModel = serde_wasm_bindgen::from_value(store).unwrap();
    log(&format!("find recipient: {:?}", model));

    let res = find_recipient_internal(
        &model.search,
        Some(ExpectedFingerprint {
            fingerprint: model.expected_fingerprint.as_ref().unwrap().clone(),
            username: model.expected_fingerprint_user.as_ref().unwrap().clone(),
        }),
    )
    .await;

    match res {
        Ok(acc) => {
            model.error = None;
            model.recipient = Some(acc);
        }
        Err(e) => {
            model.error = Some(format!("{e:?}"));
        }
    }

    serde_wasm_bindgen::to_value(&model).unwrap()
}

async fn find_recipient_internal(
    username: &String,
    expected_fingerprint: Option<ExpectedFingerprint>,
) -> Result<Account, FrontendError> {
    log(&format!("find recipient: username = {username}"));

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://localhost:8080/api/accounts/{}", username))
        .send()
        .await
        .map_err(|err| FrontendError::GeneralBackendError(err.to_string()))?;

    match resp.status() {
        reqwest::StatusCode::OK => {
            let acc = resp
                .json::<core::Account>()
                .await
                .map_err(|err| FrontendError::GeneralBackendError(err.to_string()))?;
            if let Some(fingerprint) = expected_fingerprint {
                if fingerprint.username == acc.username {
                    verify_fingerprint(&acc, &fingerprint)?;
                }
            }
            Ok(acc)
        }
        reqwest::StatusCode::NOT_FOUND => {
            Err(FrontendError::Unknown("Recipient not found".to_owned()))
        }
        _ => Err(FrontendError::Unknown(
            "Unknown error from server".to_owned(),
        )),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ShareSecretSuccessViewModel {
    url: String,
    recipient: String,
    expiration: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShareSecretModel {
    recipient: Account,
    secret: String,
    success: Option<ShareSecretSuccessViewModel>,
    timeout: String,
    error: Option<String>,
    expected_fingerprint: Option<String>,
    expected_fingerprint_user: Option<String>,
}

#[wasm_bindgen]
pub async fn share_secret(model: JsValue) -> JsValue {
    let mut model: SearchRecipientModel = serde_wasm_bindgen::from_value(model).unwrap();
    log(&format!("share secret: {:?}", model));

    let res = share_secret_internal(
        model.recipient.as_ref().unwrap(),
        &model.secret,
        &model.timeout,
    )
    .await;

    match res {
        Ok(vm) => {
            model.success = Some(vm);
            model.error = None;
        }
        Err(e) => {
            model.error = Some(format!("{e:?}"));
        }
    };

    serde_wasm_bindgen::to_value(&model).unwrap()
}

fn verify_fingerprint(
    acc: &core::Account,
    expected: &ExpectedFingerprint,
) -> Result<(), FrontendError> {
    let raw_ek_bytes =
        core::decode_base64(&acc.public_key).expect("Failed to decode encapsulation key");

    let actual_recipient_ek_fingerprint = crypto::encapsulation_key_fingerprint(&raw_ek_bytes);
    if actual_recipient_ek_fingerprint != expected.fingerprint {
        return Err(FrontendError::Unknown(format!(
            "Recipient key mismatch. Expected: {}, actual: {actual_recipient_ek_fingerprint}",
            expected.fingerprint
        )));
    }
    Ok(())
}

async fn share_secret_internal(
    recipient: &Account,
    secret: &str,
    timeout: &str,
) -> Result<ShareSecretSuccessViewModel, FrontendError> {
    log(&format!("recipient: {:?}", recipient.username));

    let now = web_time::SystemTime::now();
    let deadline = match timeout {
        "1hour" => now + web_time::Duration::from_secs_f32(3600.0),
        "1day" => now + web_time::Duration::from_secs_f32(86400.0),
        "1week" => now + web_time::Duration::from_secs_f32(604800.0),
        "10seconds" => now + web_time::Duration::from_secs_f32(10.0),
        _ => todo!("invalid timeout selected"),
    };

    let deadline_unix = deadline
        .duration_since(web_time::UNIX_EPOCH)
        .map_err(|e| FrontendError::Unknown(format!("Failed to convert to unix time: {e:?}")))?
        .as_secs() as u32;

    let ek_bytes = core::decode_base64(&recipient.public_key)
        .map_err(|e| FrontendError::Unknown(format!("Failed to decode public key: {e:?}")))?;

    let EncryptionResult {
        ciphertext,
        encapsulated_sym_key,
        nonce,
    } = crypto::encrypt(&ek_bytes, secret)
        .map_err(|err| FrontendError::Unknown(format!("Failed to encrypt: {err:?}")))?;

    let secret_body = core::CreateSecret {
        ciphertext: core::encode_bas64(&ciphertext),
        encapsulated_sym_key: core::encode_bas64(&encapsulated_sym_key),
        expiration: deadline_unix,
        nonce: core::encode_bas64(&nonce),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("http://localhost:8080/api/secrets")
        .json(&secret_body)
        .send()
        .await
        .map_err(|err| FrontendError::GeneralBackendError(err.to_string()))?;

    match resp.status() {
        StatusCode::CREATED => {
            let response_body: core::SecretCreated = resp
                .json()
                .await
                .map_err(|e| FrontendError::GeneralBackendError(e.to_string()))?;

            let url = format!("http://localhost:8080/?secret_id={}", response_body.id);

            let deadline_fmt = format_date(deadline_unix)?;
            Ok(ShareSecretSuccessViewModel {
                url,
                recipient: recipient.username.clone(),
                expiration: deadline_fmt,
            })
        }
        _ => {
            log("failed to create secret");
            Err(FrontendError::GeneralBackendError(
                format!("Failed to create secret: Status code {:?}", resp.status()).to_string(),
            ))
        }
    }
}

#[derive(Debug)]
struct DecryptedSecretViewModel {
    plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptSecretModel {
    secret_id: String,
    password: String,
    plaintext: Option<String>,
    error: Option<String>,
}

#[wasm_bindgen]
pub async fn decrypt_secret(model: JsValue) -> JsValue {
    let mut model: DecryptSecretModel = serde_wasm_bindgen::from_value(model).unwrap();
    log(&format!("{model:?}"));

    let res = decrypt_secret_internal(&model.secret_id, &model.password).await;
    log(&format!("{res:?}"));

    match res {
        Ok(vm) => {
            model.plaintext = Some(vm.plaintext);
            model.error = None;
        }
        Err(e) => {
            model.error = Some(format!("{e:?}"));
        }
    };

    serde_wasm_bindgen::to_value(&model).unwrap()
}

async fn decrypt_secret_internal(
    secret_id: &String,
    password: &String,
) -> Result<DecryptedSecretViewModel, FrontendError> {
    if secret_id.is_empty() {
        return Err(FrontendError::Unknown("Secret ID is empty".to_string()));
    }
    if password.is_empty() {
        return Err(FrontendError::Unknown("Password is empty".to_string()));
    }
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://localhost:8080/api/secrets/{}", secret_id))
        .send()
        .await
        .map_err(|err| FrontendError::GeneralBackendError(err.to_string()))?;

    match resp.status() {
        StatusCode::OK => {
            let secret: core::GetSecret = resp
                .json()
                .await
                .map_err(|e| FrontendError::GeneralBackendError(e.to_string()))?;

            log(&format!("got secret: {:?}", secret));

            let ciphertext = core::decode_base64(&secret.ciphertext).map_err(|e| {
                FrontendError::Unknown(format!("Failed to decode ciphertext: {e:?}"))
            })?;
            let encapsulated_sym_key =
                core::decode_base64(&secret.encapsulated_sym_key).map_err(|e| {
                    FrontendError::Unknown(format!(
                        "Failed to decode encapsulated symetric key: {e:?}"
                    ))
                })?;
            let nonce = core::decode_base64(&secret.nonce)
                .map_err(|e| FrontendError::Unknown(format!("Failed to decode nonce: {e:?}")))?;

            let plaintext = crypto::decrypt::<ml_kem::MlKem1024>(
                &password,
                &ciphertext,
                &encapsulated_sym_key,
                &nonce,
            )
            .map_err(|e| FrontendError::Unknown(format!("Failed to decrypt secret: {e:?}")))?;

            Ok(DecryptedSecretViewModel { plaintext })
        }
        StatusCode::NOT_FOUND => Err(FrontendError::Unknown("Secret not found".to_owned())),
        _ => Err(FrontendError::Unknown(
            "Unknown error from server".to_owned(),
        )),
    }
}

fn main() -> anyhow::Result<()> {
    console_error_panic_hook::set_once();

    Ok(())
}

struct ExpectedFingerprint {
    fingerprint: String,
    username: String,
}
