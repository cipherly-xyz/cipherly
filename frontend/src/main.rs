use std::{fmt::Debug, sync::Mutex};

use crypto::EncryptionResult;
use ml_kem::EncodedSizeUser;
use reqwest::StatusCode;
use secretshare::{
    display_result, format_date, get_element_by_id, get_selected_radio_option, validate_input,
    FrontendError,
};
use wasm_bindgen::prelude::*;
use web_sys::{window, HtmlElement, HtmlInputElement};

mod crypto;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

#[derive(Debug)]
struct RegistrationViewModel {
    username: String,
    encapsulation_key_fingerprint: String,
    profile_url: String,
    profile_url_with_fingerprint: String,
}

impl maud::Render for RegistrationViewModel {
    fn render(&self) -> maud::Markup {
        maud::html! {
            p { (format!("Registered as {}", self.username)) }
            p { (format!("Encapsulation key fingerprint: {}", self.encapsulation_key_fingerprint)) }
            p {
                a href=(self.profile_url) {
                    (self.profile_url)
                }
            }
            p {
                a href=(self.profile_url_with_fingerprint) {
                    (self.profile_url_with_fingerprint)
                }
            }
        }
    }
}

#[wasm_bindgen]
pub async fn register() {
    let res = register_internal().await;

    log(&format!("{res:?}"));
    if let Err(err) = display_result("register-result", res) {
        log(&format!("Failed to display error: {:?}", err));
    }
}

async fn register_internal() -> Result<RegistrationViewModel, FrontendError> {
    log("registering");

    let document = window()
        .and_then(|win| win.document())
        .ok_or(FrontendError::DomError(
            "Could not access the document".to_string(),
        ))?;

    let body = document.body().ok_or(FrontendError::DomError(
        "Could not access DOM body".to_string(),
    ))?;

    let username_input: HtmlInputElement = get_element_by_id("username-input")?;
    let password_input = get_element_by_id("password-input")?;
    let username_hint: HtmlElement = get_element_by_id("username-hint")?;
    let password_hint = get_element_by_id("password-hint")?;

    let username = validate_input(
        Some(&username_hint),
        &username_input,
        "Username cannot be empty",
    )?;

    let password = validate_input(
        Some(&password_hint),
        &password_input,
        "Password cannot be empty",
    )?;

    let (_, ek) = crypto::generate_keys::<crypto::MlKem1024>(password.as_str());
    drop(password);

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
            let text_node = document.create_text_node("Account created!");
            body.append_child(text_node.as_ref()).map_err(|e| {
                FrontendError::DomError(format!("Failed to create child node: {e:?}"))
            })?;

            let profile_url = format!("http://localhost:8080/user/{username}");
            let profile_url_with_fingerprint =
                format!("http://localhost:8080/user/{username}/{encapsulation_key_fingerprint}");

            Ok(RegistrationViewModel {
                username,
                encapsulation_key_fingerprint,
                profile_url,
                profile_url_with_fingerprint,
            })
        }
        reqwest::StatusCode::CONFLICT => {
            log("username taken");
            Err(FrontendError::InvalidInput {
                input_element_id: "username-input".to_owned(),
                hint_element_id: Some("username-hint".to_owned()),
                message: "Username taken".to_owned(),
            })
        }
        _ => Err(FrontendError::Unknown(
            "Unknown error from server".to_owned(),
        )),
    }
}

struct State {
    recipient: Option<core::Account>,
    expected_fingerprint: Option<ExpectedFingerprint>,
}
static STATE: once_cell::sync::Lazy<Mutex<State>> = once_cell::sync::Lazy::new(|| {
    Mutex::new(State {
        recipient: None,
        expected_fingerprint: None,
    })
});

#[wasm_bindgen]
pub async fn find_recipient() {
    let res = find_recipient_internal().await;

    log(&format!("{res:?}"));
    if let Err(err) = display_result("find-recipient-result", res) {
        log(&format!("Failed to display error: {:?}", err));
    }
}

#[derive(Debug)]
struct FindRecipientViewModel {
    username: String,
}

impl maud::Render for FindRecipientViewModel {
    fn render(&self) -> maud::Markup {
        maud::html! {
            p { (format!("Found recipient {}", self.username)) }
        }
    }
}

async fn find_recipient_internal() -> Result<FindRecipientViewModel, FrontendError> {
    log("find recipient");

    let recipient_input: HtmlInputElement = get_element_by_id("search-recipient-input")?;

    let username = validate_input(None, &recipient_input, "Recipient cannot be empty")?;

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

            let mut s = STATE.lock().unwrap();

            s.recipient = Some(acc);
            Ok(FindRecipientViewModel { username })
        }
        reqwest::StatusCode::NOT_FOUND => {
            Err(FrontendError::Unknown("Recipient not found".to_owned()))
        }
        _ => Err(FrontendError::Unknown(
            "Unknown error from server".to_owned(),
        )),
    }
}

#[derive(Debug)]
struct ShareSecretViewModel {
    url: String,
    recipient: String,
    expiration: String,
}

impl maud::Render for ShareSecretViewModel {
    fn render(&self) -> maud::Markup {
        maud::html! {
            p {
                "Share this link with " (self.recipient)
            }
            a href=(self.url) { (self.url) }
            p {
                "⌛️ Expires at " (self.expiration)
            }
        }
    }
}

#[wasm_bindgen]
pub async fn share_secret() {
    let res = share_secret_internal().await;

    log(&format!("{res:?}"));
    if let Err(err) = display_result("share-secret-result", res) {
        log(&format!("Failed to display error: {:?}", err));
    }
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

async fn share_secret_internal() -> Result<ShareSecretViewModel, FrontendError> {
    let acc = {
        let s = STATE.lock().unwrap();
        s.recipient.clone()
    }
    .ok_or(FrontendError::Unknown(
        "No recipient in application state".to_owned(),
    ))?;

    log(&format!("recipient: {:?}", acc.username));

    // new block to avoid clippy false positive about unreleased locks with the await further down: https://github.com/rust-lang/rust-clippy/issues/6353
    {
        let mut s = STATE.lock().unwrap();

        if let Some(expected_fingerprint) = &s.expected_fingerprint {
            if expected_fingerprint.username == acc.username {
                verify_fingerprint(&acc, expected_fingerprint)?;
            } else {
                s.expected_fingerprint = None;
            }
        }
    }

    let secret_hint: HtmlElement = get_element_by_id("secret-hint")?;
    let secret_input: HtmlInputElement = get_element_by_id("secret-input")?;
    let secret = validate_input(Some(&secret_hint), &secret_input, "Secret cannot be empty")?;

    let selected_timeout = get_selected_radio_option("destroy-after")?;

    log(&format!("now: {:?}", web_time::SystemTime::now()));

    let now = web_time::SystemTime::now();
    let deadline = match selected_timeout.as_str() {
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

    let ek_bytes = core::decode_base64(&acc.public_key)
        .map_err(|e| FrontendError::Unknown(format!("Failed to decode public key: {e:?}")))?;

    let EncryptionResult {
        ciphertext,
        encapsulated_sym_key,
        nonce,
    } = crypto::encrypt(&ek_bytes, &secret)
        .map_err(|err| FrontendError::Unknown(format!("Failed to encrypt: {err:?}")))?;

    drop(secret);

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

            let url = format!("http://localhost:8080/secret/{}", response_body.id);

            let deadline_fmt = format_date(deadline_unix)?;
            Ok(ShareSecretViewModel {
                url,
                recipient: acc.username,
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

impl maud::Render for DecryptedSecretViewModel {
    fn render(&self) -> maud::Markup {
        maud::html! {
            p { (self.plaintext) }
        }
    }
}

#[wasm_bindgen]
pub async fn decrypt_secret() {
    let res = decrypt_secret_internal().await;
    log(&format!("{res:?}"));

    if let Err(err) = display_result("decrypt-secret-result", res) {
        log(&format!("Failed to display error: {:?}", err));
    }
}

async fn decrypt_secret_internal() -> Result<DecryptedSecretViewModel, FrontendError> {
    let secret_id_input = get_element_by_id::<HtmlInputElement>("decrypt-secret-id-input")?;
    let secret_id = validate_input(None, &secret_id_input, "Secret ID cannot be empty")?;

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

            let password_input = get_element_by_id("decode-password-input")?;

            let password = validate_input(None, &password_input, "Password cannot be empty")?;

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
            drop(password);

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

    if let Err(err) = autofill_stuff_from_url() {
        log(&format!("Failed to autofill secret id: {:?}", err));
    }

    Ok(())
}

struct ExpectedFingerprint {
    fingerprint: String,
    username: String,
}

fn autofill_stuff_from_url() -> anyhow::Result<()> {
    let path = window()
        .ok_or(anyhow::anyhow!("Failed to get window"))?
        .location()
        .pathname()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let mut segments = path.split('/');
    segments.next();

    match segments.next() {
        Some("secret") => {
            let secret_id = segments
                .next()
                .ok_or(anyhow::anyhow!("Secret path, but no id"))?;
            let secret_id_input = get_element_by_id::<HtmlInputElement>("decrypt-secret-id-input")?;
            secret_id_input.set_value(secret_id);
        }
        Some("user") => {
            let username = segments
                .next()
                .ok_or(anyhow::anyhow!("User path, but no username"))?;
            let username_input = get_element_by_id::<HtmlInputElement>("search-recipient-input")?;
            username_input.set_value(username);

            if let Some(fingerprint) = segments.next() {
                let mut state = STATE.lock().unwrap();
                state.expected_fingerprint = Some(ExpectedFingerprint {
                    fingerprint: fingerprint.to_owned(),
                    username: username.to_owned(),
                });
            }
        }
        _ => (),
    }
    Ok(())
}
