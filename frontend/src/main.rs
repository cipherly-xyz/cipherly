use std::sync::Mutex;

use crypto::EncryptionResult;
use ml_kem::EncodedSizeUser;
use reqwest::StatusCode;
use secretshare::{display_result, get_element_by_id, validate_input, FrontendError};
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
}

impl maud::Render for RegistrationViewModel {
    fn render(&self) -> maud::Markup {
        maud::html! {
            p { (format!("Registered as {}", self.username)) }
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

    let acc = core::CreateAccount {
        username: username.to_string(),
        public_key: core::encode_bas64(&ek.as_bytes()).to_string(),
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

            Ok(RegistrationViewModel { username })
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
}
static STATE: once_cell::sync::Lazy<Mutex<State>> =
    once_cell::sync::Lazy::new(|| Mutex::new(State { recipient: None }));

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
}

impl maud::Render for ShareSecretViewModel {
    fn render(&self) -> maud::Markup {
        maud::html! {
            p {
                "Share this link with " (self.recipient)
            }
            a href=(self.url) { (self.url) }
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

async fn share_secret_internal() -> Result<ShareSecretViewModel, FrontendError> {
    let acc = {
        let s = STATE.lock().unwrap();
        s.recipient.clone()
    }
    .ok_or(FrontendError::Unknown(
        "No recipient in application state".to_owned(),
    ))?;

    log(&format!("recipient: {:?}", acc.username));

    let secret_hint: HtmlElement = get_element_by_id("secret-hint")?;
    let secret_input: HtmlInputElement = get_element_by_id("secret-input")?;
    let secret = validate_input(Some(&secret_hint), &secret_input, "Secret cannot be empty")?;

    let ek_bytes = core::decode_base64(&acc.public_key)
        .map_err(|e| FrontendError::Unknown(format!("Failed to decode public key: {e:?}")))?;

    let EncryptionResult {
        ciphertext,
        encapsulated_sym_key,
    } = crypto::encrypt(&ek_bytes, &secret)
        .map_err(|err| FrontendError::Unknown(format!("Failed to encrypt: {err:?}")))?;

    drop(secret);

    let secret_body = core::CreateSecret {
        ciphertext: core::encode_bas64(&ciphertext),
        encapsulated_sym_key: core::encode_bas64(&encapsulated_sym_key),
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

            Ok(ShareSecretViewModel {
                url,
                recipient: acc.username,
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
            let encapsulated_sym_key = core::decode_base64(&secret.encapsulated_sym_key)
                .map_err(|e| {
                    FrontendError::Unknown(format!(
                        "Failed to decode encapsulated symetric key: {e:?}"
                    ))
                })?;

            let plaintext =
                crypto::decrypt::<ml_kem::MlKem1024>(&password, &ciphertext, &encapsulated_sym_key)
                    .map_err(|e| {
                        FrontendError::Unknown(format!("Failed to decrypt secret: {e:?}"))
                    })?;
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

    Ok(())
}
