use std::sync::Mutex;

use ml_kem::EncodedSizeUser;
use ml_kem::MlKem1024;
use reqwest::StatusCode;
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

fn display_error(
    text_ele: Option<&HtmlElement>,
    input_ele: &HtmlInputElement,
    message: Option<&str>,
) {
    match message {
        Some(message) => {
            if let Some(text_ele) = text_ele {
                text_ele.set_inner_text(message);
            }

            input_ele.set_attribute("aria-invalid", "true").unwrap();
        }
        None => {
            if let Some(text_ele) = text_ele {
                text_ele.set_inner_text("");
            }
            input_ele.remove_attribute("aria-invalid").unwrap();
        }
    }
}

fn validate_input(
    text_ele: Option<&HtmlElement>,
    input_ele: &HtmlInputElement,
    message: &str,
) -> Option<String> {
    let value = input_ele.value();
    if value.is_empty() {
        display_error(text_ele, input_ele, Some(message));
        None
    } else {
        display_error(text_ele, input_ele, None);
        Some(value)
    }
}

#[wasm_bindgen]
pub async fn register() {
    log("registering");

    let document = window()
        .and_then(|win| win.document())
        .expect("Could not access the document");
    let body = document.body().expect("Could not access document.body");

    let username_input = document
        .get_element_by_id("username-input")
        .ok_or(anyhow::anyhow!("failed to find username input"))
        .unwrap()
        .dyn_into::<HtmlInputElement>()
        .unwrap();
    let password_input = document
        .get_element_by_id("password-input")
        .ok_or(anyhow::anyhow!("failed to find password input"))
        .unwrap()
        .dyn_into::<HtmlInputElement>()
        .unwrap();
    let username_hint = document
        .get_element_by_id("username-hint")
        .ok_or(anyhow::anyhow!("failed to find username hint"))
        .unwrap()
        .dyn_into::<HtmlElement>()
        .unwrap();
    let password_hint = document
        .get_element_by_id("password-hint")
        .ok_or(anyhow::anyhow!("failed to find password hint"))
        .unwrap()
        .dyn_into::<HtmlElement>()
        .unwrap();

    let username = validate_input(
        Some(&username_hint),
        &username_input,
        "Username cannot be empty",
    );
    let password = validate_input(
        Some(&password_hint),
        &password_input,
        "Password cannot be empty",
    );

    if password.is_none() || username.is_none() {
        return;
    }

    let username = username.unwrap();
    let password = password.unwrap();

    let (_, ek) = crypto::generate_keys::<crypto::MlKem1024>(password.as_str());
    drop(password);

    let acc = core::CreateAccount {
        username: username.to_string(),
        public_key: core::encode_public_key(&ek.as_bytes()).to_string(),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("http://localhost:8080/api/accounts")
        .json(&acc)
        .send()
        .await
        .unwrap();

    match resp.status() {
        reqwest::StatusCode::CREATED => {
            let text_node = document.create_text_node("Account created!");
            body.append_child(text_node.as_ref())
                .expect("Failed to append text");

            display_error(Some(&username_hint), &username_input, None);
        }
        reqwest::StatusCode::CONFLICT => {
            log("username taken");
            display_error(
                Some(&username_hint),
                &username_input,
                Some("Username taken"),
            );
        }
        _ => {
            log("failed");
        }
    }
}

pub fn get_element_by_id<T: wasm_bindgen::JsCast>(id: &str) -> anyhow::Result<T> {
    let document = window()
        .and_then(|win| win.document())
        .ok_or(anyhow::anyhow!("Failed to get document"))?;

    let element = document
        .get_element_by_id(id)
        .ok_or(anyhow::anyhow!("failed to find element {id}"))?
        .dyn_into::<T>();

    match element {
        Ok(element) => Ok(element),
        Err(_) => Err(anyhow::anyhow!("Failed to cast element")),
    }
}

struct State {
    recipient: Option<core::Account>,
}
static STATE: once_cell::sync::Lazy<Mutex<State>> =
    once_cell::sync::Lazy::new(|| Mutex::new(State { recipient: None }));

#[wasm_bindgen]
pub async fn find_recipient() {
    log("find recipient");

    let recipient_input: HtmlInputElement = get_element_by_id("search-recipient-input").unwrap();

    let username = validate_input(None, &recipient_input, "Recipient cannot be empty");

    if username.is_none() {
        return;
    }
    let username = username.unwrap();

    let client = reqwest::Client::new();
    let acc = client
        .get(format!("http://localhost:8080/api/accounts/{}", username))
        .send()
        .await
        .unwrap()
        .json::<core::Account>()
        .await
        .unwrap();

    log(&format!("{:?}", acc));

    let mut s = STATE.lock().unwrap();

    s.recipient = Some(acc);
}

#[wasm_bindgen]
pub async fn share_secret() {
    let acc = {
        let s = STATE.lock().unwrap();
        s.recipient.clone()
    };

    if acc.is_none() {
        log("no recipient");
        return;
    }
    let acc = acc.unwrap();

    log(&format!("recipient: {:?}", acc.username));

    let secret_hint: HtmlElement = get_element_by_id("secret-hint").unwrap();
    let secret_input: HtmlInputElement = get_element_by_id("secret-input").unwrap();
    let secret = validate_input(Some(&secret_hint), &secret_input, "Secret cannot be empty");

    if secret.is_none() {
        return;
    }
    let secret = secret.unwrap();

    let ek_bytes = core::decode_public_key(&acc.public_key).unwrap();

    let ek = crypto::ek_from_bytes::<MlKem1024>(&ek_bytes);

    let (encapsulated_sym_key, sym_key) = crypto::ek_shared_secret::<MlKem1024>(&ek);

    let ciphertext = crypto::aes_enc(secret.as_bytes(), &sym_key).unwrap();

    drop(secret);
    drop(sym_key);

    let secret_body = core::CreateSecret {
        ciphertext: core::encode_public_key(&ciphertext),
        enc_key: core::encode_public_key(&encapsulated_sym_key),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("http://localhost:8080/api/secrets")
        .json(&secret_body)
        .send()
        .await
        .unwrap();

    match resp.status() {
        StatusCode::CREATED => {
            let response_body: core::SecretCreated = resp.json().await.unwrap();

            let link = get_element_by_id::<HtmlElement>("shared-secret-link").unwrap();

            let url = format!("http://localhost:8080/secret/{}", response_body.id);

            link.set_attribute("href", &url).unwrap();
            link.set_inner_text(&url);
        }
        _ => {
            log("failed to create secret");
        }
    }
}

fn main() -> anyhow::Result<()> {
    console_error_panic_hook::set_once();

    Ok(())
}
