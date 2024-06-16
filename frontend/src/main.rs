use ml_kem::EncodedSizeUser;
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

fn display_error(text_ele: &HtmlElement, input_ele: &HtmlInputElement, message: Option<&str>) {
    match message {
        Some(message) => {
            text_ele.set_inner_text(message);
            input_ele.set_attribute("aria-invalid", "true").unwrap();
        }
        None => {
            text_ele.set_inner_text("");
            input_ele.remove_attribute("aria-invalid").unwrap();
        }
    }
}

fn validate_input(
    text_ele: &HtmlElement,
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

    let username = validate_input(&username_hint, &username_input, "Username cannot be empty");
    let password = validate_input(&password_hint, &password_input, "Password cannot be empty");

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

            display_error(&username_hint, &username_input, None);
        }
        reqwest::StatusCode::CONFLICT => {
            log("username taken");
            display_error(&username_hint, &username_input, Some("Username taken"));
        }
        _ => {
            log("failed");
        }
    }
}

fn main() -> anyhow::Result<()> {
    console_error_panic_hook::set_once();

    Ok(())
}
