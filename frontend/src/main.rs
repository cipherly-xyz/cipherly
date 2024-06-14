use web_sys::{window, Element, HtmlInputElement};
use wasm_bindgen::prelude::*;

mod crypto;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

fn main() -> anyhow::Result<()> {
    
    console_error_panic_hook::set_once();

    let document = window()
        .and_then(|win| win.document())
        .expect("Could not access the document");
    let body = document.body().expect("Could not access document.body");
    let text_node = document.create_text_node("Hello, world from Vanilla Rust!");
    body.append_child(text_node.as_ref())
        .expect("Failed to append text");
    
    let button = document.get_element_by_id("encrypt").ok_or(anyhow::anyhow!("failed to find button"))?;
    let secret_input = document.get_element_by_id("secret-input").ok_or(anyhow::anyhow!("failed to find secret text"))?.dyn_into::<HtmlInputElement>().unwrap();
    
    let closure = Closure::<dyn FnMut(_)>::new(move |_event: web_sys::MouseEvent| {
                
                let mut rng = rand::thread_rng();
                log("clicked");
                let plaintext = secret_input.value();
                log(format!("plaintext: {plaintext}").as_str());
                
                let (dk, ek) = crypto::generate_keys::<ml_kem::MlKem1024>("password");
                
                use kem::Encapsulate;
                let (_f, sym_key) = ek.encapsulate(&mut rng).unwrap();
                
                log(&format!("sym key: {sym_key:X?}"));
                
                let cipher = crypto::aes_enc(plaintext.as_bytes(), &sym_key).unwrap();
                log(&format!("cipher: {cipher:X?}"));
                
                let decrypted = crypto::aes_dec(&cipher, &sym_key).unwrap();
                let decrypted = String::from_utf8_lossy(&decrypted); 
                log(&format!("decrypted: {decrypted:?}"));
            });
    
    button.add_event_listener_with_callback("click", closure.as_ref().unchecked_ref()).expect("msg");
    closure.forget();

    
    Ok(())
}
