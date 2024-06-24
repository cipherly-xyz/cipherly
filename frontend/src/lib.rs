use wasm_bindgen::prelude::*;
use web_sys::{window, HtmlElement, HtmlInputElement};

#[derive(Debug)]
pub enum FrontendError {
    InvalidInput {
        input_element_id: String,
        hint_element_id: Option<String>,
        message: String,
    },
    Unknown(String),
    DomError(String),
    GeneralBackendError(String),
}

impl std::fmt::Display for FrontendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput {
                input_element_id,
                hint_element_id,
                message,
            } => {
                write!(f, "Invalid input: {} ({})", message, input_element_id)
            }
            Self::Unknown(err) | Self::DomError(err) | Self::GeneralBackendError(err) => {
                write!(f, "Unknown error: {}", err)
            }
        }
    }
}

pub fn validate_input(
    text_ele: Option<&HtmlElement>,
    input_ele: &HtmlInputElement,
    message: &str,
) -> Result<String, FrontendError> {
    let value = input_ele.value();
    if value.is_empty() {
        Err(FrontendError::InvalidInput {
            input_element_id: input_ele.id(),
            hint_element_id: text_ele.map(|ele| ele.id()),
            message: message.to_string(),
        })
    } else {
        display_form_error(text_ele, input_ele, None)?;
        Ok(value)
    }
}

pub fn display_form_error(
    text_ele: Option<&HtmlElement>,
    input_ele: &HtmlInputElement,
    message: Option<&str>,
) -> Result<(), FrontendError> {
    match message {
        Some(message) => {
            if let Some(text_ele) = text_ele {
                text_ele.set_inner_text(message);
            }

            input_ele
                .set_attribute("aria-invalid", "true")
                .map_err(|_| {
                    FrontendError::DomError("Could not set aria-invalid attribute".to_string())
                })?;
        }
        None => {
            if let Some(text_ele) = text_ele {
                text_ele.set_inner_text("");
            }
            input_ele.remove_attribute("aria-invalid").map_err(|_| {
                FrontendError::DomError("Could not remove aria-invalid attribute".to_string())
            })?;
        }
    }

    Ok(())
}

pub fn display_result<T>(
    target_element: &str,
    res: Result<T, FrontendError>,
) -> Result<(), FrontendError>
where
    T: maud::Render,
{
    let target = get_element_by_id::<HtmlElement>(target_element)?;

    match res {
        Ok(content) => {
            let html = maud::html! {
                div .success {
                   (content)
                }
            }
            .into_string();

            target.set_inner_html(&html);
        }
        Err(FrontendError::InvalidInput {
            input_element_id,
            hint_element_id,
            message,
        }) => {
            let text_ele = if let Some(id) = hint_element_id {
                Some(get_element_by_id::<HtmlElement>(&id)?)
            } else {
                None
            };

            let input_ele = get_element_by_id::<HtmlInputElement>(&input_element_id)?;
            display_form_error(text_ele.as_ref(), &input_ele, Some(&message))?;
        }
        Err(
            FrontendError::Unknown(err)
            | FrontendError::DomError(err)
            | FrontendError::GeneralBackendError(err),
        ) => {
            let html = maud::html! {
                div .error {
                   p { (err) }
                }
            }
            .into_string();

            target.set_inner_html(&html);
        }
    }

    Ok(())
}

pub fn get_element_by_id<T: wasm_bindgen::JsCast>(id: &str) -> Result<T, FrontendError> {
    let document = window()
        .and_then(|win| win.document())
        .ok_or(FrontendError::DomError(
            "Failed to get document".to_string(),
        ))?;

    let element = document
        .get_element_by_id(id)
        .ok_or(FrontendError::DomError(format!(
            "Failed to find element {id}"
        )))?
        .dyn_into::<T>();

    match element {
        Ok(element) => Ok(element),
        Err(_) => Err(FrontendError::DomError(
            "Failed to cast element".to_string(),
        )),
    }
}
