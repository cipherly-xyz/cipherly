use web_sys::js_sys;

#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    Unknown(String),
    GeneralBackendError(String),
    UsernameTaken,
}

impl std::fmt::Display for FrontendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            
            Self::Unknown(err) | Self::GeneralBackendError(err) => {
                write!(f, "Unknown error: {}", err)
            }
            FrontendError::Unknown(_) => todo!(),
            FrontendError::GeneralBackendError(_) => todo!(),
            FrontendError::UsernameTaken => todo!(),
        }
    }
}

pub fn format_date(unix: u32) -> Result<String, FrontendError> {
    let unix_millis = unix as u64 * 1000;

    js_sys::eval(&format!(
        r"
        const date = new Date({});

        date.toLocaleTimeString(undefined, {{
            year: 'numeric',
            month: 'numeric',
            day: 'numeric',
        }})
        ",
        unix_millis
    ))
    .map_err(|_| FrontendError::Unknown("Failed to evaluate js".to_string()))?
    .as_string()
    .ok_or(FrontendError::Unknown(
        "Failed to get js value as string".to_string(),
    ))
}
