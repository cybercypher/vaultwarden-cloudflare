use serde_json::json;
use worker::Response;

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub status: u16,
}

impl Error {
    pub fn new(message: impl Into<String>, status: u16) -> Self {
        Self {
            message: message.into(),
            status,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(message, 400)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(message, 401)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(message, 404)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(message, 500)
    }

    pub fn into_response(self) -> Response {
        let body = json!({
            "error": self.message,
            "error_description": self.message,
            "ErrorModel": {
                "Message": self.message,
                "Object": "error"
            }
        });
        let mut resp =
            Response::from_json(&body).unwrap_or_else(|_| Response::error(&self.message, self.status).unwrap());
        let _ = resp.headers_mut().set("Content-Type", "application/json");
        resp.with_status(self.status)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<worker::Error> for Error {
    fn from(e: worker::Error) -> Self {
        Error::internal(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::bad_request(format!("JSON error: {e}"))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::bad_request(format!("Base64 error: {e}"))
    }
}

impl From<Error> for worker::Error {
    fn from(e: Error) -> Self {
        worker::Error::RustError(e.message)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Macro for returning errors, matching original vaultwarden pattern
#[macro_export]
macro_rules! err {
    ($msg:expr) => {
        return Err($crate::error::Error::bad_request($msg))
    };
    ($msg:expr, $status:expr) => {
        return Err($crate::error::Error::new($msg, $status))
    };
}
