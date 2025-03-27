pub mod error;

use base64::{engine::general_purpose, Engine as _};
use error::JwtError;
use std::process;

pub fn b64(input: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub fn unb64(value: &str) -> Result<String, JwtError> {
    let decoded_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JwtError::Base64Error)?;
    String::from_utf8(decoded_bytes).map_err(|_| JwtError::Base64Error)
}

pub fn error_and_exit(msg: &str) {
    eprint!("{}", msg);
    process::exit(0);
}
