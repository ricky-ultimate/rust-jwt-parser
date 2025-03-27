use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use std::process;

pub fn b64(input: &[u8] ) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub fn unb64(value: &str) -> Value {
    let decoded_bytes = general_purpose::URL_SAFE_NO_PAD.decode(value).unwrap();
    let decoded_str = String::from_utf8(decoded_bytes).unwrap();
    let json_value: Value = serde_json::from_str(&decoded_str).unwrap();
    json_value
}

pub fn error_and_exit(msg: &str) {
    eprint!("{}", msg);
    process::exit(0);
}
