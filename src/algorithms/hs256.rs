use crate::utils;
use serde_json::{json, Value};
use std::process;

pub fn jwt_encode(header: &Value, payload: &Value) -> String {
    if !header.is_object() || !payload.is_object() {
        eprint!("header and payload must be json objects");
        process::exit(0);
    }

    let encoded_header = utils::b64(header);
    let encoded_payload = utils::b64(payload);

    format!("{}.{}.", encoded_header, encoded_payload)
}

pub fn jwt_verify_and_decode(jwt: String) -> Value {
    if jwt.trim().is_empty() {
        eprint!("empty string detected");
        process::exit(0);
    }

    let parts: Vec<_> = jwt.split('.').collect();
    if parts.len() != 2 {
        eprint!("Invalid jwt format");
        process::exit(0);
    }
    let header = utils::unb64(parts[0]);
    if header["alg"] != "HS256" {
        eprint!("Wrong algorithm: {}", header["alg"])
    }
    let payload = utils::unb64(parts[1]);

    return json!({
        "header": header,
        "payload": payload
    });
}
