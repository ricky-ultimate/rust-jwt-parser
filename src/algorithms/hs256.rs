use crate::utils;
use serde_json::{json, Value};

pub fn jwt_encode(header: &Value, payload: &Value) -> String {
    if !header.is_object() || !payload.is_object() {
        utils::error_and_exit("header and payload must be json objects");
    }

    let encoded_header = utils::b64(header);
    let encoded_payload = utils::b64(payload);

    format!("{}.{}.", encoded_header, encoded_payload)
}

pub fn jwt_verify_and_decode(jwt: String) -> Value {
    if jwt.trim().is_empty() {
        utils::error_and_exit("empty string detected");
    }

    let parts: Vec<_> = jwt.split('.').collect();
    if parts.len() != 2 {
        utils::error_and_exit("Invalid jwt format");
    }
    let header = utils::unb64(parts[0]);
    if header["alg"] != "HS256" {
        let msg = format!("Wrong algorithm: {}", header["alg"]);
        utils::error_and_exit(&msg);
    }
    let payload = utils::unb64(parts[1]);

    return json!({
        "header": header,
        "payload": payload
    });
}
