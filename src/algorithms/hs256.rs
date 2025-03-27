use crate::utils;
use serde_json::{json, Value};
use ring::hmac::{self, HMAC_SHA256};

pub fn jwt_encode(header: &Value, payload: &Value, secret: String) -> String {
    if !header.is_object() || !payload.is_object() {
        utils::error_and_exit("header and payload must be json objects");
    }

    let header_json = serde_json::to_string(header).expect("Failed to serialize header");
    let encoded_header = utils::b64(header_json.as_bytes());

    let payload_json = serde_json::to_string(payload).expect("Failed to seialize payload");
    let encoded_payload = utils::b64(payload_json.as_bytes());

    let jwt_unprotected = format!("{}.{}", encoded_header, encoded_payload);

    let signature = hs256(jwt_unprotected, secret);

    format!("{}.{}.{}", encoded_header, encoded_payload, signature)
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
        "payload": payload,
        "valid" : true
    });
}

pub fn hs256(unsigned_jwt: String, secret: String) -> String {
    let key = hmac::Key::new(HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, &unsigned_jwt.as_bytes());

    utils::b64(signature.as_ref())
}
