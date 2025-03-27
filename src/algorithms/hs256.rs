use crate::utils;
use serde_json::{json, Value};
use ring::hmac::{self, HMAC_SHA256};

pub fn jwt_encode(header: &Value, payload: &Value, secret: &str) -> String {
    if !header.is_object() || !payload.is_object() {
        utils::error_and_exit("header and payload must be json objects");
    }

    let header_json = serde_json::to_string(header).expect("Failed to serialize header");
    let encoded_header = utils::b64(header_json.as_bytes());

    let payload_json = serde_json::to_string(payload).expect("Failed to seialize payload");
    let encoded_payload = utils::b64(payload_json.as_bytes());

    let jwt_unprotected = format!("{}.{}", encoded_header, encoded_payload);

    let signature = hs256(&jwt_unprotected, secret);

    format!("{}.{}.{}", encoded_header, encoded_payload, signature)
}

pub fn jwt_verify_and_decode(jwt: &str, secret: &str) -> Value {
    if jwt.trim().is_empty() || secret.trim().is_empty() {
        utils::error_and_exit("empty string detected");
    }

    let parts: Vec<String> = jwt.split('.').map(String::from).collect();
    if parts.len() != 3 {
        utils::error_and_exit("Invalid jwt format");
    }

    let header: Value = serde_json::from_str(&utils::unb64(&parts[0])).unwrap();
    if header["alg"] != "HS256" {
        let msg = format!("Wrong algorithm: {}", header["alg"]);
        utils::error_and_exit(&msg);
    }

    let payload: Value = serde_json::from_str(&utils::unb64(&parts[1])).unwrap() ;
    let jwt_unprotected = format!("{}.{}", parts[0], parts[1]);


    let signature = hs256(&jwt_unprotected, &secret);

    let valid = signature == parts[2];

    return json!({
        "header": header,
        "payload": payload,
        "valid" : valid
    });
}

pub fn hs256(jwt_unprotected: &str, secret: &str) -> String {
    let key = hmac::Key::new(HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, &jwt_unprotected.as_bytes());

    utils::b64(signature.as_ref())
}
