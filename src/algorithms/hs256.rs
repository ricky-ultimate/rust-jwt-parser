use serde_json::{json, Value};
use crate::utils;


pub fn jwt_encode(header: &Value, payload: &Value) -> String {

    if !header.is_object() || !payload.is_object() {
        panic!("header and payload must be json objects")
    }

    let encoded_header = utils::b64(header);
    let encoded_payload = utils::b64(payload);

    format!("{}.{}.", encoded_header, encoded_payload)
}


pub fn jwt_verify_and_decode(jwt: String) -> Value{

    if jwt.is_empty() {
        panic!("empty string detected")
    }
    let mut parts = jwt.split('.');
    let encoded_header = parts.next().unwrap();
    let encoded_payload = parts.next().unwrap();

    let header = utils::unb64(encoded_header);
    let payload = utils::unb64(encoded_payload);

    return json!({
        "header": header,
        "payload": payload
    })
}
