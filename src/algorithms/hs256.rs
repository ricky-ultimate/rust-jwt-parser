use crate::utils::{self, error::JwtError};
use ring::hmac::{self, HMAC_SHA256};
use serde_json::{json, Value};

pub fn jwt_encode(header: &Value, payload: &Value, secret: &str) -> Result<String, JwtError> {
    if !header.is_object() || !payload.is_object() {
        utils::error_and_exit("header and payload must be json objects");
    }

    let header_json = serde_json::to_string(header)?;
    let payload_json = serde_json::to_string(payload)?;

    let encoded_header = utils::b64(header_json.as_bytes());
    let encoded_payload = utils::b64(payload_json.as_bytes());

    let jwt_unprotected = format!("{}.{}", encoded_header, encoded_payload);
    let signature = hs256(&jwt_unprotected, secret);

    Ok(format!(
        "{}.{}.{}",
        encoded_header, encoded_payload, signature
    ))
}

pub fn jwt_verify_and_decode(jwt: &str, secret: &str) -> Result<Value, JwtError> {
    if jwt.trim().is_empty() || secret.trim().is_empty() {
        return Err(JwtError::InvalidFormat);
    }

    let parts: Vec<String> = jwt.split('.').map(String::from).collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }

    let header_str =
        String::from_utf8(utils::unb64(&parts[0])?).map_err(|_| JwtError::Base64Error)?;
    let header: Value = serde_json::from_str(&header_str)?;

    if header["alg"] != "HS256" {
        return Err(JwtError::WrongAlgorithm(header["alg"].to_string()));
    }

    let payload_str =
        String::from_utf8(utils::unb64(&parts[1])?).map_err(|_| JwtError::Base64Error)?;
    let payload: Value = serde_json::from_str(&payload_str)?;

    let jwt_unprotected = format!("{}.{}", parts[0], parts[1]);
    let signature = hs256(&jwt_unprotected, &secret);

    let valid = signature == parts[2];

    Ok(json!({
        "header": header,
        "payload": payload,
        "valid" : valid
    }))
}

pub fn hs256(jwt_unprotected: &str, secret: &str) -> String {
    let key = hmac::Key::new(HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, &jwt_unprotected.as_bytes());

    utils::b64(signature.as_ref())
}
