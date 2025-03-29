use crate::utils::{self, error::JwtError};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde_json::{json, Value};

pub fn rs256(jwt_unprotected: &str, private_key_pem: &str) -> Result<String, JwtError> {
    let private_key_der = pem_to_der(private_key_pem)?;

    let private_key =
        RsaKeyPair::from_pkcs8(&private_key_der).expect("Invalid RSA private key format");

    let rng = SystemRandom::new();
    let mut signature = vec![0; private_key.public_modulus_len()];

    private_key
        .sign(
            &RSA_PKCS1_SHA256,
            &rng,
            jwt_unprotected.as_bytes(),
            &mut signature,
        )
        .expect("RSA signing failed");

    Ok(utils::b64(signature.as_ref()))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, JwtError> {
    let pem = pem.trim();
    if pem.starts_with("-----BEGIN") {
        let base64_part = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<&str>>()
            .join("");

        utils::unb64(&base64_part)
            .map(|decoded_str| decoded_str.into_bytes())
    } else {
        Err(JwtError::InvalidPemFormat)
    }
}

pub fn jwt_encode(header: &Value, payload: &Value, private_key: &str) -> Result<String, JwtError> {
    if !header.is_object() || !payload.is_object() {
        utils::error_and_exit("header and payload must be json objects");
    }

    let header_json = serde_json::to_string(header)?;
    let payload_json = serde_json::to_string(payload)?;

    let encoded_header = utils::b64(header_json.as_bytes());
    let encoded_payload = utils::b64(payload_json.as_bytes());

    let jwt_unprotected = format!("{}.{}", encoded_header, encoded_payload);
    let signature = rs256(&jwt_unprotected, private_key)?;

    Ok(format!(
        "{}.{}.{}",
        encoded_header, encoded_payload, signature
    ))
}

pub fn jwt_verify_and_decode(jwt: &str, private_key: &str) -> Result<Value, JwtError> {
    if jwt.trim().is_empty() || private_key.trim().is_empty() {
        return Err(JwtError::InvalidFormat);
    }

    let parts: Vec<String> = jwt.split('.').map(String::from).collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }

    let header_str = utils::unb64(&parts[0])?;
    let header: Value = serde_json::from_str(&header_str)?;

    if header["alg"] != "HS256" {
        return Err(JwtError::WrongAlgorithm(header["alg"].to_string()));
    }

    let payload_str = utils::unb64(&parts[1])?;
    let payload: Value = serde_json::from_str(&payload_str)?;

    let jwt_unprotected = format!("{}.{}", parts[0], parts[1]);
    let signature = rs256(&jwt_unprotected, &private_key)?;

    let valid = signature == parts[2];

    Ok(json!({
        "header": header,
        "payload": payload,
        "valid" : valid
    }))
}
