use serde_json::json;
use serde_json::Value;

use crate::algorithms::hs256::jwt_encode as hs256_encode;

use crate::utils;
use crate::utils::error::JwtError;

pub fn sign(payload: &Value, secret: &str, algorithm: &str) -> Result<String, JwtError> {
    match algorithm {
        "HS256" => hs256_encode(&json!({"alg": "HS256", "typ":"JWT"}), payload, secret),
        _ => Err(utils::error::JwtError::WrongAlgorithm(algorithm.to_string())),
    }
}
