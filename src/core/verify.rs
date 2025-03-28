use crate::{algorithms::hs256::jwt_verify_and_decode as hs256_decode, utils};
use crate::utils::error::JwtError;
use serde_json::Value;


pub fn verify(signed: &str, secret: &str, algorithm: &str) -> Result<Value, JwtError> {
    match algorithm {
        "HS256" => hs256_decode(signed, secret),
        _ => Err(utils::error::JwtError::WrongAlgorithm(algorithm.to_owned()))
    }
}
