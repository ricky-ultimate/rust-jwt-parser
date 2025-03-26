mod algorithms;
mod utils;

use crate::algorithms::hs256::jwt_encode as hs256_encode;
use crate::algorithms::hs256::jwt_verify_and_decode as hs256_decode;
use serde_json::{json, Value};

fn main() {
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });

    let payload: Value = json!({
        "name": "rando",
        "admin": "true"
    });

    println!("{}", hs256_encode(&header, &payload));
    println!(
        "{}",
        hs256_decode(String::from(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6InRydWUiLCJuYW1lIjoicmFuZG8ifQ"
        ))
    );
}
