mod algorithms;
mod utils;
use dotenv::dotenv;
use std::env;

use crate::algorithms::hs256::jwt_encode as hs256_encode;
use crate::algorithms::hs256::jwt_verify_and_decode as hs256_decode;
use serde_json::{json, Value};

fn main() {
    dotenv().ok();
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });

    let payload: Value = json!({
        "name": "rando",
        "admin": true
    });

    println!("{}", hs256_encode(&header, &payload, env::var("SECRET").expect("SECRET MUST BE SET")));
    println!(
        "{}",
        hs256_decode(String::from(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6InJhbmRvIn0"
        ))
    );
}
