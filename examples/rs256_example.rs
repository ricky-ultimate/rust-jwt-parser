use dotenv::dotenv;
use rust_jwt_parser::algorithms::rs256::{jwt_encode, jwt_verify_and_decode};
use serde_json::{json, Value};
use std::env;
use std::fs;

fn main() {
    dotenv().ok();

    let header = json!({
        "alg": "RS256",
        "typ": "JWT"
    });

    let payload: Value = json!({
        "sub": "1234567890",
        "name": "John Doe",
        "admin": true,
        "iat": 1743361855
    });

    let private_key_path = env::var("RSA_PRIVATE_KEY_PATH").expect("RSA_PRIVATE_KEY_PATH must be set");
    let private_key_pem = fs::read_to_string(private_key_path).expect("Failed to read private key file");
    let public_key_path = env::var("RSA_PUBLIC_KEY_PATH").expect("RSA_PUBLIC_KEY_PATH must be set");
    let public_key_pem = fs::read_to_string(public_key_path).expect("Failed to read private key file");

    match jwt_encode(&header, &payload, &private_key_pem) {
        Ok(token) => {
            println!("jwt: {}", token);
            match jwt_verify_and_decode(&token, &public_key_pem){
                Ok(decoded) => println!("Decoded JWT: {}", decoded),
                Err(e) => eprintln!("Error decoding JWT: {}", e),
            }
        },
        Err(e) => eprintln!("{}", e),
    }
}
