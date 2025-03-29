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
    let private_key = fs::read_to_string(private_key_path).expect("Failed to read private key file");

    match jwt_encode(&header, &payload, &private_key) {
        Ok(token) => println!("jwt: {}", token),
        Err(e) => eprintln!("{}", e),
    }


    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNzQzMzYxODU1LCJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.nQ5RbTqw_bfIjL3fwngBBNfDMjAvTTcMgkiZKwOhm0HpGg2BPOhHo8NFAjMYEFhMqlf0jw_lv7QK4lsaPvy0USaWkf0mQAJoASvrftMfCl9LVGmZbDqaGPpwPCtvpmREWRTMINWEjAaCE91MQDJlDhMmClYrfxvNGvSnctiYNFKZbnpWsvAWJcAdWVZrPmTTfadk1b_AZvyv-9xml22jB8w60ONNg32ybGKQb36V_1UQr9X_eO6ijc26OPMZY5z6xXgKkJb_PgLgsMAxSJKKMbiwUC4_OOaDwqvCoQlbJYaYTMpbMjmg9rodg46SX3XVTRG1YCRCZ-bTmyCl0Ce7-g";
    match jwt_verify_and_decode(jwt, &private_key){
        Ok(decoded) => println!("Decoded JWT: {}", decoded),
        Err(e) => eprintln!("Error decoding JWT: {}", e),
    }
}
