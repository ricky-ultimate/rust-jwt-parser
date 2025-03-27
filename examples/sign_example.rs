use dotenv::dotenv;
use rust_jwt_parser::core::sign::sign as jwt_sign;
use serde_json::json;
use std::env;

fn main() {
    dotenv().ok();

    let payload = json!({
        "sub": "qwe-564-9i1",
        "kid" : "98266722",
        "name": "john doe"
    });

    let secret = env::var("SECRET").expect("SECRET MUST BE SET");

    match jwt_sign(&payload, &secret, "HS256"){
        Ok(token) => println!("{}", token),
        Err(e) => eprintln!("{}", e)
    }
}
