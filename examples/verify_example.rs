use std::env;

use dotenv::dotenv;
use rust_jwt_parser::core::verify::verify;

fn main() {
    dotenv().ok();

    let secret = env::var("SECRET").expect("SECRET MUST BE SET");
    let signed = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJraWQiOiI5ODI2NjcyMiIsIm5hbWUiOiJqb2huIGRvZSIsInN1YiI6InF3ZS01NjQtOWkxIn0.fAb_cK0mHnBnS1INJgRWy87U-z4zSC9ylXDB0hfQ0ws";

    match verify(signed, &secret, "HS25") {
        Ok(jwt) => println!("{}", jwt),
        Err(e) => eprintln!("{}", e),
    }
}
