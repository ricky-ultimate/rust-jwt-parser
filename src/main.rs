use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};

fn main(){
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });

    let payload: Value = json!({
        "name": "rando",
        "admin": "true"
    });

    println!("{}", encode(&header, &payload));
    println!("{}", jwt_json("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXIn0.eyJhZG1pbiI6InRydWUiLCJuYW1lIjoicmFuZG8ifQ."));
}


fn base64url(input: &Value) -> String{
    let json_string = serde_json::to_string(&input).unwrap();
    general_purpose::URL_SAFE_NO_PAD.encode(json_string.as_bytes())
}


fn encode(header: &Value, payload: &Value) -> String {
    let encoded_header = base64url(header);
    let encoded_payload = base64url(payload);

    let unsigned_jwt = format!("{}.{}.", encoded_header, encoded_payload);
    unsigned_jwt
}

fn jwt_json(jwt: &str) -> Value{
    let mut parts = jwt.split('.');
    let encoded_header = parts.next().unwrap();
    let encoded_payload = parts.next().unwrap();

    let header = decode(encoded_header);
    let payload = decode(encoded_payload);

    return json!({
        "header": header,
        "payload": payload
    })
}

fn decode(value: &str) -> Value{
    let decoded_bytes = general_purpose::URL_SAFE_NO_PAD.decode(value).unwrap();
    let decoded_str = String::from_utf8(decoded_bytes).unwrap();
    let json_value: Value =  serde_json::from_str(&decoded_str).unwrap();
    json_value
}
