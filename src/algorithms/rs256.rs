use crate::utils;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

pub fn rs256(jwt_unprotected: &str, private_key_pem: &str) -> String {
    let private_key_der = pem_to_der(private_key_pem).expect("Failed to convert PEM to DER");

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

    utils::b64(signature.as_ref())
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, &'static str> {
    let pem = pem.trim();
    if pem.starts_with("-----BEGIN") {
        let base64_part = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<&str>>()
            .join("");

        utils::unb64(&base64_part)
            .map(|decoded_str| decoded_str.into_bytes())
            .map_err(|_| "Failed to decode base64")
    } else {
        Err("Invalid PEM format")
    }
}
