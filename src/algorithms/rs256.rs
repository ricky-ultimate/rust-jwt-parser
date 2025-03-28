use ring::{rand::SystemRandom, signature::{self, RSA_PKCS1_SHA256}};

use crate::utils;


pub fn rs256(jwt_unprotected: &str, private_key: &str) -> String {
    let private_key_as_bytes = private_key.as_bytes();
    let private_key = signature::RsaKeyPair::from_pkcs8(&private_key_as_bytes).expect("Error");

    let rng= SystemRandom::new();
    let mut signature = vec![0; private_key.public_modulus_len()];

    private_key.sign(&RSA_PKCS1_SHA256, &rng, jwt_unprotected.as_bytes(), &mut signature).expect("msg");

    utils::b64(signature.as_ref())
}
