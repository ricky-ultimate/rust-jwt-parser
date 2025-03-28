use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Invalid JWT format")]
    InvalidFormat,
    #[error("Invalid JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid base64 encoding")]
    Base64Error,
    #[error("Wrong Algorithm: {0}")]
    WrongAlgorithm(String),
    #[error("Signature verification failed")]
    InvalidSignature,
}
