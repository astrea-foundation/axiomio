use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid hex: {0}")]
    Hex(String),
    #[error("invalid key: {0}")]
    Key(String),
    #[error("ciphertext too short")]
    CiphertextTooShort,
    #[error("decryption failed")]
    Decrypt,
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
