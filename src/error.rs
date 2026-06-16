use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncipherError {
    #[error("session token not found in request")]
    MissingToken,

    #[error("session token signature is invalid")]
    InvalidSignature,

    #[error("session token has expired")]
    TokenExpired,

    #[error("failed to deserialize session data: {0}")]
    DeserializationError(String),

    #[error("failed to serialize session data: {0}")]
    SerializationError(String),
}

// Always returns a generic message to avoid leaking internal details to the client
impl EncipherError {
    pub fn public_message(&self) -> &'static str {
        "Unauthorized"
    }
}