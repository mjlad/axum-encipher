use std::time::Duration;
use std::sync::Arc;
use encipher::Encipher;
use tower::Layer;
use crate::middleware::EncipherMiddleware;

/// Storage mode for the session token.
#[derive(Debug, Clone)]
pub enum TokenStorage {
    /// Store token in a Cookie (default, suitable for browsers)
    Cookie(String),  // String = cookie name
    /// Store token in a Header (suitable for mobile/API)
    Header(String),  // String = header name
}

impl Default for TokenStorage {
    fn default() -> Self {
        TokenStorage::Cookie(String::from("session"))
    }
}

/// Layer that adds encrypted session management to axum.
#[derive(Clone)]
pub struct EncipherLayer {
    cipher: Arc<Encipher>,
    storage: TokenStorage,
    expiry: Option<Duration>,
}

impl EncipherLayer {
    /// Creates a new EncipherLayer.
    pub fn new(key: Option<u64>, key_env: Option<&str>, step: u8) -> Self {
        Self {
            cipher: Arc::new(Encipher::new(key, key_env, step).expect("Failed to initialize cipher")),
            storage: TokenStorage::default(),
            expiry: None,
        }
    }

    /// Sets the token expiry duration.
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expiry = Some(duration);
        self
    }

    /// Stores the token in a Cookie with the given name.
    pub fn with_cookie(mut self, name: &str) -> Self {
        self.storage = TokenStorage::Cookie(name.to_string());
        self
    }

    /// Stores the token in a Header with the given name.
    pub fn with_header(mut self, name: &str) -> Self {
        self.storage = TokenStorage::Header(name.to_string());
        self
    }
}

impl<S> Layer<S> for EncipherLayer {
    type Service = EncipherMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EncipherMiddleware {
            inner,
            cipher: self.cipher.clone(),
            storage: self.storage.clone(),
            expiry: self.expiry,
        }
    }
}