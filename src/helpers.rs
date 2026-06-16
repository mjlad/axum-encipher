use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use axum::http::{Request, Response, HeaderValue, header};
use axum::body::Body;
use encipher::Encipher;
use serde_json::Value;
use crate::layer::TokenStorage;
use crate::session::EncipherSession;
use crate::error::EncipherError;

/// Extracts the token from Cookie or Header.
pub(crate) fn extract_token(req: &Request<Body>, storage: &TokenStorage) -> Option<String> {
    match storage {
        TokenStorage::Cookie(name) => {
            req.headers()
                .get(header::COOKIE)?
                .to_str().ok()?
                .split(';')
                .find(|c| c.trim().starts_with(name.as_str()))?
                .split_once('=')?
                .1
                .trim()
                .to_string()
                .into()
        }
        TokenStorage::Header(name) => {
            req.headers()
                .get(name.as_str())?
                .to_str().ok()?
                .to_string()
                .into()
        }
    }
}

/// Decrypts the token and builds an EncipherSession.
pub(crate) fn decrypt_session(
    cipher: &Arc<Encipher>,
    token: &str,
    expiry: Option<Duration>,
) -> Result<EncipherSession, EncipherError> {
    let json = cipher.decrypt(token).map_err(|_| EncipherError::InvalidSignature)?;

    let mut data: HashMap<String, Value> = serde_json::from_str(&json)
        .map_err(|e| EncipherError::DeserializationError(e.to_string()))?;

    // Check expiry if set
    if expiry.is_some() {
        let exp = data.remove("_exp")
            .and_then(|v| v.as_u64())
            .ok_or(EncipherError::TokenExpired)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > exp {
            return Err(EncipherError::TokenExpired);
        }
    }

    Ok(EncipherSession::from_data(data))
}

/// Encrypts the session and returns a token string.
pub(crate) fn encrypt_session(
    cipher: &Arc<Encipher>,
    session: &EncipherSession,
    expiry: Option<Duration>,
) -> Result<String, EncipherError> {
    let mut data = session.data().clone();

    // Add expiry timestamp if set
    if let Some(duration) = expiry {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + duration.as_secs();
        data.insert("_exp".to_string(), Value::Number(exp.into()));
    }

    let json = serde_json::to_string(&data)
        .map_err(|e| EncipherError::SerializationError(e.to_string()))?;

    Ok(cipher.encrypt(&json))
}

/// Sets the token in the response via Cookie or Header.
pub(crate) fn set_token(
    response: &mut Response<Body>,
    storage: &TokenStorage,
    token: &str,
    expiry: Option<Duration>,
) {
    match storage {
        TokenStorage::Cookie(name) => {
            let cookie = match expiry {
                Some(d) => format!("{name}={token}; HttpOnly; SameSite=Strict; Max-Age={}", d.as_secs()),
                None    => format!("{name}={token}; HttpOnly; SameSite=Strict"),
            };
            if let Ok(val) = HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(header::SET_COOKIE, val);
            }
        }
        TokenStorage::Header(name) => {
            if let Ok(header_name) = name.parse::<header::HeaderName>() {
                if let Ok(val) = HeaderValue::from_str(token) {
                    response.headers_mut().insert(header_name, val);
                }
            }
        }
    }
}