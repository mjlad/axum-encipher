use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::error::EncipherError;

/// Internal session data.
struct SessionInner {
    data:     HashMap<String, Value>,
    modified: bool,
}

/// Encrypted session accessible in any handler via `Extension<EncipherSession>`.
/// Cheap to clone — backed by `Arc<Mutex<SessionInner>>`.
#[derive(Clone)]
pub struct EncipherSession {
    inner: Arc<Mutex<SessionInner>>,
}

impl Default for EncipherSession {
    fn default() -> Self {
        Self::new()
    }
}

impl EncipherSession {
    /// Creates a new empty session.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                data:     HashMap::new(),
                modified: false,
            })),
        }
    }

    /// Creates a session from existing data (deserialized from token).
    pub(crate) fn from_data(data: HashMap<String, Value>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionInner {
                data,
                modified: false,
            })),
        }
    }

    /// Returns a copy of the session data (used for serialization).
    pub(crate) fn data(&self) -> HashMap<String, Value> {
        self.inner.lock().unwrap().data.clone()
    }

    /// Returns true if the session was modified during the request.
    pub(crate) fn is_modified(&self) -> bool {
        self.inner.lock().unwrap().modified
    }

    /// Gets a value from the session by key.
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        let inner = self.inner.lock().unwrap();
        inner.data.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Inserts or updates a value in the session.
    pub fn set<T: Serialize>(&self, key: &str, value: T) -> Result<(), EncipherError> {
        let v = serde_json::to_value(value)
            .map_err(|e| EncipherError::SerializationError(e.to_string()))?;
        let mut inner = self.inner.lock().unwrap();
        inner.data.insert(key.to_string(), v);
        inner.modified = true;
        Ok(())
    }

    /// Removes a value from the session by key.
    pub fn remove(&self, key: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.data.remove(key);
        inner.modified = true;
    }

    /// Clears all session data.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.data.clear();
        inner.modified = true;
    }
}