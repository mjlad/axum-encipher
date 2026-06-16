use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use axum::http::{Request, Response, StatusCode};
use axum::body::Body;
use tower::Service;
use crate::layer::TokenStorage;
use crate::session::EncipherSession;
use crate::helpers::{extract_token, decrypt_session, encrypt_session, set_token};
use encipher::Encipher;

/// Middleware that processes each request and response.
#[derive(Clone)]
pub struct EncipherMiddleware<S> {
    pub(crate) inner:   S,
    pub(crate) cipher:  Arc<Encipher>,
    pub(crate) storage: TokenStorage,
    pub(crate) expiry:  Option<Duration>,
}

impl<S> Service<Request<Body>> for EncipherMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error    = S::Error;
    type Future   = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let cipher  = self.cipher.clone();
        let storage = self.storage.clone();
        let expiry  = self.expiry;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // 1. Extract token from Cookie or Header
            let token = extract_token(&req, &storage);

            // 2. Decrypt token → build session
            let session = match token {
                Some(t) => decrypt_session(&cipher, &t, expiry),
                None    => Ok(EncipherSession::new()),
            };

            // 3. Handle session errors → return 401
            let session = match session {
                Ok(s)  => s,
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Session error: {}", e);

                    let response = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::from(e.public_message()))
                        .unwrap();

                    return Ok(response);
                }
            };

            // 4. Insert session into request extensions
            req.extensions_mut().insert(session.clone());

            // 5. Call the handler
            let mut response = inner.call(req).await?;

            // 6. Session is shared via Arc — read modified flag directly
            if session.is_modified() {
                if let Ok(token) = encrypt_session(&cipher, &session, expiry) {
                    set_token(&mut response, &storage, &token, expiry);
                }
            }

            Ok(response)
        })
    }
}