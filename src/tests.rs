use crate::{EncipherLayer, EncipherSession};
use axum::{Router, routing::get, Extension};
use axum_test::TestServer;
use std::time::Duration;

// Helper — builds a test app with EncipherLayer
fn build_app(layer: EncipherLayer) -> Router {
    Router::new()
        .route("/read", get(|Extension(session): Extension<EncipherSession>| async move {
            let value: Option<String> = session.get("user");
            value.unwrap_or_else(|| "empty".to_string())
        }))
        .route("/write", get(|Extension(mut session): Extension<EncipherSession>| async move {
            session.set("user", "Ahmed").unwrap();
            "ok"
        }))
        .layer(layer)
}

// ─── 1. Request without token → empty session ───
#[tokio::test]
async fn test_no_token_gives_empty_session() {
    let app    = build_app(EncipherLayer::new(Some(42), None, 7));
    let server = TestServer::new(app).unwrap();
    let response = server.get("/read").await;
    response.assert_status_ok();
    response.assert_text("empty");
}

// ─── 2. Write session → Cookie contains token ───
#[tokio::test]
async fn test_write_sets_cookie() {
    let app    = build_app(EncipherLayer::new(Some(42), None, 7));
    let server = TestServer::new(app).unwrap();
    let response = server.get("/write").await;
    response.assert_status_ok();
    assert!(response.headers().get("set-cookie").is_some());
}

// ─── 3. Invalid token → 401 ───
#[tokio::test]
async fn test_invalid_token_returns_401() {
    let app    = build_app(EncipherLayer::new(Some(42), None, 7));
    let server = TestServer::new(app).unwrap();
    let response = server
        .get("/read")
        .add_header("cookie", "session=invalid_token")
        .await;
    response.assert_status_unauthorized();
}

// ─── 4. Expired token → 401 ───
#[tokio::test]
async fn test_expired_token_returns_401() {
    let layer  = EncipherLayer::new(Some(42), None, 7)
        .with_expiry(Duration::from_secs(1));
    let app    = build_app(layer.clone());
    let server = TestServer::new(app).unwrap();
    let write_response = server.get("/write").await;
    let cookie = write_response.headers()
        .get("set-cookie").unwrap()
        .to_str().unwrap()
        .to_string();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let response = server
        .get("/read")
        .add_header("cookie", cookie)
        .await;
    response.assert_status_unauthorized();
}

// ─── 5. Header storage ───
#[tokio::test]
async fn test_header_storage() {
    let layer  = EncipherLayer::new(Some(42), None, 7)
        .with_header("x-session");
    let app    = build_app(layer);
    let server = TestServer::new(app).unwrap();
    let response = server.get("/write").await;
    response.assert_status_ok();
    assert!(response.headers().get("x-session").is_some());
}