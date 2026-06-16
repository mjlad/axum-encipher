# axum-encipher

[![Crates.io](https://img.shields.io/crates/v/axum-encipher)](https://crates.io/crates/axum-encipher)
[![Docs.rs](https://docs.rs/axum-encipher/badge.svg)](https://docs.rs/axum-encipher)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Encrypted session middleware for axum — stateless, no database required.

Replaces the default cookie with a fully encrypted one using the [encipher](https://crates.io/crates/encipher) library (Rust-powered, 10x faster than Fernet).

> Not intended as a general-purpose session management library.
> Not suitable for sensitive data such as passwords or financial information.

## Installation

```toml
[dependencies]
axum-encipher = "0.1"
```

## Usage

```rust
use axum::{Router, routing::{get, post}, Extension, Json};
use axum_encipher::{EncipherLayer, EncipherSession};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/login", post(login))
        .route("/home",  get(home))
        .layer(EncipherLayer::new(Some(42), None, 7));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn login(Extension(session): Extension<EncipherSession>) {
    session.set("user_id", 1u32).unwrap();
    session.set("username", "mejlad").unwrap();
}

async fn home(Extension(session): Extension<EncipherSession>) {
    let username: Option<String> = session.get("username");
}
```

## Options

```rust
EncipherLayer::new(Some(42), None, 7)
    .with_expiry(Duration::from_secs(86400))  // 24 hours (optional)
    .with_cookie("session")                    // Cookie storage (default)
    // or
    .with_header("x-session")                 // Header storage (for mobile/API)
```

## License

Licensed under the [Apache License 2.0](LICENSE).