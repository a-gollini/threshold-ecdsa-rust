use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use threshold_ecdsa::api::{KeyService, router};
use tower::ServiceExt;
use uuid::Uuid;

/// Sends one request to a clone of the app (the in-memory key store is shared between clones).
async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn create_key(app: &Router) -> Value {
    let (status, key) = call(
        app,
        "POST",
        "/keys",
        Some(json!({ "threshold": 2, "parties": 3 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    key
}

fn app() -> Router {
    router(KeyService::default())
}

#[tokio::test]
async fn create_key_returns_compressed_public_key() {
    let key = create_key(&app()).await;
    let public_key = key["public_key"].as_str().unwrap();

    assert_eq!(public_key.len(), 66);
    assert!(public_key.starts_with("02") || public_key.starts_with("03"));
}

#[tokio::test]
async fn sign_then_verify_round_trips() {
    let app = app();
    let key = create_key(&app).await;
    let id = key["key_id"].as_str().unwrap();

    let (_, signature) = call(
        &app,
        "POST",
        &format!("/keys/{id}/sign"),
        Some(json!({ "message": "hello" })),
    )
    .await;
    let verify = |message: &'static str| {
        let body = json!({ "message": message, "r": signature["r"], "s": signature["s"] });
        let (app, uri) = (app.clone(), format!("/keys/{id}/verify"));
        async move {
            call(&app, "POST", &uri, Some(body)).await.1["valid"]
                .as_bool()
                .unwrap()
        }
    };

    assert!(verify("hello").await);
    assert!(!verify("hellO").await);
}

#[tokio::test]
async fn signatures_are_always_64_hex_characters() {
    let app = app();
    let key = create_key(&app).await;
    let id = key["key_id"].as_str().unwrap();

    for i in 0..30 {
        let (_, signature) = call(
            &app,
            "POST",
            &format!("/keys/{id}/sign"),
            Some(json!({ "message": format!("message {i}") })),
        )
        .await;
        assert_eq!(signature["r"].as_str().unwrap().len(), 64);
        assert_eq!(signature["s"].as_str().unwrap().len(), 64);
    }
}

#[tokio::test]
async fn create_key_rejects_invalid_parameters() {
    let app = app();

    for (threshold, parties) in [(0, 3), (3, 4), (2, 100), (i64::MIN, 3), (i64::MAX, 3)] {
        let (status, _) = call(
            &app,
            "POST",
            "/keys",
            Some(json!({ "threshold": threshold, "parties": parties })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "threshold={threshold} parties={parties}"
        );
    }
}

#[tokio::test]
async fn unknown_key_returns_404() {
    let app = app();
    let unknown = Uuid::new_v4();

    assert_eq!(
        call(&app, "GET", &format!("/keys/{unknown}"), None).await.0,
        StatusCode::NOT_FOUND
    );
    let sign = call(
        &app,
        "POST",
        &format!("/keys/{unknown}/sign"),
        Some(json!({ "message": "x" })),
    )
    .await;
    assert_eq!(sign.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sign_requires_message() {
    let app = app();
    let key = create_key(&app).await;
    let id = key["key_id"].as_str().unwrap();

    let (status, _) = call(
        &app,
        "POST",
        &format!("/keys/{id}/sign"),
        Some(json!({ "message": "" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_rejects_malformed_hex() {
    let app = app();
    let key = create_key(&app).await;
    let id = key["key_id"].as_str().unwrap();

    let (status, _) = call(
        &app,
        "POST",
        &format!("/keys/{id}/verify"),
        Some(json!({ "message": "m", "r": "zz", "s": "01" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}
