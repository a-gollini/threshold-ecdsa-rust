//! REST API (axum): run a DKG, sign with a threshold of parties, verify with standard ECDSA.
//!
//! All parties are simulated in-process, so shares live in memory only and are lost on
//! restart (by design for this demo).

use crate::dkg::{self, KeyShare};
use crate::signer::{self, EcdsaSignature};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const MAX_PARTIES: i64 = 20;

pub struct StoredKey {
    pub id: Uuid,
    pub threshold: usize,
    pub shares: Vec<KeyShare>,
}

impl StoredKey {
    fn public_key_hex(&self) -> String {
        let encoded = self.shares[0]
            .public_key
            .encode()
            .expect("public key is never infinity");
        encoded.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Application layer. Cloning is cheap: it clones the `Arc`, not the map.
#[derive(Clone, Default)]
pub struct KeyService {
    keys: Arc<Mutex<HashMap<Uuid, Arc<StoredKey>>>>,
}

impl KeyService {
    pub fn create_key(
        &self,
        threshold: usize,
        parties: usize,
    ) -> Result<Arc<StoredKey>, crate::Error> {
        let key = Arc::new(StoredKey {
            id: Uuid::new_v4(),
            threshold,
            shares: dkg::run(threshold, parties)?,
        });
        self.keys.lock().unwrap().insert(key.id, Arc::clone(&key));
        Ok(key)
    }

    pub fn find(&self, id: &Uuid) -> Option<Arc<StoredKey>> {
        self.keys.lock().unwrap().get(id).cloned()
    }
}

pub fn hash_message(message: &str) -> Vec<u8> {
    Sha256::digest(message.as_bytes()).to_vec()
}

// ---- contracts ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub threshold: i64,
    pub parties: i64,
}

#[derive(Serialize, Deserialize)]
pub struct KeyResponse {
    pub key_id: Uuid,
    pub threshold: usize,
    pub parties: usize,
    pub public_key: String,
}

#[derive(Deserialize)]
pub struct SignRequest {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureResponse {
    pub r: String,
    pub s: String,
    pub message_hash: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    #[serde(default)]
    pub message: String,
    pub r: String,
    pub s: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

/// Errors map to HTTP responses through `IntoResponse`, so handlers can just return `Err(...)`.
pub enum ApiError {
    BadRequest(String),
    NotFound,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::BadRequest(detail) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "detail": detail })),
            )
                .into_response(),
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "detail": "Key not found." })),
            )
                .into_response(),
        }
    }
}

// ---- routes ------------------------------------------------------------------------------

pub fn router(service: KeyService) -> Router {
    Router::new()
        .route("/keys", post(create_key))
        .route("/keys/{id}", get(read_key))
        .route("/keys/{id}/sign", post(sign))
        .route("/keys/{id}/verify", post(verify))
        .with_state(service)
}

fn to_response(key: &StoredKey) -> KeyResponse {
    KeyResponse {
        key_id: key.id,
        threshold: key.threshold,
        parties: key.shares.len(),
        public_key: key.public_key_hex(),
    }
}

/// The protocol code is CPU-bound, so it runs on the blocking thread pool, not the async executor.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work)
        .await
        .expect("worker task panicked")
}

async fn create_key(
    State(service): State<KeyService>,
    Json(request): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<KeyResponse>), ApiError> {
    // Range-check the threshold first so that `2t-1` cannot overflow.
    let needed = 2 * request.threshold.clamp(1, MAX_PARTIES) - 1;
    if request.threshold < 1 || request.parties < needed || request.parties > MAX_PARTIES {
        return Err(ApiError::BadRequest(format!(
            "parties must be between {needed} (2t-1, needed to sign) and {MAX_PARTIES}, and threshold must be >= 1."
        )));
    }
    let (threshold, parties) = (request.threshold as usize, request.parties as usize);
    let key = blocking(move || service.create_key(threshold, parties))
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::CREATED, Json(to_response(&key))))
}

async fn read_key(
    State(service): State<KeyService>,
    Path(id): Path<Uuid>,
) -> Result<Json<KeyResponse>, ApiError> {
    let key = service.find(&id).ok_or(ApiError::NotFound)?;
    Ok(Json(to_response(&key)))
}

async fn sign(
    State(service): State<KeyService>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignatureResponse>, ApiError> {
    let key = service.find(&id).ok_or(ApiError::NotFound)?;
    if request.message.is_empty() {
        return Err(ApiError::BadRequest("message is required.".into()));
    }
    let hash = hash_message(&request.message);
    let signature = {
        let hash = hash.clone();
        blocking(move || signer::sign(&key.shares, key.threshold, &hash))
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?
    };
    Ok(Json(SignatureResponse {
        r: format!("{:064x}", signature.r),
        s: format!("{:064x}", signature.s),
        message_hash: hash.iter().map(|b| format!("{b:02x}")).collect(),
    }))
}

async fn verify(
    State(service): State<KeyService>,
    Path(id): Path<Uuid>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let key = service.find(&id).ok_or(ApiError::NotFound)?;
    let (Some(r), Some(s)) = (parse_hex(&request.r), parse_hex(&request.s)) else {
        return Err(ApiError::BadRequest("r and s must be hex-encoded.".into()));
    };
    let valid = blocking(move || {
        signer::verify(
            &key.shares[0].public_key,
            &hash_message(&request.message),
            &EcdsaSignature { r, s },
        )
    })
    .await;
    Ok(Json(VerifyResponse { valid }))
}

fn parse_hex(text: &str) -> Option<BigUint> {
    if text.is_empty() || text.len() > 64 {
        return None;
    }
    BigUint::parse_bytes(text.as_bytes(), 16)
}
