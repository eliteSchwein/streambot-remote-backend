use axum::http::{HeaderMap, header::COOKIE};
use rand::{Rng, RngCore, distr::Alphanumeric};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub twitch_user_id: String,
    pub login: String,
    pub display_name: String,
    pub streamer_ids: Vec<Uuid>,
    pub owner_streamer_ids: Vec<Uuid>,
}

pub fn random_token(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn random_state() -> String {
    rand::rng().sample_iter(&Alphanumeric).take(48).map(char::from).collect()
}

pub async fn create_session(state: &AppState, session: &Session) -> Result<String, AppError> {
    let token = random_token(32);
    let key = format!("session:{token}");
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let payload = serde_json::to_string(session).map_err(|e| AppError::Internal(e.into()))?;
    let _: () = conn.set_ex(key, payload, state.config.session_ttl_seconds).await?;
    Ok(token)
}

pub async fn get_session(state: &AppState, headers: &HeaderMap) -> Result<Session, AppError> {
    let token = cookie_value(headers, &state.config.session_cookie_name).ok_or(AppError::Unauthorized)?;
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let payload: Option<String> = conn.get(format!("session:{token}")).await?;
    let payload = payload.ok_or(AppError::Unauthorized)?;
    serde_json::from_str(&payload).map_err(|e| AppError::Internal(e.into()))
}

pub async fn delete_session(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    if let Some(token) = cookie_value(headers, &state.config.session_cookie_name) {
        let mut conn = state.valkey.get_multiplexed_async_connection().await?;
        let _: () = conn.del(format!("session:{token}")).await?;
    }
    Ok(())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|pair| {
        let mut parts = pair.trim().splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(k), Some(v)) if k == name => Some(v.to_owned()),
            _ => None,
        }
    })
}
