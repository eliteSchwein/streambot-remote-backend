//! Webcam stream relay via MediaMTX.
//!
//! A Streambot instance can publish any number of webcams (MPEG-TS over SRT) to
//! MediaMTX, each at `live/<stream_key>`. The stream key is random per
//! (instance, camera), generated on the first start of that camera and stored in
//! `webcam_streams`, so the public viewer link of a camera stays identical
//! across sessions. The per-session publish password is random and only lives
//! in Valkey while the camera is streaming. MediaMTX authorizes every
//! publish/read through `POST /internal/mediamtx/auth`, so deleting the Valkey
//! entry immediately invalidates the viewer link.
//!
//! Valkey layout while a camera is active:
//! - `webcam:{stream_key}` = JSON `{"instance_id","camera_id","password"}`
//! - `streambot:{instance_id}:webcam:{camera_id}` = stream_key
//! - `streambot:{instance_id}:webcams` = set of active camera ids

use std::collections::HashMap;

use axum::{
    Json,
    body::Bytes,
    extract::{Path as AxumPath, Query, State, ws::Message},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use redis::{AsyncCommands, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{error::AppError, routes::streambot::notify_instance, state::AppState};

const STREAM_KEY_LEN: usize = 32;
const PUBLISH_PASSWORD_BYTES: usize = 32;
const CAMERA_ID_MAX_LEN: usize = 64;
const CAMERA_NAME_MAX_CHARS: usize = 64;

#[derive(Serialize, Deserialize)]
struct WebcamSession {
    instance_id: Uuid,
    camera_id: String,
    password: String,
}

/// Lowercase unpadded base32 of 20 cryptographically random bytes (32 chars).
fn generate_stream_key() -> String {
    let mut raw = [0u8; 20];
    rand::rng().fill_bytes(&mut raw);
    data_encoding::BASE32_NOPAD.encode(&raw).to_ascii_lowercase()
}

fn generate_publish_password() -> String {
    let mut raw = [0u8; PUBLISH_PASSWORD_BYTES];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

fn valid_stream_key(key: &str) -> bool {
    key.len() == STREAM_KEY_LEN && key.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// `^[A-Za-z0-9_-]{1,64}$`
fn valid_camera_id(camera_id: &str) -> bool {
    (1..=CAMERA_ID_MAX_LEN).contains(&camera_id.len())
        && camera_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Trimmed and capped at 64 characters.
fn normalize_camera_name(name: &str) -> String {
    name.trim().chars().take(CAMERA_NAME_MAX_CHARS).collect::<String>().trim_end().to_owned()
}

fn camera_id_field(value: &Value) -> Result<&str, AppError> {
    let camera_id = value.get("camera_id").and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("camera_id is required".into()))?;
    if !valid_camera_id(camera_id) {
        return Err(AppError::BadRequest("camera_id is invalid".into()));
    }
    Ok(camera_id)
}

fn stream_key_from_path(path: &str) -> Option<&str> {
    let key = path.strip_prefix("live/")?;
    valid_stream_key(key).then_some(key)
}

fn session_key(stream_key: &str) -> String { format!("webcam:{stream_key}") }
fn camera_index_key(instance_id: Uuid, camera_id: &str) -> String { format!("streambot:{instance_id}:webcam:{camera_id}") }
fn active_cameras_key(instance_id: Uuid) -> String { format!("streambot:{instance_id}:webcams") }

fn viewer_url(state: &AppState, stream_key: &str) -> String {
    format!("{}/live/{stream_key}", state.config.frontend_url.trim_end_matches('/'))
}

fn whep_url(state: &AppState, stream_key: &str) -> String {
    format!("{}/live/{stream_key}/whep", state.config.mediamtx_public_url)
}

/// The MediaMTX endpoints (with ports) this backend hands out, shown in the
/// panel so a wrong host/port in the environment is visible at a glance.
fn server_info(state: &AppState) -> Value {
    let config = &state.config;
    json!({
        "srt": format!("srt://{}:{}", crate::config::url_host(&config.mediamtx_srt_host), config.mediamtx_srt_port),
        "whep": config.mediamtx_public_url,
        "rtsp": format!("rtsp://{}:{}", crate::config::url_host(&config.mediamtx_rtsp_host), config.mediamtx_rtsp_port),
    })
}

/// Read-only RTSP (TCP) URL, e.g. for OBS media sources or VLC.
fn rtsp_url(state: &AppState, stream_key: &str) -> String {
    format!(
        "rtsp://{}:{}/live/{stream_key}",
        crate::config::url_host(&state.config.mediamtx_rtsp_host),
        state.config.mediamtx_rtsp_port,
    )
}

/// Upserts the camera row and returns its permanent stream key. The key is only
/// set on insert; `ON CONFLICT` keeps the existing one, which makes concurrent
/// first starts race-safe.
async fn upsert_camera(state: &AppState, instance_id: Uuid, camera_id: &str, name: &str) -> Result<String, AppError> {
    let key: String = sqlx::query_scalar(
        "INSERT INTO webcam_streams (instance_id, camera_id, name, stream_key)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (instance_id, camera_id)
         DO UPDATE SET name=EXCLUDED.name, updated_at=NOW()
         RETURNING stream_key"
    ).bind(instance_id).bind(camera_id).bind(name).bind(generate_stream_key())
        .fetch_one(&state.db).await?;
    Ok(key)
}

async fn stored_stream_key(state: &AppState, instance_id: Uuid, camera_id: &str) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar("SELECT stream_key FROM webcam_streams WHERE instance_id=$1 AND camera_id=$2")
        .bind(instance_id).bind(camera_id).fetch_optional(&state.db).await?)
}

/// Deletes the Valkey session of one camera. Returns the stream key whose
/// session existed, so the caller can kick its MediaMTX path. `fallback_key`
/// (the persisted key) covers the case where only the session entry survived.
async fn end_session(
    conn: &mut MultiplexedConnection,
    instance_id: Uuid,
    camera_id: &str,
    fallback_key: Option<String>,
) -> Result<Option<String>, AppError> {
    let indexed: Option<String> = conn.get(camera_index_key(instance_id, camera_id)).await?;
    let mut keys: Vec<String> = indexed.into_iter().chain(fallback_key).collect();
    keys.dedup();

    let mut ended = None;
    for key in keys {
        let existed: usize = conn.del(session_key(&key)).await?;
        if existed > 0 {
            ended = Some(key);
        }
    }
    let _: usize = conn.del(camera_index_key(instance_id, camera_id)).await?;
    let _: usize = conn.srem(active_cameras_key(instance_id), camera_id).await?;
    Ok(ended)
}

/// Kicks publisher and readers in the background. Credentials are already
/// gone, so any reconnect attempt is rejected by the auth hook.
fn spawn_kick(state: &AppState, key: String) {
    let state = state.clone();
    tokio::spawn(async move { kick_path_sessions(&state, &key, false).await });
}

/// Handles `{"type":"webcam_stream_start","camera_id","name"}` from a Streambot.
pub async fn start_webcam_stream(state: &AppState, instance_id: Uuid, value: &Value) -> Result<(), AppError> {
    let camera_id = camera_id_field(value)?;
    let name = normalize_camera_name(value.get("name").and_then(Value::as_str).unwrap_or(""));
    let key = upsert_camera(state, instance_id, camera_id, &name).await?;
    let password = generate_publish_password();

    let session = WebcamSession { instance_id, camera_id: camera_id.to_owned(), password: password.clone() };
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let previous_key: Option<String> = conn.get(camera_index_key(instance_id, camera_id)).await?;
    let was_active: bool = conn.exists(session_key(&key)).await?;
    let _: () = conn.set(
        session_key(&key),
        serde_json::to_string(&session).map_err(|e| AppError::Internal(e.into()))?,
    ).await?;
    let _: () = conn.set(camera_index_key(instance_id, camera_id), &key).await?;
    let _: usize = conn.sadd(active_cameras_key(instance_id), camera_id).await?;

    // A stale index pointing at another key (row removed and recreated) must
    // not leave a session behind.
    if let Some(previous_key) = previous_key.filter(|previous| *previous != key) {
        let existed: usize = conn.del(session_key(&previous_key)).await?;
        if existed > 0 {
            spawn_kick(state, previous_key);
        }
    }

    // Restart of an active camera: the old password is already invalid; kick
    // the existing publisher before handing out the new credentials so the
    // kick cannot hit the new publisher.
    if was_active {
        kick_path_sessions(state, &key, true).await;
    }

    let publish_url = format!(
        "srt://{}:{}?streamid=publish:live/{key}:{instance_id}:{password}&latency=200000&pkt_size=1316",
        crate::config::url_host(&state.config.mediamtx_srt_host),
        state.config.mediamtx_srt_port,
    );
    let credentials = json!({
        "type":"webcam_stream_credentials",
        "camera_id":camera_id,
        "stream_key":key,
        "publish_url":publish_url,
        // RTSP (TCP) publish URL for codecs MPEG-TS/SRT cannot carry to
        // MediaMTX (AV1). Same per-session credentials as the SRT URL.
        "publish_rtsp_url":format!(
            "rtsp://{instance_id}:{password}@{}:{}/live/{key}",
            crate::config::url_host(&state.config.mediamtx_rtsp_host),
            state.config.mediamtx_rtsp_port,
        ),
        "viewer_url":viewer_url(state, &key),
        "rtsp_url":rtsp_url(state, &key)
    }).to_string();

    let sender = state.streambot_connections.read().await.get(&instance_id).cloned();
    match sender {
        Some(sender) => {
            if sender.send(Message::Text(credentials.into())).await.is_err() {
                tracing::warn!(%instance_id, %camera_id, "failed to deliver webcam stream credentials");
            }
        }
        None => tracing::warn!(%instance_id, %camera_id, "no Streambot connection to deliver webcam stream credentials"),
    }

    notify_webcam_streams(state, instance_id).await;
    tracing::info!(%instance_id, %camera_id, restarted = was_active, "webcam stream session started");
    Ok(())
}

/// Handles `{"type":"webcam_stream_stop","camera_id"}`.
pub async fn stop_webcam_stream(state: &AppState, instance_id: Uuid, value: &Value) -> Result<(), AppError> {
    let camera_id = camera_id_field(value)?;
    let fallback = stored_stream_key(state, instance_id, camera_id).await?;
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    if let Some(key) = end_session(&mut conn, instance_id, camera_id, fallback).await? {
        spawn_kick(state, key);
        tracing::info!(%instance_id, %camera_id, "webcam stream session stopped");
    }
    notify_webcam_streams(state, instance_id).await;
    Ok(())
}

/// Handles `{"type":"webcam_camera_removed","camera_id"}`: stops the camera and
/// deletes its row, so the viewer link is gone for good.
pub async fn remove_webcam_camera(state: &AppState, instance_id: Uuid, value: &Value) -> Result<(), AppError> {
    let camera_id = camera_id_field(value)?;
    let fallback = stored_stream_key(state, instance_id, camera_id).await?;
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    // Kick even without an active session: nothing may keep reading the path
    // of a link that is gone for good.
    if let Some(key) = end_session(&mut conn, instance_id, camera_id, fallback.clone()).await?.or(fallback) {
        spawn_kick(state, key);
    }
    sqlx::query("DELETE FROM webcam_streams WHERE instance_id=$1 AND camera_id=$2")
        .bind(instance_id).bind(camera_id).execute(&state.db).await?;
    notify_webcam_streams(state, instance_id).await;
    tracing::info!(%instance_id, %camera_id, "webcam camera removed");
    Ok(())
}

/// Stops every active camera of an instance (Streambot disconnect, instance
/// deletion). Rows are kept; on instance deletion they are already gone via
/// `ON DELETE CASCADE`, which is why the Valkey set is the source of truth here.
pub async fn stop_all_webcam_streams(state: &AppState, instance_id: Uuid) -> Result<(), AppError> {
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let camera_ids: Vec<String> = conn.smembers(active_cameras_key(instance_id)).await?;
    for camera_id in &camera_ids {
        if let Some(key) = end_session(&mut conn, instance_id, camera_id, None).await? {
            spawn_kick(state, key);
        }
    }
    let _: usize = conn.del(active_cameras_key(instance_id)).await?;
    if !camera_ids.is_empty() {
        tracing::info!(%instance_id, cameras = camera_ids.len(), "webcam stream sessions stopped");
    }
    notify_webcam_streams(state, instance_id).await;
    Ok(())
}

async fn notify_webcam_streams(state: &AppState, instance_id: Uuid) {
    let message = webcam_state_message(state, instance_id).await;
    notify_instance(state, instance_id, message).await;
}

/// Current `notify_webcam_streams` state: all cameras of the instance.
pub async fn webcam_state_message(state: &AppState, instance_id: Uuid) -> Value {
    let rows: Vec<(String, String, String)> = match sqlx::query_as(
        "SELECT camera_id, name, stream_key FROM webcam_streams WHERE instance_id=$1 ORDER BY name, camera_id"
    ).bind(instance_id).fetch_all(&state.db).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%instance_id, error=?error, "failed to load webcam streams");
            Vec::new()
        }
    };

    let mut conn = state.valkey.get_multiplexed_async_connection().await.ok();
    let mut streams = Vec::with_capacity(rows.len());
    for (camera_id, name, key) in rows {
        let active = match conn.as_mut() {
            Some(conn) => conn.exists::<_, bool>(session_key(&key)).await.unwrap_or(false),
            None => false,
        };
        streams.push(json!({
            "camera_id":camera_id,
            "name":name,
            "viewer_url":viewer_url(state, &key),
            "whep_url":whep_url(state, &key),
            "rtsp_url":rtsp_url(state, &key),
            "active":active
        }));
    }
    json!({
        "type":"notify_webcam_streams",
        "instance_id":instance_id,
        "streams":streams,
        "server":server_info(state)
    })
}

/// Kicks the MediaMTX sessions of `live/<key>`: the publisher and, unless
/// `publisher_only`, all readers.
async fn kick_path_sessions(state: &AppState, key: &str, publisher_only: bool) {
    let api = &state.config.mediamtx_api_url;
    let path_info: Value = match state.http.get(format!("{api}/v3/paths/get/live/{key}")).send().await {
        Ok(response) if response.status().is_success() => match response.json().await {
            Ok(value) => value,
            Err(_) => return,
        },
        // 404: nobody is publishing or reading.
        _ => return,
    };

    let mut sessions: Vec<&Value> = Vec::new();
    if let Some(source) = path_info.get("source").filter(|v| !v.is_null()) {
        sessions.push(source);
    }
    if !publisher_only && let Some(readers) = path_info.get("readers").and_then(Value::as_array) {
        sessions.extend(readers.iter());
    }

    for session in sessions {
        let kind = session.get("type").and_then(Value::as_str).unwrap_or("");
        let Some(id) = session.get("id").and_then(Value::as_str) else { continue; };
        let endpoint = match kind {
            "srtConn" => "srtconns",
            "webRTCSession" => "webrtcsessions",
            "rtspSession" => "rtspsessions",
            "rtspsSession" => "rtspssessions",
            "rtmpConn" => "rtmpconns",
            "rtmpsConn" => "rtmpsconns",
            _ => continue,
        };
        if let Err(error) = state.http.post(format!("{api}/v3/{endpoint}/kick/{id}")).send().await {
            tracing::debug!(%key, %kind, %id, error=?error, "failed to kick MediaMTX session");
        }
    }
}

/// `POST /internal/mediamtx/auth?secret=...` — MediaMTX `authMethod: http` hook.
pub async fn mediamtx_auth(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> StatusCode {
    let secret_ok = query.get("secret").is_some_and(|secret| {
        bool::from(secret.as_bytes().ct_eq(state.config.mediamtx_auth_secret.as_bytes()))
    });
    if !secret_ok {
        return StatusCode::UNAUTHORIZED;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::UNAUTHORIZED;
    };
    let field = |name: &str| request.get(name).and_then(Value::as_str).unwrap_or("");
    let action = field("action");
    if action != "publish" && action != "read" {
        return StatusCode::UNAUTHORIZED;
    }
    let Some(key) = stream_key_from_path(field("path")) else {
        return StatusCode::UNAUTHORIZED;
    };

    let session = match load_session(&state, key).await {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::UNAUTHORIZED,
        Err(error) => {
            tracing::warn!(error=?error, "MediaMTX auth lookup failed");
            return StatusCode::UNAUTHORIZED;
        }
    };

    if action == "publish" {
        let user_ok = field("user") == session.instance_id.hyphenated().to_string();
        let password_ok = bool::from(field("password").as_bytes().ct_eq(session.password.as_bytes()));
        if !(user_ok && password_ok) {
            tracing::warn!(instance_id=%session.instance_id, camera_id=%session.camera_id, ip=%field("ip"), "rejected webcam publish with invalid credentials");
            return StatusCode::UNAUTHORIZED;
        }
    }
    StatusCode::OK
}

async fn load_session(state: &AppState, key: &str) -> Result<Option<WebcamSession>, AppError> {
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let raw: Option<String> = conn.get(session_key(key)).await?;
    Ok(raw.and_then(|raw| serde_json::from_str(&raw).ok()))
}

/// `GET /api/v1/live/{stream_key}` — public viewer status.
pub async fn live_status(
    State(state): State<AppState>,
    AxumPath(key): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    if !valid_stream_key(&key) || load_session(&state, &key).await?.is_none() {
        return Err(AppError::NotFound);
    }
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM webcam_streams WHERE stream_key=$1")
        .bind(&key).fetch_optional(&state.db).await?;
    let api = &state.config.mediamtx_api_url;
    let online = match state.http.get(format!("{api}/v3/paths/get/live/{key}")).send().await {
        Ok(response) if response.status().is_success() => response
            .json::<Value>()
            .await
            .ok()
            .and_then(|value| value.get("ready").and_then(Value::as_bool))
            .unwrap_or(false),
        _ => false,
    };
    Ok(Json(json!({
        "online":online,
        "name":name.unwrap_or_default(),
        "whep_url":whep_url(&state, &key),
        "rtsp_url":rtsp_url(&state, &key)
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_key_shape() {
        let key = generate_stream_key();
        assert_eq!(key.len(), 32);
        assert!(valid_stream_key(&key));
        assert_ne!(key, generate_stream_key());
        assert_eq!(stream_key_from_path(&format!("live/{key}")), Some(key.as_str()));
        assert_eq!(stream_key_from_path(&format!("live/{key}x")), None);
    }

    #[test]
    fn camera_id_validation() {
        assert!(valid_camera_id("a"));
        assert!(valid_camera_id("cam_01-Front"));
        assert!(valid_camera_id(&"x".repeat(64)));
        assert!(!valid_camera_id(""));
        assert!(!valid_camera_id(&"x".repeat(65)));
        assert!(!valid_camera_id("cam 1"));
        assert!(!valid_camera_id("cam/1"));
        assert!(!valid_camera_id("cam:1"));
        assert!(!valid_camera_id("kamera\u{e4}"));
        assert!(camera_id_field(&json!({})).is_err());
        assert!(camera_id_field(&json!({"camera_id":5})).is_err());
        assert_eq!(camera_id_field(&json!({"camera_id":"cam1"})).ok(), Some("cam1"));
    }

    #[test]
    fn camera_name_normalization() {
        assert_eq!(normalize_camera_name("  Front cam \n"), "Front cam");
        assert_eq!(normalize_camera_name(""), "");
        let long = "\u{e4}".repeat(80);
        assert_eq!(normalize_camera_name(&long).chars().count(), 64);
    }
}
