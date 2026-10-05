
use axum::{
    Json,
    extract::{Path as AxumPath, Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::HeaderMap,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256};
use tokio::{sync::mpsc, time::{Duration, Instant, MissedTickBehavior}};
use uuid::Uuid;

use crate::{
    error::AppError,
    routes::{
        api::{websocket_create_instance, websocket_delete_instance, websocket_me, websocket_streamers, websocket_update_user_settings, websocket_user_settings},
        kofi::{websocket_delete_kofi_settings, websocket_kofi_settings, websocket_save_kofi_settings},
        mod_panel::{valid_dashboard_section, websocket_dashboard, websocket_dashboard_action,
        websocket_instances},
    },
    session::{Session, get_session, random_token},
    state::AppState,
};

const REGISTRATION_TTL_SECONDS: u64 = 600;
const MAX_PIN_ATTEMPTS: i64 = 5;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub name: String,
    pub twitch_login: String,
    pub twitch_user_id: String,
    pub streamer_id: Uuid,
    pub pin: String,
    pub pin_hash: String,
}

#[derive(Deserialize)]
pub struct StartRegistrationRequest {
    pub name: String,
    pub twitch_login: String,
}

#[derive(Serialize)]
pub struct StartRegistrationResponse {
    pub pairing_id: Uuid,
    pub twitch_login: String,
    pub expires_in: u64,
}

pub async fn registration_start(
    State(state): State<AppState>,
    Json(body): Json<StartRegistrationRequest>,
) -> Result<Json<StartRegistrationResponse>, AppError> {
    let name = body.name.trim();
    if name.is_empty() { return Err(AppError::BadRequest("name cannot be empty".into())); }
    let twitch_login = body.twitch_login.trim().trim_start_matches('@').to_lowercase();
    if twitch_login.is_empty() || !twitch_login.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AppError::BadRequest("twitch_login is invalid".into()));
    }

    let owner: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, twitch_user_id, login FROM streamers WHERE LOWER(login)=LOWER($1)"
    ).bind(&twitch_login).fetch_optional(&state.db).await?;
    let (streamer_id, twitch_user_id, canonical_login) = owner.ok_or_else(||
        AppError::BadRequest("this Twitch user has not logged into the cloud yet".into())
    )?;

    let pairing_id = Uuid::new_v4();
    let pin = format!("{:06}", rand::rng().random_range(0..1_000_000u32));
    let request = RegistrationRequest {
        name: name.to_owned(),
        twitch_login: canonical_login.clone(),
        twitch_user_id: twitch_user_id.clone(),
        streamer_id,
        pin_hash: sha256(&pin),
        pin: pin.clone(),
    };

    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let key = format!("streambot_registration:{pairing_id}");
    let _: () = conn.set_ex(&key, serde_json::to_string(&request).map_err(|e| AppError::Internal(e.into()))?, REGISTRATION_TTL_SECONDS).await?;
    let user_key = format!("streambot_registration_user:{twitch_user_id}");
    let _: usize = conn.sadd(&user_key, pairing_id.to_string()).await?;
    let _: bool = conn.expire(&user_key, REGISTRATION_TTL_SECONDS as i64).await?;

    notify_user(&state, &twitch_user_id, json!({
        "type": "notify_streambot_registration",
        "status": "pending",
        "pairing_id": pairing_id,
        "name": name,
        "twitch_login": canonical_login,
        "pin": pin,
        "expires_in": REGISTRATION_TTL_SECONDS,
    })).await;

    tracing::info!(%pairing_id, name=%name, twitch_login=%twitch_login, "created PIN Streambot registration");
    Ok(Json(StartRegistrationResponse { pairing_id, twitch_login, expires_in: REGISTRATION_TTL_SECONDS }))
}

#[derive(Deserialize)]
pub struct VerifyRegistrationRequest { pub pairing_id: Uuid, pub pin: String }

#[derive(Serialize)]
pub struct VerifyRegistrationResponse {
    pub streamer_id: Uuid,
    pub instance_id: Uuid,
    pub name: String,
    pub token: String,
}

pub async fn registration_verify(
    State(state): State<AppState>,
    Json(body): Json<VerifyRegistrationRequest>,
) -> Result<Json<VerifyRegistrationResponse>, AppError> {
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let key = format!("streambot_registration:{}", body.pairing_id);
    let raw: Option<String> = conn.get(&key).await?;
    let request: RegistrationRequest = serde_json::from_str(&raw.ok_or_else(|| AppError::BadRequest("registration expired or does not exist".into()))?)
        .map_err(|e| AppError::Internal(e.into()))?;

    let attempts_key = format!("streambot_registration_attempts:{}", body.pairing_id);
    let attempts: i64 = conn.incr(&attempts_key, 1).await?;
    if attempts == 1 { let _: bool = conn.expire(&attempts_key, REGISTRATION_TTL_SECONDS as i64).await?; }
    if attempts > MAX_PIN_ATTEMPTS {
        let _: () = conn.del(&key).await?;
        return Err(AppError::BadRequest("too many invalid PIN attempts; start registration again".into()));
    }
    if sha256(body.pin.trim()) != request.pin_hash {
        tracing::warn!(pairing_id=%body.pairing_id, attempts, "Streambot registration PIN rejected");
        return Err(AppError::Unauthorized);
    }

    let token = random_token(32);
    let token_hash = sha256(&token);
    let instance_id = Uuid::new_v4();
    sqlx::query("INSERT INTO streambot_instances (id, streamer_id, name, token_hash) VALUES ($1,$2,$3,$4)")
        .bind(instance_id).bind(request.streamer_id).bind(&request.name).bind(token_hash).execute(&state.db).await?;

    let _: () = conn.del(&key).await?;
    let _: () = conn.del(&attempts_key).await?;
    let user_key = format!("streambot_registration_user:{}", request.twitch_user_id);
    let _: usize = conn.srem(&user_key, body.pairing_id.to_string()).await?;

    notify_user(&state, &request.twitch_user_id, json!({
        "type": "notify_streambot_registration",
        "status": "completed",
        "pairing_id": body.pairing_id,
        "instance_id": instance_id,
        "streamer_id": request.streamer_id,
        "name": request.name,
    })).await;
    notify_user(&state, &request.twitch_user_id, json!({
        "type":"notify_instance_created",
        "instance": {
            "id":instance_id,
            "streamer_id":request.streamer_id,
            "name":request.name,
            "online":false
        }
    })).await;

    tracing::info!(pairing_id=%body.pairing_id, %instance_id, streamer_id=%request.streamer_id, "Streambot registration completed by PIN");
    Ok(Json(VerifyRegistrationResponse { streamer_id: request.streamer_id, instance_id, name: request.name, token }))
}

#[derive(Deserialize)]
pub struct RegistrationStatusQuery { pub pairing_id: Uuid }
#[derive(Serialize)]
pub struct RegistrationStatusResponse { pub pairing_id: Uuid, pub status: String }

pub async fn registration_status(State(state): State<AppState>, Query(query): Query<RegistrationStatusQuery>) -> Result<Json<RegistrationStatusResponse>, AppError> {
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let exists: bool = conn.exists(format!("streambot_registration:{}", query.pairing_id)).await?;
    Ok(Json(RegistrationStatusResponse { pairing_id: query.pairing_id, status: if exists { "pending" } else { "expired_or_completed" }.into() }))
}

pub async fn ws_user(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let session = get_session(&state, &headers).await?;
    Ok(ws.on_upgrade(move |socket| handle_user_socket(state, socket, session)))
}

async fn handle_user_socket(state: AppState, socket: WebSocket, session: Session) {
    let twitch_user_id = session.twitch_user_id.clone();
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(32);
    state.user_connections.write().await.entry(twitch_user_id.clone()).or_default().push(tx);

    let _ = sender.send(Message::Text(json!({"type":"connected","scope":"user"}).to_string().into())).await;
    if let Ok(user) = websocket_me(&state, &session).await {
        let _ = sender.send(Message::Text(json!({"type":"notify_user_update","user":user}).to_string().into())).await;
    }
    if let Ok(settings) = websocket_user_settings(&state, &session).await {
        let _ = sender.send(Message::Text(json!({"type":"notify_user_settings_update","settings":settings}).to_string().into())).await;
    }
    if let Ok(streamers) = websocket_streamers(&state, &session).await {
        let _ = sender.send(Message::Text(json!({"type":"notify_streamers_update","streamers":streamers}).to_string().into())).await;
    }
    if let Ok(instances) = websocket_instances(&state, &session).await {
        let _ = sender.send(Message::Text(json!({"type":"notify_instances_update","instances":instances}).to_string().into())).await;
    }
    if let Ok(integrations) = websocket_kofi_settings(&state, &session).await {
        let data = integrations
            .as_array()
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(Value::Null);
        let _ = sender.send(Message::Text(json!({
            "type":"notify_kofi_settings_update",
            "data":data,
            "integrations":integrations
        }).to_string().into())).await;
    }
    if let Ok(mut conn) = state.valkey.get_multiplexed_async_connection().await {
        let ids: Vec<String> = conn.smembers(format!("streambot_registration_user:{twitch_user_id}")).await.unwrap_or_default();
        for id in ids {
            if let Ok(Some(raw)) = conn.get::<_, Option<String>>(format!("streambot_registration:{id}")).await {
                if let Ok(req) = serde_json::from_str::<RegistrationRequest>(&raw) {
                    let msg = json!({"type":"notify_streambot_registration","status":"pending","pairing_id":id,"name":req.name,"twitch_login":req.twitch_login,"pin":req.pin,"expires_in":REGISTRATION_TTL_SECONDS}).to_string();
                    let _ = sender.send(Message::Text(msg.into())).await;
                }
            }
        }
    }

    let send_task = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if sender.send(Message::Text(text.into())).await.is_err() { break; }
        }
    });
    while let Some(message) = receiver.next().await {
        match message {
            Ok(Message::Text(text)) => {
                match handle_user_message(&state, &session, text.as_str()).await {
                    Ok(Some(reply)) => {
                        notify_user(&state, &twitch_user_id, reply).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let reply = json!({"type":"notify_error","error":error.to_string()}).to_string();
                        if let Some(list) = state.user_connections.read().await.get(&twitch_user_id) {
                            if let Some(tx) = list.last() { let _ = tx.try_send(reply); }
                        }
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Binary(_)) | Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
        }
    }
    send_task.abort();
    let mut connections = state.user_connections.write().await;
    let remove_user = if let Some(list) = connections.get_mut(&twitch_user_id) {
        list.retain(|s| !s.is_closed());
        list.is_empty()
    } else {
        false
    };
    if remove_user { connections.remove(&twitch_user_id); }
}


pub async fn ws_instance(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(instance_id): AxumPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let session = get_session(&state, &headers).await?;

    // Authorize before upgrading. websocket_dashboard performs the same owner/mod
    // access check used by the panel and also gives us the initial state.
    let initial_dashboard = websocket_dashboard(&state, &session, instance_id).await?;
    Ok(ws.on_upgrade(move |socket| handle_instance_socket(state, socket, session, instance_id, initial_dashboard)))
}

async fn handle_instance_socket(
    state: AppState,
    socket: WebSocket,
    session: Session,
    instance_id: Uuid,
    initial_dashboard: Value,
) {
    let twitch_user_id = session.twitch_user_id.clone();
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(64);

    state.instance_connections.write().await
        .entry(instance_id)
        .or_default()
        .entry(twitch_user_id.clone())
        .or_default()
        .push(tx);

    tracing::info!(%instance_id, twitch_user_id=%twitch_user_id, "instance panel websocket connected");

    if sender.send(Message::Text(json!({
        "type":"connected",
        "scope":"instance",
        "instance_id":instance_id
    }).to_string().into())).await.is_err() {
        remove_instance_connection(&state, instance_id, &twitch_user_id).await;
        return;
    }

    let _ = sender.send(Message::Text(json!({
        "type":"notify_dashboard_snapshot",
        "data":initial_dashboard
    }).to_string().into())).await;

    if let Ok(mut conn) = state.valkey.get_multiplexed_async_connection().await {
        let bytes: Option<Vec<u8>> = conn.get(format!("streambot:{instance_id}:yolobox_preview:data")).await.unwrap_or(None);
        if let Some(bytes) = bytes {
            let mime: Option<String> = conn.get(format!("streambot:{instance_id}:yolobox_preview:mime")).await.unwrap_or(None);
            let _ = sender.send(Message::Text(json!({
                "type":"notify_yolobox_preview",
                "instance_id":instance_id,
                "mime":mime.unwrap_or_else(|| "image/jpeg".into()),
                "data":BASE64_STANDARD.encode(bytes),
            }).to_string().into())).await;
        }
    }

    // Every instance websocket owns its own Tokio send task/queue. A slow or noisy
    // instance therefore cannot block another instance's frontend updates.
    let send_task = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if sender.send(Message::Text(text.into())).await.is_err() { break; }
        }
    });

    while let Some(message) = receiver.next().await {
        match message {
            Ok(Message::Text(text)) => {
                match handle_instance_message(&state, &session, instance_id, text.as_str()).await {
                    Ok(Some(reply)) => {
                        notify_instance_user(&state, instance_id, &twitch_user_id, reply).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        notify_instance_user(&state, instance_id, &twitch_user_id, json!({
                            "type":"notify_error",
                            "instance_id":instance_id,
                            "error":error.to_string()
                        })).await;
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Binary(_)) | Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
        }
    }

    send_task.abort();
    remove_instance_connection(&state, instance_id, &twitch_user_id).await;
    tracing::info!(%instance_id, twitch_user_id=%twitch_user_id, "instance panel websocket disconnected");
}

async fn handle_instance_message(
    state: &AppState,
    session: &Session,
    instance_id: Uuid,
    text: &str,
) -> Result<Option<Value>, AppError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|_| AppError::BadRequest("websocket message must be valid JSON".into()))?;
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");

    match kind {
        "dashboard_action" => {
            let section = value.get("section").and_then(Value::as_str)
                .ok_or_else(|| AppError::BadRequest("section is required".into()))?;
            let action = value.get("action").and_then(Value::as_str)
                .ok_or_else(|| AppError::BadRequest("action is required".into()))?;
            let payload = value.get("payload").cloned().unwrap_or(Value::Null);
            let request_id = value.get("request_id").and_then(Value::as_str)
                .and_then(|v| Uuid::parse_str(v).ok()).unwrap_or_else(Uuid::new_v4);

            // Re-check access for every mutation so a socket that lost moderator
            // access cannot keep controlling the instance until it reconnects.
            websocket_dashboard_action(state, session, instance_id, section, action, payload, request_id).await?;
            Ok(Some(json!({
                "type":"notify_dashboard_action_accepted",
                "instance_id":instance_id,
                "section":section,
                "action":action,
                "request_id":request_id
            })))
        }
        "resync" => {
            let dashboard = websocket_dashboard(state, session, instance_id).await?;
            Ok(Some(json!({"type":"notify_dashboard_snapshot","data":dashboard,"source":"resync"})))
        }
        _ => Err(AppError::BadRequest("unknown instance websocket message type".into())),
    }
}


async fn handle_user_message(state: &AppState, session: &Session, text: &str) -> Result<Option<Value>, AppError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|_| AppError::BadRequest("websocket message must be valid JSON".into()))?;
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    match kind {
        "update_user_settings" => {
            let language = value.get("language").and_then(Value::as_str);
            let dashboard_layouts = value.get("dashboard_layouts");
            let settings = websocket_update_user_settings(state, session, language, dashboard_layouts).await?;
            Ok(Some(json!({"type":"notify_user_settings_update","settings":settings,"source":"mutation"})))
        }
        "save_kofi_settings" => {
            let streamer_id = parse_uuid_field(&value, "streamer_id")?;
            let verification_token = value.get("verification_token").and_then(Value::as_str);
            let relay_urls = value.get("relay_urls");
            let integration = websocket_save_kofi_settings(
                state,
                session,
                streamer_id,
                verification_token,
                relay_urls,
            ).await?;
            let integrations = websocket_kofi_settings(state, session).await?;
            Ok(Some(json!({
                "type":"notify_kofi_settings_update",
                "data":integration,
                "integrations":integrations,
                "event":"saved"
            })))
        }
        "delete_kofi_settings" => {
            let streamer_id = parse_uuid_field(&value, "streamer_id")?;
            websocket_delete_kofi_settings(state, session, streamer_id).await?;
            let integrations = websocket_kofi_settings(state, session).await?;
            let data = integrations
                .as_array()
                .and_then(|items| items.first())
                .cloned()
                .unwrap_or(Value::Null);
            Ok(Some(json!({
                "type":"notify_kofi_settings_update",
                "data":data,
                "integrations":integrations,
                "deleted_streamer_id":streamer_id,
                "event":"deleted"
            })))
        }
        "create_instance" => {
            let streamer_id = parse_uuid_field(&value, "streamer_id")?;
            let name = value.get("name").and_then(Value::as_str)
                .ok_or_else(|| AppError::BadRequest("name is required".into()))?;
            let instance = websocket_create_instance(state, session, streamer_id, name).await?;
            let instances = websocket_instances(state, session).await?;
            Ok(Some(json!({"type":"notify_instances_update","instances":instances,"created":instance,"event":"created"})))
        }
        "delete_instance" => {
            let streamer_id = parse_uuid_field(&value, "streamer_id")?;
            let instance_id = parse_uuid_field(&value, "instance_id")?;

            // Capture moderators before deleting cache/state so their open panels can
            // immediately remove the instance too. websocket_delete_instance itself
            // enforces owner-only access.
            let moderators = load_moderator_map(state, instance_id).await.unwrap_or_else(|_| json!([]));
            let mut affected_users = moderator_ids(&moderators);
            affected_users.push(session.twitch_user_id.clone());
            affected_users.sort();
            affected_users.dedup();

            websocket_delete_instance(state, session, streamer_id, instance_id).await?;

            let deleted = json!({
                "type":"notify_instance_deleted",
                "instance_id":instance_id,
                "streamer_id":streamer_id
            });
            notify_instance(state, instance_id, deleted.clone()).await;
            notify_users(state, affected_users, deleted).await;

            // Drop the local Streambot command channel and all per-instance viewer
            // channels. Dropping the senders causes their websocket tasks to finish.
            state.streambot_connections.write().await.remove(&instance_id);
            state.instance_connections.write().await.remove(&instance_id);
            purge_instance_cache(state, instance_id).await;

            let instances = websocket_instances(state, session).await?;
            Ok(Some(json!({
                "type":"notify_instances_update",
                "instances":instances,
                "deleted_instance_id":instance_id,
                "event":"deleted"
            })))
        }
        // Recovery only. Normal panel operation must never poll or expose reload buttons.
        // A reconnect automatically performs the same full bootstrap, so this is mainly
        // useful for debugging clients that cannot reconnect their websocket cleanly.
        "resync" => {
            let user = websocket_me(state, session).await?;
            let settings = websocket_user_settings(state, session).await?;
            let streamers = websocket_streamers(state, session).await?;
            let instances = websocket_instances(state, session).await?;
            let kofi_integrations = websocket_kofi_settings(state, session).await?;
            Ok(Some(json!({
                "type":"notify_resync",
                "user":user,
                "settings":settings,
                "streamers":streamers,
                "instances":instances,
                "kofi_integrations":kofi_integrations
            })))
        }
        _ => Err(AppError::BadRequest("unknown user websocket message type".into())),
    }
}


async fn purge_instance_cache(state: &AppState, instance_id: Uuid) {
    let mut conn = match state.valkey.get_multiplexed_async_connection().await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!(%instance_id, error=?err, "failed to open Valkey connection while deleting instance");
            return;
        }
    };

    let mut keys = vec![
        format!("streambot:{instance_id}:online"),
        format!("streambot:{instance_id}:last_message"),
        format!("streambot:{instance_id}:moderators"),
        format!("streambot:{instance_id}:panel_state"),
        format!("streambot:{instance_id}:dashboard:updated_at"),
        format!("streambot:{instance_id}:dashboard:version"),
        format!("streambot:{instance_id}:dashboard:connections"),
        format!("streambot:{instance_id}:yolobox_preview:data"),
        format!("streambot:{instance_id}:yolobox_preview:mime"),
    ];
    for section in crate::routes::mod_panel::DASHBOARD_SECTIONS {
        keys.push(format!("streambot:{instance_id}:dashboard:{section}"));
    }

    if let Err(err) = redis::cmd("DEL").arg(keys).query_async::<()>(&mut conn).await {
        tracing::warn!(%instance_id, error=?err, "failed to purge deleted instance cache");
    }
}

fn parse_uuid_field(value: &Value, field: &str) -> Result<Uuid, AppError> {
    let raw = value.get(field).and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest(format!("{field} is required")))?;
    Uuid::parse_str(raw).map_err(|_| AppError::BadRequest(format!("{field} is invalid")))
}

async fn notify_user(state: &AppState, twitch_user_id: &str, value: Value) {
    let text = value.to_string();
    let mut connections = state.user_connections.write().await;
    if let Some(list) = connections.get_mut(twitch_user_id) {
        list.retain(|sender| !sender.is_closed());
        for sender in list.iter() { let _ = sender.try_send(text.clone()); }
    }
}

async fn notify_users(state: &AppState, mut user_ids: Vec<String>, value: Value) {
    user_ids.sort();
    user_ids.dedup();
    for user_id in user_ids { notify_user(state, &user_id, value.clone()).await; }
}

async fn notify_instance(state: &AppState, instance_id: Uuid, value: Value) {
    let text = value.to_string();
    let senders: Vec<mpsc::Sender<String>> = {
        let connections = state.instance_connections.read().await;
        connections.get(&instance_id)
            .map(|users| users.values().flat_map(|list| list.iter().cloned()).collect())
            .unwrap_or_default()
    };
    for sender in senders {
        let _ = sender.try_send(text.clone());
    }
    cleanup_instance_connections(state, instance_id).await;
}

async fn notify_instance_user(state: &AppState, instance_id: Uuid, twitch_user_id: &str, value: Value) {
    let text = value.to_string();
    let senders: Vec<mpsc::Sender<String>> = {
        let connections = state.instance_connections.read().await;
        connections.get(&instance_id)
            .and_then(|users| users.get(twitch_user_id))
            .map(|list| list.to_vec())
            .unwrap_or_default()
    };
    for sender in senders {
        let _ = sender.try_send(text.clone());
    }
    cleanup_instance_connections(state, instance_id).await;
}

async fn cleanup_instance_connections(state: &AppState, instance_id: Uuid) {
    let mut connections = state.instance_connections.write().await;
    let remove_instance = if let Some(users) = connections.get_mut(&instance_id) {
        users.retain(|_, list| {
            list.retain(|sender| !sender.is_closed());
            !list.is_empty()
        });
        users.is_empty()
    } else {
        false
    };
    if remove_instance {
        connections.remove(&instance_id);
    }
}

async fn remove_instance_connection(state: &AppState, instance_id: Uuid, twitch_user_id: &str) {
    let mut connections = state.instance_connections.write().await;
    let remove_instance = if let Some(users) = connections.get_mut(&instance_id) {
        if let Some(list) = users.get_mut(twitch_user_id) {
            list.retain(|sender| !sender.is_closed());
            if list.is_empty() {
                users.remove(twitch_user_id);
            }
        }
        users.is_empty()
    } else {
        false
    };
    if remove_instance {
        connections.remove(&instance_id);
    }
}

async fn revoke_instance_user(state: &AppState, instance_id: Uuid, twitch_user_id: &str) {
    notify_instance_user(state, instance_id, twitch_user_id, json!({
        "type":"notify_instance_access_revoked",
        "instance_id":instance_id
    })).await;
    let mut connections = state.instance_connections.write().await;
    let remove_instance = if let Some(users) = connections.get_mut(&instance_id) {
        users.remove(twitch_user_id);
        users.is_empty()
    } else {
        false
    };
    if remove_instance {
        connections.remove(&instance_id);
    }
}

fn moderator_ids(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    match value {
        Value::Array(items) => for item in items {
            if let Some(id) = item.get("twitch_user_id").or_else(|| item.get("user_id")).or_else(|| item.get("id")).and_then(Value::as_str) { out.push(id.to_owned()); }
        },
        Value::Object(map) => for (key, item) in map {
            if let Some(id) = item.get("twitch_user_id").or_else(|| item.get("user_id")).or_else(|| item.get("id")).and_then(Value::as_str) { out.push(id.to_owned()); }
            else if !key.is_empty() { out.push(key.clone()); }
        },
        _ => {}
    }
    out.sort(); out.dedup(); out
}

#[derive(Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

pub async fn ws_streambot(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let token = query.token
        .or_else(|| bearer_token(&headers))
        .ok_or(AppError::Unauthorized)?;

    let hash = sha256(&token);
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
        "UPDATE streambot_instances SET last_seen_at=NOW() WHERE token_hash=$1 RETURNING streamer_id, id, name"
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await?;
    let (streamer_id, instance_id, name) = row.ok_or(AppError::Unauthorized)?;

    Ok(ws.on_upgrade(move |socket| handle_socket(state, socket, streamer_id, instance_id, name)))
}

async fn handle_socket(
    state: AppState,
    socket: WebSocket,
    streamer_id: Uuid,
    instance_id: Uuid,
    name: String,
) {
    tracing::info!(%streamer_id, %instance_id, %name, "Streambot websocket connected");
    const HEARTBEAT_INTERVAL_SECONDS: u64 = 10;
    const HEARTBEAT_TIMEOUT_SECONDS: u64 = 25;

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(64);
    state.streambot_connections.write().await.insert(instance_id, tx.clone());
    if let Err(error) = mark_instance_alive(&state, instance_id).await {
        tracing::debug!(%instance_id, error = ?error, "failed to mark Streambot instance alive");
    }
    notify_instance_presence(&state, streamer_id, instance_id, true).await;

    let connected = json!({
        "type": "connected",
        "streamer_id": streamer_id,
        "instance_id": instance_id,
        "name": name,
    }).to_string();
    if sender.send(Message::Text(connected.into())).await.is_err() {
        state.streambot_connections.write().await.remove(&instance_id);
        return;
    }

    let send_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_seen = Instant::now();

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if last_seen.elapsed() >= Duration::from_secs(HEARTBEAT_TIMEOUT_SECONDS) {
                    tracing::warn!(%instance_id, timeout_seconds = HEARTBEAT_TIMEOUT_SECONDS, "Streambot websocket heartbeat timed out");
                    break;
                }
                if tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            message = receiver.next() => {
                let Some(message) = message else { break; };
                match message {
                    Ok(Message::Text(text)) => {
                        last_seen = Instant::now();
                        if let Err(error) = mark_instance_alive(&state, instance_id).await {
                            tracing::debug!(%instance_id, error = ?error, "failed to refresh Streambot liveness");
                        }
                        if let Err(error) = handle_streambot_message(&state, streamer_id, instance_id, text.as_str()).await {
                            tracing::warn!(%instance_id, error = ?error, "invalid Streambot websocket message");
                        }
                    }
                    Ok(Message::Binary(_)) | Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                        last_seen = Instant::now();
                        if let Err(error) = mark_instance_alive(&state, instance_id).await {
                            tracing::debug!(%instance_id, error = ?error, "failed to refresh Streambot liveness");
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                }
            }
        }
    }

    send_task.abort();
    state.streambot_connections.write().await.remove(&instance_id);
    if let Ok(mut conn) = state.valkey.get_multiplexed_async_connection().await {
        let _: redis::RedisResult<usize> = conn.del(format!("streambot:{instance_id}:online")).await;
    }
    notify_instance_presence(&state, streamer_id, instance_id, false).await;
    tracing::info!(%instance_id, "Streambot websocket disconnected");
}

async fn mark_instance_alive(state: &AppState, instance_id: Uuid) -> Result<(), AppError> {
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let _: () = conn.set_ex(format!("streambot:{instance_id}:online"), "1", 30).await?;
    Ok(())
}

async fn handle_streambot_message(
    state: &AppState,
    streamer_id: Uuid,
    instance_id: Uuid,
    text: &str,
) -> Result<(), AppError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|_| AppError::BadRequest("websocket message must be valid JSON".into()))?;
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;

    match kind {
        "moderators" => {
            let moderators = value.get("moderators").cloned().unwrap_or_else(|| json!([]));
            let old_raw: Option<String> = conn.get(format!("streambot:{instance_id}:moderators")).await?;
            let old_value = old_raw.and_then(|raw| serde_json::from_str::<Value>(&raw).ok()).unwrap_or_else(|| json!([]));
            let old_ids = moderator_ids(&old_value);
            let new_ids = moderator_ids(&moderators);
            let _: () = conn.set(
                format!("streambot:{instance_id}:moderators"),
                serde_json::to_string(&moderators).map_err(|e| AppError::Internal(e.into()))?,
            ).await?;

            let owner: Option<String> = sqlx::query_scalar("SELECT twitch_user_id FROM streamers WHERE id=$1")
                .bind(streamer_id).fetch_optional(&state.db).await?;
            let mut recipients = old_ids.clone(); recipients.extend(new_ids.clone());
            if let Some(owner) = owner.clone() { recipients.push(owner); }
            notify_users(state, recipients, json!({
                "type":"notify_moderators_update",
                "instance_id":instance_id,
                "moderators":moderators
            })).await;
            notify_instance(state, instance_id, json!({
                "type":"notify_moderators_update",
                "instance_id":instance_id,
                "moderators":moderators
            })).await;

            for id in new_ids.iter().filter(|id| !old_ids.contains(id)) {
                notify_user(state, id, json!({"type":"notify_instance_access_granted","instance_id":instance_id,"streamer_id":streamer_id,"role":"mod"})).await;
            }
            for id in old_ids.iter().filter(|id| !new_ids.contains(id)) {
                notify_user(state, id, json!({"type":"notify_instance_access_revoked","instance_id":instance_id,"streamer_id":streamer_id})).await;
                revoke_instance_user(state, instance_id, id).await;
            }
            tracing::debug!(%instance_id, "updated Valkey moderator map");
        }
        "snapshot" | "state" => {
            let data = value.get("data").cloned().unwrap_or(Value::Null);
            let _: () = conn.set(
                format!("streambot:{instance_id}:panel_state"),
                serde_json::to_string(&data).map_err(|e| AppError::Internal(e.into()))?,
            ).await?;

            // Streambot v2 sends a dedicated, already-trimmed remote dashboard under
            // data.dashboard. Prefer that shape over the legacy top-level/status payload.
            let dashboard = data.get("dashboard").unwrap_or(&data);
            if let Value::Object(map) = dashboard {
                for (section, section_data) in map {
                    if valid_dashboard_section(section) {
                        let sanitized = sanitize_dashboard_section(section, section_data);
                        let _: () = conn.set(
                            format!("streambot:{instance_id}:dashboard:{section}"),
                            serde_json::to_string(&sanitized).map_err(|e| AppError::Internal(e.into()))?,
                        ).await?;
                    }
                }

                if let Some(version) = map.get("version") {
                    let _: () = conn.set(
                        format!("streambot:{instance_id}:dashboard:version"),
                        version.to_string(),
                    ).await?;
                }
                if let Some(connections) = map.get("connections") {
                    let _: () = conn.set(
                        format!("streambot:{instance_id}:dashboard:connections"),
                        serde_json::to_string(connections).map_err(|e| AppError::Internal(e.into()))?,
                    ).await?;
                }
            }
            let updated_at = dashboard.get("updated_at")
                .map(Value::to_string)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            let _: () = conn.set(format!("streambot:{instance_id}:dashboard:updated_at"), updated_at).await?;
            notify_dashboard_viewers(state, streamer_id, instance_id, None).await;
        }
        "dashboard_snapshot" => {
            let data = value.get("data").cloned().unwrap_or(Value::Null);
            let map = data.as_object().ok_or_else(|| AppError::BadRequest("dashboard_snapshot.data must be an object".into()))?;
            for (section, section_data) in map {
                if !valid_dashboard_section(section) { continue; }
                let sanitized = sanitize_dashboard_section(section, section_data);
                let _: () = conn.set(
                    format!("streambot:{instance_id}:dashboard:{section}"),
                    serde_json::to_string(&sanitized).map_err(|e| AppError::Internal(e.into()))?,
                ).await?;
            }
            let _: () = conn.set(format!("streambot:{instance_id}:dashboard:updated_at"), chrono::Utc::now().to_rfc3339()).await?;
            notify_dashboard_viewers(state, streamer_id, instance_id, None).await;
        }
        "dashboard_update" => {
            let section = value.get("section").and_then(Value::as_str).unwrap_or("");
            if !valid_dashboard_section(section) {
                return Err(AppError::BadRequest("unknown dashboard section".into()));
            }
            let data = value.get("data").cloned().unwrap_or(Value::Null);
            let sanitized = sanitize_dashboard_section(section, &data);
            let _: () = conn.set(
                format!("streambot:{instance_id}:dashboard:{section}"),
                serde_json::to_string(&sanitized).map_err(|e| AppError::Internal(e.into()))?,
            ).await?;
            let _: () = conn.set(format!("streambot:{instance_id}:dashboard:updated_at"), chrono::Utc::now().to_rfc3339()).await?;
            notify_dashboard_viewers(state, streamer_id, instance_id, Some(section)).await;
        }
        "yolobox_preview" => {
            let mime = value.get("mime").and_then(Value::as_str).unwrap_or("image/jpeg");
            if mime != "image/jpeg" && mime != "image/webp" && mime != "image/png" {
                return Err(AppError::BadRequest("unsupported Yolobox preview mime type".into()));
            }
            let encoded = value.get("data").and_then(Value::as_str).ok_or_else(|| AppError::BadRequest("yolobox_preview.data is required".into()))?;
            let bytes = BASE64_STANDARD.decode(encoded).map_err(|_| AppError::BadRequest("invalid base64 Yolobox preview".into()))?;
            if bytes.len() > 2_000_000 {
                return Err(AppError::BadRequest("Yolobox preview exceeds 2 MB".into()));
            }
            let preview_b64 = encoded.to_owned();
            let _: () = conn.set_ex(format!("streambot:{instance_id}:yolobox_preview:data"), bytes, 30).await?;
            let _: () = conn.set_ex(format!("streambot:{instance_id}:yolobox_preview:mime"), mime, 30).await?;
            notify_yolobox_preview_viewers(state, streamer_id, instance_id, mime, &preview_b64).await;
        }
        "dashboard_action_result" | "action_result" => {
            let request_id = value.get("request_id").cloned().unwrap_or(Value::Null);
            let section = value.get("section").cloned().unwrap_or(Value::Null);
            let action = value.get("action").cloned().unwrap_or(Value::Null);
            let success = value.get("success").and_then(Value::as_bool).unwrap_or_else(|| value.get("error").is_none());
            let data = value.get("data").cloned().unwrap_or(Value::Null);
            let error = value.get("error").cloned().unwrap_or(Value::Null);
            notify_instance(state, instance_id, json!({
                "type":"notify_dashboard_action_result",
                "instance_id":instance_id,
                "request_id":request_id,
                "section":section,
                "action":action,
                "success":success,
                "data":data,
                "error":error
            })).await;
        }
        "hello" | "heartbeat" => {}
        _ => {
            let _: () = conn.set(
                format!("streambot:{instance_id}:last_message"),
                text,
            ).await?;
        }
    }

    let _: () = conn.set_ex(format!("streambot:{instance_id}:online"), "1", 30).await?;
    sqlx::query("UPDATE streambot_instances SET last_seen_at=NOW() WHERE id=$1 AND streamer_id=$2")
        .bind(instance_id)
        .bind(streamer_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

pub fn moderator_map_contains(value: &Value, twitch_user_id: &str) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| {
            item.get("twitch_user_id").or_else(|| item.get("user_id")).or_else(|| item.get("id"))
                .and_then(Value::as_str) == Some(twitch_user_id)
        }),
        Value::Object(map) => {
            if map.contains_key(twitch_user_id) { return true; }
            map.values().any(|item| {
                item.get("twitch_user_id").or_else(|| item.get("user_id")).or_else(|| item.get("id"))
                    .and_then(Value::as_str) == Some(twitch_user_id)
            })
        }
        _ => false,
    }
}

pub async fn load_moderator_map(state: &AppState, instance_id: Uuid) -> Result<Value, AppError> {
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let raw: Option<String> = conn.get(format!("streambot:{instance_id}:moderators")).await?;
    match raw {
        Some(raw) => serde_json::from_str(&raw).map_err(|e| AppError::Internal(e.into())),
        None => Ok(json!([])),
    }
}

fn sanitize_dashboard_section(section: &str, value: &Value) -> Value {
    match section {
        "macros" => {
            let Some(macros) = value.as_object() else { return json!({}); };
            let mut out = serde_json::Map::new();
            for (key, macro_value) in macros {
                let name = macro_value.get("name").and_then(Value::as_str).unwrap_or(key);
                out.insert(key.clone(), json!({ "name": name }));
            }
            Value::Object(out)
        }
        "music" => {
            let Some(obj) = value.as_object() else { return value.clone(); };
            let mut out = obj.clone();
            out.remove("path");
            if let Some(Value::Object(thumbnail)) = out.get_mut("thumbnail") {
                thumbnail.remove("path");
            }
            Value::Object(out)
        }
        "auto_macros" => {
            let Some(items) = value.as_array() else { return value.clone(); };
            Value::Array(items.iter().map(|item| {
                let Some(obj) = item.as_object() else { return item.clone(); };
                let mut out = obj.clone();
                out.remove("file");
                Value::Object(out)
            }).collect())
        }
        "channel_points" => strip_keys_recursive(value, &["file"]),
        _ => value.clone(),
    }
}

fn strip_keys_recursive(value: &Value, keys: &[&str]) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, child) in map {
                if keys.iter().any(|blocked| key == blocked) { continue; }
                out.insert(key.clone(), strip_keys_recursive(child, keys));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(|item| strip_keys_recursive(item, keys)).collect()),
        _ => value.clone(),
    }
}


async fn notify_instance_presence(state: &AppState, streamer_id: Uuid, instance_id: Uuid, online: bool) {
    let owner: Option<String> = sqlx::query_scalar("SELECT twitch_user_id FROM streamers WHERE id=$1")
        .bind(streamer_id).fetch_optional(&state.db).await.ok().flatten();
    let mut recipients = Vec::new();
    if let Some(owner) = owner { recipients.push(owner); }
    if let Ok(Value::Array(items)) = load_moderator_map(state, instance_id).await {
        for item in items {
            if let Some(id) = item.get("twitch_user_id").or_else(|| item.get("user_id")).or_else(|| item.get("id")).and_then(Value::as_str) { recipients.push(id.to_owned()); }
        }
    }
    recipients.sort(); recipients.dedup();
    let message = json!({"type":"notify_instance_presence","instance_id":instance_id,"online":online});
    for user_id in recipients { notify_user(state, &user_id, message.clone()).await; }
    notify_instance(state, instance_id, message).await;
}

async fn notify_dashboard_viewers(state: &AppState, _streamer_id: Uuid, instance_id: Uuid, section: Option<&str>) {
    let mut conn = match state.valkey.get_multiplexed_async_connection().await { Ok(c) => c, Err(_) => return };
    let message = if let Some(section) = section {
        let raw: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:{section}")).await.ok().flatten();
        let data = raw.and_then(|v| serde_json::from_str::<Value>(&v).ok()).unwrap_or(Value::Null);
        json!({"type":"notify_dashboard_update","instance_id":instance_id,"section":section,"data":data})
    } else {
        let mut sections = serde_json::Map::new();
        for section in crate::routes::mod_panel::DASHBOARD_SECTIONS {
            let raw: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:{section}")).await.ok().flatten();
            sections.insert(section.to_string(), raw.and_then(|v| serde_json::from_str::<Value>(&v).ok()).unwrap_or(Value::Null));
        }
        let updated_at: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:updated_at")).await.ok().flatten();
        let version: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:version")).await.ok().flatten();
        let connections_raw: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:connections")).await.ok().flatten();
        let connections = connections_raw.and_then(|v| serde_json::from_str::<Value>(&v).ok()).unwrap_or(Value::Null);
        json!({"type":"notify_dashboard_snapshot","data":{
            "instance_id":instance_id,
            "online":true,
            "updated_at":updated_at,
            "version":version,
            "connections":connections,
            "sections":Value::Object(sections)
        }})
    };
    notify_instance(state, instance_id, message).await;
}


async fn notify_yolobox_preview_viewers(state: &AppState, _streamer_id: Uuid, instance_id: Uuid, mime: &str, data: &str) {
    notify_instance(state, instance_id, json!({
        "type":"notify_yolobox_preview",
        "instance_id":instance_id,
        "mime":mime,
        "data":data
    })).await;
}

pub fn sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
}
