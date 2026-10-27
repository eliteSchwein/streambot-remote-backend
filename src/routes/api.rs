use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{error::AppError, models::StreamerSummary, session::random_token, state::AppState};

#[derive(Serialize)]
pub struct InstanceAuthResponse {
    streamer_id: Uuid,
    instance_id: Uuid,
    name: String,
}

#[derive(Debug, Deserialize)]
pub struct TwitchRefreshRequest {
    pub refresh_token: String,
    #[serde(default)]
    pub r#type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TwitchRefreshResponse {
    client_id: String,
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    obtainment_timestamp: i64,
    scope: Vec<String>,
    auth_type: String,
}

async fn authenticate_instance(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, Uuid, String), AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("instance authentication rejected: missing bearer token");
            AppError::Unauthorized
        })?;

    let hash = format!("{:x}", Sha256::digest(auth.as_bytes()));
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
        "UPDATE streambot_instances SET last_seen_at=NOW() WHERE token_hash=$1 RETURNING streamer_id, id, name"
    )
        .bind(hash)
        .fetch_optional(&state.db)
        .await?;

    row.ok_or_else(|| {
        tracing::warn!("instance authentication rejected: bearer token did not match an instance");
        AppError::Unauthorized
    })
}

pub async fn instance_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InstanceAuthResponse>, AppError> {
    let (streamer_id, instance_id, name) = authenticate_instance(&state, &headers).await?;

    tracing::info!(streamer_id = %streamer_id, instance_id = %instance_id, name = %name, "Streambot instance authenticated");
    Ok(Json(InstanceAuthResponse { streamer_id, instance_id, name }))
}

fn normalize_refresh_type(value: &str) -> Result<&'static str, AppError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "control" | "bot" => Ok("control"),
        "message" | "message_bot" | "message-bot" => Ok("message"),
        _ => Err(AppError::BadRequest("type must be control or message".into())),
    }
}

async fn refresh_twitch_token(
    state: AppState,
    auth_type: &str,
    body: TwitchRefreshRequest,
) -> Result<Json<TwitchRefreshResponse>, AppError> {
    let refresh_token = body.refresh_token.trim();
    if refresh_token.is_empty() {
        return Err(AppError::BadRequest("refresh_token is required".into()));
    }

    let auth_type = normalize_refresh_type(auth_type)?;
    let token = state
        .twitch
        .refresh_token(refresh_token)
        .await
        .map_err(AppError::Internal)?;

    tracing::info!(
        auth_type = auth_type,
        "refreshed Twitch access token"
    );

    Ok(Json(TwitchRefreshResponse {
        client_id: state.config.twitch_client_id.clone(),
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        obtainment_timestamp: chrono::Utc::now().timestamp_millis(),
        scope: token.scope,
        auth_type: auth_type.to_string(),
    }))
}

pub async fn twitch_refresh_control(
    State(state): State<AppState>,
    Json(body): Json<TwitchRefreshRequest>,
) -> Result<Json<TwitchRefreshResponse>, AppError> {
    refresh_twitch_token(state, "control", body).await
}

pub async fn twitch_refresh_message(
    State(state): State<AppState>,
    Json(body): Json<TwitchRefreshRequest>,
) -> Result<Json<TwitchRefreshResponse>, AppError> {
    refresh_twitch_token(state, "message", body).await
}

pub async fn twitch_refresh(
    State(state): State<AppState>,
    Json(body): Json<TwitchRefreshRequest>,
) -> Result<Json<TwitchRefreshResponse>, AppError> {
    let auth_type = body.r#type.as_deref().ok_or_else(|| {
        AppError::BadRequest("type is required and must be control or message".into())
    })?;
    let auth_type = normalize_refresh_type(auth_type)?;
    refresh_twitch_token(state, auth_type, body).await
}



fn require_owner(session: &crate::session::Session, streamer_id: Uuid) -> Result<(), AppError> {
    if session.owner_streamer_ids.contains(&streamer_id) { Ok(()) } else { Err(AppError::Forbidden) }
}

pub(crate) fn normalize_language(value: &str) -> Result<String, AppError> {
    let language = value.trim().to_lowercase();
    if language.is_empty() || language.len() > 16 {
        return Err(AppError::BadRequest("language must be between 1 and 16 characters".into()));
    }
    if !language.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(AppError::BadRequest("language must be a language tag such as en, de, or de-de".into()));
    }
    Ok(language)
}

pub(crate) async fn websocket_me(state: &AppState, session: &crate::session::Session) -> Result<serde_json::Value, AppError> {
    let language: String = sqlx::query_scalar(
        "SELECT COALESCE((SELECT language FROM user_settings WHERE twitch_user_id=$1), 'en')"
    )
        .bind(&session.twitch_user_id)
        .fetch_one(&state.db)
        .await?;
    Ok(serde_json::json!({
        "twitch_user_id": session.twitch_user_id,
        "login": session.login,
        "display_name": session.display_name,
        "streamer_ids": session.streamer_ids,
        "owner_streamer_ids": session.owner_streamer_ids,
        "language": language,
    }))
}

pub(crate) async fn websocket_user_settings(state: &AppState, session: &crate::session::Session) -> Result<serde_json::Value, AppError> {
    let row: Option<(String, Value)> = sqlx::query_as(
        "SELECT language, dashboard_layouts FROM user_settings WHERE twitch_user_id=$1"
    )
        .bind(&session.twitch_user_id)
        .fetch_optional(&state.db)
        .await?;
    let (language, dashboard_layouts) = row.unwrap_or_else(|| ("en".to_string(), serde_json::json!({})));
    Ok(serde_json::json!({
        "language": language,
        "dashboard_layouts": dashboard_layouts,
    }))
}

pub(crate) async fn websocket_update_user_settings(
    state: &AppState,
    session: &crate::session::Session,
    language: Option<&str>,
    dashboard_layouts: Option<&Value>,
) -> Result<serde_json::Value, AppError> {
    if language.is_none() && dashboard_layouts.is_none() {
        return Err(AppError::BadRequest("at least one setting is required".into()));
    }

    let language = match language {
        Some(value) => Some(normalize_language(value)?),
        None => None,
    };

    if let Some(layouts) = dashboard_layouts {
        if !layouts.is_object() {
            return Err(AppError::BadRequest("dashboard_layouts must be a JSON object".into()));
        }
    }

    sqlx::query(
        r#"
        INSERT INTO user_settings (twitch_user_id, language, dashboard_layouts)
        VALUES ($1, COALESCE($2, 'en'), COALESCE($3, '{}'::jsonb))
        ON CONFLICT (twitch_user_id) DO UPDATE SET
            language = COALESCE($2, user_settings.language),
            dashboard_layouts = COALESCE($3, user_settings.dashboard_layouts),
            updated_at = NOW()
        "#,
    )
        .bind(&session.twitch_user_id)
        .bind(language.as_deref())
        .bind(dashboard_layouts.cloned())
        .execute(&state.db)
        .await?;

    tracing::info!(
        twitch_user_id=%session.twitch_user_id,
        language=?language,
        dashboard_layouts_updated=dashboard_layouts.is_some(),
        "updated cloud user settings over websocket"
    );

    websocket_user_settings(state, session).await
}

pub(crate) async fn websocket_streamers(state: &AppState, session: &crate::session::Session) -> Result<serde_json::Value, AppError> {
    if session.streamer_ids.is_empty() { return Ok(serde_json::json!([])); }
    let rows = sqlx::query_as::<_, StreamerSummary>(r#"
        SELECT s.id, s.login, s.display_name, s.profile_image_url,
               FALSE AS bot_connected,
               FALSE AS message_bot_connected,
               (SELECT COUNT(*) FROM streambot_instances i WHERE i.streamer_id=s.id) AS instance_count,
               CASE WHEN s.id = ANY($2) THEN 'owner' ELSE 'mod' END AS role
        FROM streamers s WHERE s.id = ANY($1)
        ORDER BY s.display_name
    "#).bind(&session.streamer_ids).bind(&session.owner_streamer_ids).fetch_all(&state.db).await?;
    Ok(serde_json::to_value(rows).map_err(|e| AppError::Internal(e.into()))?)
}


pub(crate) async fn websocket_create_instance(state: &AppState, session: &crate::session::Session, streamer_id: Uuid, name: &str) -> Result<serde_json::Value, AppError> {
    require_owner(session, streamer_id)?;
    let name = name.trim();
    if name.is_empty() { return Err(AppError::BadRequest("name cannot be empty".into())); }
    let token = random_token(32);
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let instance_id = Uuid::new_v4();
    sqlx::query("INSERT INTO streambot_instances (id, streamer_id, name, token_hash) VALUES ($1,$2,$3,$4)")
        .bind(instance_id).bind(streamer_id).bind(name).bind(hash).execute(&state.db).await?;
    Ok(serde_json::json!({"id":instance_id,"name":name,"token":token,"streamer_id":streamer_id}))
}

pub(crate) async fn websocket_delete_instance(
    state: &AppState,
    session: &crate::session::Session,
    instance_id: Uuid,
) -> Result<Uuid, AppError> {
    let streamer_id: Uuid = sqlx::query_scalar(
        "SELECT streamer_id FROM streambot_instances WHERE id=$1"
    )
        .bind(instance_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    // Only the owner of the streamer that owns this instance may delete it.
    // Moderator access to the instance is intentionally not sufficient.
    require_owner(session, streamer_id)?;

    let result = sqlx::query("DELETE FROM streambot_instances WHERE id=$1")
        .bind(instance_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(streamer_id)
}
