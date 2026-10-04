use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;
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

pub async fn instance_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InstanceAuthResponse>, AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("instance-auth rejected: missing bearer token");
            AppError::Unauthorized
        })?;

    let hash = format!("{:x}", Sha256::digest(auth.as_bytes()));
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
        "UPDATE streambot_instances SET last_seen_at=NOW() WHERE token_hash=$1 RETURNING streamer_id, id, name"
    )
        .bind(hash)
        .fetch_optional(&state.db)
        .await?;
    let (streamer_id, instance_id, name) = row.ok_or_else(|| {
        tracing::warn!("instance-auth rejected: bearer token did not match an instance");
        AppError::Unauthorized
    })?;

    tracing::info!(streamer_id = %streamer_id, instance_id = %instance_id, name = %name, "Streambot instance authenticated");
    Ok(Json(InstanceAuthResponse { streamer_id, instance_id, name }))
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

pub(crate) async fn websocket_delete_instance(state: &AppState, session: &crate::session::Session, streamer_id: Uuid, instance_id: Uuid) -> Result<(), AppError> {
    require_owner(session, streamer_id)?;
    let result = sqlx::query("DELETE FROM streambot_instances WHERE streamer_id=$1 AND id=$2")
        .bind(streamer_id)
        .bind(instance_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}
