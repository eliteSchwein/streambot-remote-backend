use redis::AsyncCommands;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    error::AppError,
    routes::streambot::{load_moderator_map, moderator_map_contains},
    session::Session,
    state::AppState,
};

pub const DASHBOARD_SECTIONS: [&str; 10] = [
    "music",
    "giveaway",
    "interactions",
    "auto_macros",
    "macros",
    "channel_points",
    "rotating_scene",
    "audio",
    "obs",
    "yolobox",
];

#[derive(sqlx::FromRow)]
struct InstanceRow {
    id: Uuid,
    streamer_id: Uuid,
    name: String,
    streamer_login: String,
    streamer_display_name: String,
}

pub(crate) async fn websocket_instances(app: &AppState, session: &Session) -> Result<Value, AppError> {
    let rows: Vec<InstanceRow> = sqlx::query_as(
        r#"
        SELECT i.id, i.streamer_id, i.name,
               s.login AS streamer_login, s.display_name AS streamer_display_name
        FROM streambot_instances i
        JOIN streamers s ON s.id=i.streamer_id
        ORDER BY s.display_name, i.name
        "#,
    ).fetch_all(&app.db).await?;
    let connections = app.streambot_connections.read().await;
    let mut output = Vec::new();
    for row in rows {
        if let Some(role) = access_role(app, session, row.streamer_id, row.id).await? {
            output.push(json!({
                "id": row.id,
                "streamer_id": row.streamer_id,
                "name": row.name,
                "streamer_login": row.streamer_login,
                "streamer_display_name": row.streamer_display_name,
                "role": role,
                "online": connections.contains_key(&row.id),
            }));
        }
    }
    Ok(Value::Array(output))
}

pub(crate) async fn websocket_dashboard(app: &AppState, session: &Session, instance_id: Uuid) -> Result<Value, AppError> {
    let role = require_access(app, session, instance_id).await?;
    let mut conn = app.valkey.get_multiplexed_async_connection().await?;
    let mut sections = Map::new();
    for section in DASHBOARD_SECTIONS {
        let raw: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:{section}")).await?;
        sections.insert(section.to_owned(), raw.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or(Value::Null));
    }
    let updated_at: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:updated_at")).await?;
    let version: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:version")).await?;
    let connections_raw: Option<String> = conn.get(format!("streambot:{instance_id}:dashboard:connections")).await?;
    let connections = connections_raw.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or(Value::Null);
    Ok(json!({
        "instance_id": instance_id,
        "role": role,
        "online": app.streambot_connections.read().await.contains_key(&instance_id),
        "updated_at": updated_at,
        "version": version,
        "connections": connections,
        "sections": sections,
    }))
}


pub(crate) async fn websocket_dashboard_action(app: &AppState, session: &Session, instance_id: Uuid, section: &str, action: &str, payload: Value, request_id: Uuid) -> Result<(), AppError> {
    require_access(app, session, instance_id).await?;
    if !valid_dashboard_section(section) { return Err(AppError::NotFound); }
    if action.trim().is_empty() { return Err(AppError::BadRequest("action cannot be empty".into())); }
    let sender = app.streambot_connections.read().await.get(&instance_id).cloned()
        .ok_or_else(|| AppError::BadRequest("Streambot instance is offline".into()))?;
    let command = json!({
        "type":"dashboard_action",
        "request_id":request_id,
        "section":section,
        "action":action,
        "payload":payload,
        "requested_by":{"twitch_user_id":session.twitch_user_id,"login":session.login}
    }).to_string();
    sender.send(command).await.map_err(|_| AppError::BadRequest("Streambot instance disconnected".into()))?;
    Ok(())
}

pub fn valid_dashboard_section(section: &str) -> bool {
    DASHBOARD_SECTIONS.contains(&section)
}

async fn instance_streamer_id(app: &AppState, instance_id: Uuid) -> Result<Uuid, AppError> {
    sqlx::query_scalar("SELECT streamer_id FROM streambot_instances WHERE id=$1")
        .bind(instance_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(AppError::NotFound)
}

pub(crate) async fn require_access(app: &AppState, session: &Session, instance_id: Uuid) -> Result<String, AppError> {
    let streamer_id = instance_streamer_id(app, instance_id).await?;
    access_role(app, session, streamer_id, instance_id).await?.ok_or(AppError::Forbidden)
}

async fn access_role(
    app: &AppState,
    session: &Session,
    streamer_id: Uuid,
    instance_id: Uuid,
) -> Result<Option<String>, AppError> {
    if session.owner_streamer_ids.contains(&streamer_id) {
        return Ok(Some("owner".into()));
    }
    let moderators = load_moderator_map(app, instance_id).await?;
    if moderator_map_contains(&moderators, &session.twitch_user_id) {
        return Ok(Some("mod".into()));
    }
    Ok(None)
}
