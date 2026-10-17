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

    // Non-dashboard notify state that the cloud panel must be able to reconstruct
    // after reconnecting. Keep this separate from dashboard sections so new
    // notify payloads do not have to masquerade as cards/sections.
    let mut notifications = Map::new();
    for method in ["notify_twitch_user_list"] {
        let raw: Option<String> = conn.get(format!("streambot:{instance_id}:notify:{method}")).await?;
        if let Some(value) = raw.and_then(|v| serde_json::from_str(&v).ok()) {
            notifications.insert(method.to_owned(), value);
        }
    }

    Ok(json!({
        "instance_id": instance_id,
        "role": role,
        "online": app.streambot_connections.read().await.contains_key(&instance_id),
        "updated_at": updated_at,
        "version": version,
        "connections": connections,
        "sections": sections,
        "notifications": notifications,
    }))
}


pub(crate) async fn websocket_dashboard_action(app: &AppState, session: &Session, instance_id: Uuid, section: &str, action: &str, payload: Value, request_id: Uuid) -> Result<(), AppError> {
    let role = require_access(app, session, instance_id).await?;
    if !valid_dashboard_section(section) && section != "twitch" && section != "twitch_users" { return Err(AppError::NotFound); }
    if action.trim().is_empty() { return Err(AppError::BadRequest("action cannot be empty".into())); }

    // Promotions are intentionally not exposed through the cloud panel.
    // Adding moderators/VIPs must be done directly on Twitch/local Streambot.
    if matches!(action, "twitch_moderator" | "twitch_vip") {
        return Err(AppError::Forbidden);
    }

    // A moderator may manage normal users, but must never be able to punish or
    // demote the broadcaster/another moderator through the cloud panel. Owners
    // are not restricted by this guard.
    if role == "mod" && is_user_targeted_moderation_action(action) {
        if let Some(target) = moderation_target(&payload) {
            if target_is_protected_moderator(app, instance_id, target).await? {
                return Err(AppError::Forbidden);
            }
        }
    }
    let sender = app.streambot_connections.read().await.get(&instance_id).cloned()
        .ok_or_else(|| AppError::BadRequest("Streambot instance is offline".into()))?;
    // Backend 3.0 action_result messages only contain request_id/success/data.
    // Persist the originating section/action briefly so the cloud can restore
    // that metadata when the result comes back and the panel can route it.
    let mut conn = app.valkey.get_multiplexed_async_connection().await?;
    let request_meta = json!({"section":section,"action":action}).to_string();
    let _: () = conn.set_ex(
        format!("streambot:{instance_id}:action_request:{request_id}"),
        request_meta,
        120,
    ).await?;

    let command = json!({
        "type":"dashboard_action",
        "request_id":request_id,
        "section":section,
        "action":action,
        "payload":payload,
        "requested_by":{"twitch_user_id":session.twitch_user_id,"login":session.login}
    }).to_string();
    sender.send(axum::extract::ws::Message::Text(command.into())).await.map_err(|_| AppError::BadRequest("Streambot instance disconnected".into()))?;
    Ok(())
}

pub fn valid_dashboard_section(section: &str) -> bool {
    DASHBOARD_SECTIONS.contains(&section)
}

fn is_user_targeted_moderation_action(action: &str) -> bool {
    matches!(
        action,
        "twitch_timeout"
            | "twitch_ban"
            | "twitch_unban"
            | "twitch_warn"
            | "twitch_unmoderator"
            | "twitch_unvip"
    )
}

fn moderation_target(payload: &Value) -> Option<&str> {
    let map = payload.as_object()?;
    [
        "user_id",
        "user",
        "username",
        "login",
        "target_user_id",
        "target_user",
        "target",
    ]
    .into_iter()
    .find_map(|key| map.get(key).and_then(Value::as_str))
    .map(str::trim)
    .filter(|value| !value.is_empty())
}

fn moderator_map_matches_target(value: &Value, target: &str) -> bool {
    let target = target.trim().trim_start_matches('@');
    if target.is_empty() {
        return false;
    }

    fn item_matches(item: &Value, target: &str) -> bool {
        [
            "twitch_user_id",
            "user_id",
            "id",
            "login",
            "user_login",
            "username",
            "display_name",
        ]
        .into_iter()
        .filter_map(|key| item.get(key).and_then(Value::as_str))
        .any(|value| value.eq_ignore_ascii_case(target))
    }

    match value {
        Value::Array(items) => items.iter().any(|item| item_matches(item, target)),
        Value::Object(map) => {
            map.keys().any(|key| key.eq_ignore_ascii_case(target))
                || map.values().any(|item| item_matches(item, target))
        }
        _ => false,
    }
}

async fn target_is_protected_moderator(
    app: &AppState,
    instance_id: Uuid,
    target: &str,
) -> Result<bool, AppError> {
    let target = target.trim().trim_start_matches('@');
    if target.is_empty() {
        return Ok(false);
    }

    let owner: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT s.twitch_user_id, s.login
        FROM streambot_instances i
        JOIN streamers s ON s.id = i.streamer_id
        WHERE i.id = $1
        "#,
    )
    .bind(instance_id)
    .fetch_optional(&app.db)
    .await?;

    if let Some((owner_id, owner_login)) = owner {
        if owner_id.eq_ignore_ascii_case(target) || owner_login.eq_ignore_ascii_case(target) {
            return Ok(true);
        }
    }

    let moderators = load_moderator_map(app, instance_id).await?;
    Ok(moderator_map_matches_target(&moderators, target))
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
