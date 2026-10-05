use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use axum::{
    Form, Json,
    extract::{Path, State},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{
    error::AppError,
    session::Session,
    state::AppState,
};

const MAX_RELAY_URLS: usize = 10;
const MAX_RELAY_URL_LEN: usize = 2048;
const DEDUPE_TTL_SECONDS: u64 = 604_800;

#[derive(sqlx::FromRow)]
struct KofiIntegrationRow {
    streamer_id: Uuid,
    webhook_id: Uuid,
    verification_token_hash: String,
    relay_urls: Value,
}

fn require_owner(session: &Session, streamer_id: Uuid) -> Result<(), AppError> {
    if session.owner_streamer_ids.contains(&streamer_id) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn hash_token(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn webhook_url(state: &AppState, webhook_id: Uuid) -> String {
    format!(
        "{}/webhooks/kofi/{webhook_id}",
        state.config.app_public_url.trim_end_matches('/')
    )
}

fn is_forbidden_literal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip == Ipv6Addr::LOCALHOST
        }
    }
}

fn normalize_relay_urls(value: Option<&Value>) -> Result<Vec<String>, AppError> {
    let Some(value) = value else { return Ok(Vec::new()); };
    let Some(items) = value.as_array() else {
        return Err(AppError::BadRequest("relay_urls must be an array".into()));
    };
    if items.len() > MAX_RELAY_URLS {
        return Err(AppError::BadRequest(format!("at most {MAX_RELAY_URLS} relay URLs are allowed")));
    }

    let mut output = Vec::new();
    for item in items {
        let raw = item.as_str().ok_or_else(|| AppError::BadRequest("relay_urls must contain strings".into()))?.trim();
        if raw.is_empty() || raw.len() > MAX_RELAY_URL_LEN {
            return Err(AppError::BadRequest("relay URL is empty or too long".into()));
        }
        let parsed = Url::parse(raw).map_err(|_| AppError::BadRequest("relay URL is invalid".into()))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(AppError::BadRequest("relay URLs must use http or https".into()));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(AppError::BadRequest("relay URLs must not contain credentials".into()));
        }
        let host = parsed.host_str().ok_or_else(|| AppError::BadRequest("relay URL must contain a host".into()))?;
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
            return Err(AppError::BadRequest("relay URL host is not allowed".into()));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_forbidden_literal_ip(ip) {
                return Err(AppError::BadRequest("relay URL may not target a private/local address".into()));
            }
        }
        output.push(parsed.to_string());
    }
    output.sort();
    output.dedup();
    Ok(output)
}

async fn relay_event(url: String, payload: Value) {
    // Relay hostnames are deliberately not resolved for validation here.
    // This keeps split-DNS/public hostnames usable while normalize_relay_urls()
    // still rejects localhost and private/local literal IP targets.
    if normalize_relay_urls(Some(&json!([url.clone()]))).is_err() {
        tracing::warn!(%url, "blocked Ko-fi relay destination");
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%url, error=?error, "failed to create Ko-fi relay HTTP client");
            return;
        }
    };

    let relay_data = match serde_json::to_string(&payload) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%url, error=?error, "failed to serialize Ko-fi relay payload");
            return;
        }
    };

    match client
        .post(&url)
        .header("X-StreamDing-Webhook", "kofi")
        .form(&[("data", relay_data)])
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            tracing::debug!(%url, status=%response.status(), "relayed Ko-fi webhook");
        }
        Ok(response) => {
            let status = response.status();
            let response_body = match response.text().await {
                Ok(body) => {
                    const MAX_LOG_BODY_BYTES: usize = 4096;
                    if body.len() > MAX_LOG_BODY_BYTES {
                        let mut truncated = body;
                        truncated.truncate(MAX_LOG_BODY_BYTES);
                        format!("{truncated}… [truncated]")
                    } else {
                        body
                    }
                }
                Err(error) => format!("<failed to read response body: {error}>")
            };

            tracing::warn!(
                %url,
                %status,
                response_body=%response_body,
                "Ko-fi relay returned non-success status"
            );
        }
        Err(error) => {
            tracing::warn!(%url, error=?error, "Ko-fi relay request failed");
        }
    }
}

pub(crate) async fn websocket_kofi_settings(
    state: &AppState,
    session: &Session,
) -> Result<Value, AppError> {
    if session.owner_streamer_ids.is_empty() {
        return Ok(json!([]));
    }

    // Generate a stable Ko-fi webhook URL as soon as an owner has at least one
    // linked streamer-owned StreamDing instance. The verification token can be
    // configured later; an empty hash means the integration is not active yet.
    let eligible_streamer_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT streamer_id
        FROM streambot_instances
        WHERE streamer_id = ANY($1)
        ORDER BY streamer_id
        "#,
    )
    .bind(&session.owner_streamer_ids)
    .fetch_all(&state.db)
    .await?;

    for streamer_id in &eligible_streamer_ids {
        sqlx::query(
            r#"
            INSERT INTO kofi_integrations (
                streamer_id,
                webhook_id,
                verification_token_hash,
                relay_urls
            )
            VALUES ($1, $2, '', '[]'::jsonb)
            ON CONFLICT (streamer_id) DO NOTHING
            "#,
        )
        .bind(streamer_id)
        .bind(Uuid::new_v4())
        .execute(&state.db)
        .await?;
    }

    if eligible_streamer_ids.is_empty() {
        return Ok(json!([]));
    }

    let rows: Vec<KofiIntegrationRow> = sqlx::query_as(
        r#"
        SELECT streamer_id, webhook_id, verification_token_hash, relay_urls
        FROM kofi_integrations
        WHERE streamer_id = ANY($1)
        ORDER BY streamer_id
        "#,
    )
    .bind(&eligible_streamer_ids)
    .fetch_all(&state.db)
    .await?;

    let result = rows.into_iter().map(|row| json!({
        "streamer_id": row.streamer_id,
        "webhook_id": row.webhook_id,
        "webhook_url": webhook_url(state, row.webhook_id),
        "configured": !row.verification_token_hash.is_empty(),
        "verification_token_configured": !row.verification_token_hash.is_empty(),
        "relay_urls": row.relay_urls,
    })).collect::<Vec<_>>();

    Ok(Value::Array(result))
}

pub(crate) async fn websocket_save_kofi_settings(
    state: &AppState,
    session: &Session,
    streamer_id: Uuid,
    verification_token: Option<&str>,
    relay_urls: Option<&Value>,
) -> Result<Value, AppError> {
    require_owner(session, streamer_id)?;

    let instance_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM streambot_instances WHERE streamer_id=$1"
    )
    .bind(streamer_id)
    .fetch_one(&state.db)
    .await?;
    if instance_count < 1 {
        return Err(AppError::BadRequest(
            "Ko-fi can only be configured after at least one streamer-owned instance is linked".into()
        ));
    }

    let existing: Option<(Uuid, String, Value)> = sqlx::query_as(
        "SELECT webhook_id, verification_token_hash, relay_urls FROM kofi_integrations WHERE streamer_id=$1"
    )
    .bind(streamer_id)
    .fetch_optional(&state.db)
    .await?;

    let token_hash = match verification_token.map(str::trim).filter(|v| !v.is_empty()) {
        Some(token) => hash_token(token),
        None => existing.as_ref()
            .map(|(_, hash, _)| hash.clone())
            .filter(|hash| !hash.is_empty())
            .ok_or_else(|| AppError::BadRequest("verification_token is required when enabling Ko-fi".into()))?,
    };

    let relays = match relay_urls {
        Some(value) => normalize_relay_urls(Some(value))?,
        None => existing.as_ref()
            .and_then(|(_, _, value)| serde_json::from_value::<Vec<String>>(value.clone()).ok())
            .unwrap_or_default(),
    };
    let relay_json = serde_json::to_value(&relays).map_err(|e| AppError::Internal(e.into()))?;
    let webhook_id = existing.as_ref().map(|(id, _, _)| *id).unwrap_or_else(Uuid::new_v4);

    sqlx::query(
        r#"
        INSERT INTO kofi_integrations (streamer_id, webhook_id, verification_token_hash, relay_urls)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (streamer_id) DO UPDATE SET
            verification_token_hash=EXCLUDED.verification_token_hash,
            relay_urls=EXCLUDED.relay_urls,
            updated_at=NOW()
        "#,
    )
    .bind(streamer_id)
    .bind(webhook_id)
    .bind(token_hash)
    .bind(relay_json.clone())
    .execute(&state.db)
    .await?;

    tracing::info!(%streamer_id, relay_count=relays.len(), "updated Ko-fi webhook settings");

    Ok(json!({
        "streamer_id": streamer_id,
        "webhook_id": webhook_id,
        "webhook_url": webhook_url(state, webhook_id),
        "configured": true,
        "verification_token_configured": true,
        "relay_urls": relays,
    }))
}

pub(crate) async fn websocket_delete_kofi_settings(
    state: &AppState,
    session: &Session,
    streamer_id: Uuid,
) -> Result<(), AppError> {
    require_owner(session, streamer_id)?;
    sqlx::query("DELETE FROM kofi_integrations WHERE streamer_id=$1")
        .bind(streamer_id)
        .execute(&state.db)
        .await?;
    tracing::info!(%streamer_id, "deleted Ko-fi webhook settings");
    Ok(())
}

pub async fn webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<Uuid>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let data = form.get("data")
        .ok_or_else(|| AppError::BadRequest("missing Ko-fi data form field".into()))?;
    let payload: Value = serde_json::from_str(data)
        .map_err(|_| AppError::BadRequest("Ko-fi data field is not valid JSON".into()))?;

    let row: Option<KofiIntegrationRow> = sqlx::query_as(
        r#"
        SELECT streamer_id, webhook_id, verification_token_hash, relay_urls
        FROM kofi_integrations
        WHERE webhook_id=$1
        "#,
    )
    .bind(webhook_id)
    .fetch_optional(&state.db)
    .await?;
    let row = row.ok_or(AppError::NotFound)?;

    if row.verification_token_hash.is_empty() {
        return Err(AppError::Forbidden);
    }

    let supplied_token = payload.get("verification_token").and_then(|v| v.as_str())
        .ok_or(AppError::Forbidden)?;
    if hash_token(supplied_token) != row.verification_token_hash {
        tracing::warn!(%webhook_id, %row.streamer_id, "rejected Ko-fi webhook with invalid verification token");
        return Err(AppError::Forbidden);
    }

    // Keep the shared secret out of StreamDing instance events. Third-party relay
    // targets intentionally receive the original Ko-fi payload unchanged so existing
    // Ko-fi webhook consumers can perform their own verification-token checks.
    let mut sanitized = payload.clone();
    if let Some(obj) = sanitized.as_object_mut() {
        obj.remove("verification_token");
    }

    let message_id = sanitized.get("message_id").and_then(|v| v.as_str()).unwrap_or("").trim();
    if !message_id.is_empty() {
        let mut conn = state.valkey.get_multiplexed_async_connection().await?;
        let key = format!("kofi:{}:message:{}", row.streamer_id, message_id);
        let result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(DEDUPE_TTL_SECONDS)
            .query_async(&mut conn)
            .await?;
        if result.is_none() {
            tracing::info!(%row.streamer_id, %message_id, "ignored duplicate Ko-fi webhook");
            return Ok(Json(json!({"ok":true,"duplicate":true})));
        }
    }

    let instance_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM streambot_instances WHERE streamer_id=$1 ORDER BY created_at"
    )
    .bind(row.streamer_id)
    .fetch_all(&state.db)
    .await?;

    // The integration is only useful while the streamer has linked instances.
    // Acknowledge stale Ko-fi deliveries instead of triggering Ko-fi retries forever.
    if instance_ids.is_empty() {
        tracing::warn!(%row.streamer_id, "received Ko-fi webhook but streamer has no linked instances");
        return Ok(Json(json!({"ok":true,"delivered_instances":0,"stale":true})));
    }

    let event = json!({
        "type": "notify_kofi_event",
        "streamer_id": row.streamer_id,
        "received_at": chrono::Utc::now().to_rfc3339(),
        "data": sanitized,
    });
    let text = event.to_string();

    let instance_senders = {
        let senders = state.streambot_connections.read().await;
        instance_ids.iter()
            .filter_map(|instance_id| senders.get(instance_id).cloned().map(|sender| (*instance_id, sender)))
            .collect::<Vec<_>>()
    };
    let mut delivered_instances = 0usize;
    for (_instance_id, sender) in instance_senders {
        if sender.send(axum::extract::ws::Message::Text(text.clone().into())).await.is_ok() {
            delivered_instances += 1;
        }
    }

    let relay_urls: Vec<String> = serde_json::from_value(row.relay_urls).unwrap_or_default();
    if !relay_urls.is_empty() {
        // Forward the original Ko-fi payload (including verification_token) so
        // downstream services can validate the webhook exactly as if Ko-fi had
        // called them directly. Only StreamDing instance events are sanitized.
        for url in relay_urls {
            let relay_payload = payload.clone();
            tokio::spawn(relay_event(url, relay_payload));
        }
    }

    tracing::info!(
        streamer_id=%row.streamer_id,
        event_type=?event.get("data").and_then(|v| v.get("type")).and_then(|v| v.as_str()),
        total_instances=instance_ids.len(),
        delivered_instances,
        "accepted Ko-fi webhook"
    );

    Ok(Json(json!({
        "ok": true,
        "delivered_instances": delivered_instances,
        "total_instances": instance_ids.len(),
    })))
}
