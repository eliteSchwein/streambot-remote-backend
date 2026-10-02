use axum::{extract::{Query, State}, http::{HeaderMap, HeaderValue, header::SET_COOKIE}, response::{IntoResponse, Redirect, Response}};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AppError, session::{Session, create_session, delete_session, random_state, random_token}, state::AppState};

const BOT_SCOPES: &[&str] = &[
    "bits:read",
    "channel:bot",
    "channel:edit:commercial",
    "channel:manage:ads",
    "channel:manage:broadcast",
    "channel:manage:moderators",
    "channel:manage:polls",
    "channel:manage:predictions",
    "channel:manage:raids",
    "channel:manage:redemptions",
    "channel:manage:schedule",
    "channel:manage:videos",
    "channel:manage:vips",
    "channel:moderate",
    "channel:read:ads",
    "channel:read:charity",
    "channel:read:editors",
    "channel:read:goals",
    "channel:read:hype_train",
    "channel:read:polls",
    "channel:read:predictions",
    "channel:read:redemptions",
    "channel:read:subscriptions",
    "channel:read:vips",
    "chat:edit",
    "chat:read",
    "clips:edit",
    "moderation:read",
    "moderator:manage:announcements",
    "moderator:manage:banned_users",
    "moderator:manage:chat_messages",
    "moderator:manage:chat_settings",
    "moderator:manage:shield_mode",
    "moderator:manage:shoutouts",
    "moderator:read:chat_settings",
    "moderator:read:chatters",
    "moderator:read:followers",
    "moderator:read:shield_mode",
    "moderator:read:shoutouts",
    "user:bot",
    "user:edit",
    "user:edit:broadcast",
    "user:edit:follows",
    "user:manage:blocked_users",
    "user:manage:whispers",
    "user:read:blocked_users",
    "user:read:broadcast",
    "user:read:chat",
    "user:read:email",
    "user:read:emotes",
    "user:read:follows",
    "user:read:moderated_channels",
    "user:read:subscriptions",
    "user:write:chat",
    "whispers:edit",
    "whispers:read",
];
const MESSAGE_SCOPES: &[&str] = &[
    "chat:read",
    "chat:edit",
    "moderator:manage:announcements",
    "user:read:chat",
    "user:write:chat",
    "user:manage:whispers",
];
const LOGIN_SCOPES: &[&str] = &[];

#[derive(Serialize, Deserialize)]
struct OauthState {
    kind: String,
    streamer_id: Option<Uuid>,
    streamer_login: Option<String>,
    return_url: Option<String>,
    redirect_uri: String,
    pairing_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct LocalAuthStartQuery {
    pub return_url: Option<String>,
    pub return_to: Option<String>,
}

impl LocalAuthStartQuery {
    fn resolved_return_url(self) -> Result<String, AppError> {
        self.return_to
            .or(self.return_url)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AppError::BadRequest("missing return_to/return_url".into()))
    }
}

#[derive(Serialize, Deserialize)]
struct StreambotOauthResult {
    client_id: String,
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    obtainment_timestamp: i64,
    scope: Vec<String>,
    user_id: String,
    login: String,
    display_name: String,
}

#[derive(Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
}


#[derive(Deserialize)]
pub struct LoginStartQuery {}

#[derive(Deserialize)]
pub struct CallbackQuery { code: Option<String>, state: String, error: Option<String> }

pub async fn bot_start(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<LocalAuthStartQuery>) -> Result<Redirect, AppError> {
    let return_url = query.resolved_return_url()?;
    validate_local_return_url(&return_url)?;
    let redirect_uri = oauth_callback_uri(&state, &headers, "bot")?;
    tracing::info!(return_url = %return_url, redirect_uri = %redirect_uri, "starting bot OAuth");
    oauth_start(&state, "bot", None, None, Some(return_url), redirect_uri, None, BOT_SCOPES, true).await
}

pub async fn message_bot_start(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<LocalAuthStartQuery>) -> Result<Redirect, AppError> {
    let return_url = query.resolved_return_url()?;
    validate_local_return_url(&return_url)?;
    let redirect_uri = oauth_callback_uri(&state, &headers, "message_bot")?;
    tracing::info!(return_url = %return_url, redirect_uri = %redirect_uri, "starting message-bot OAuth broker flow");
    oauth_start(&state, "message_bot", None, None, Some(return_url), redirect_uri, None, MESSAGE_SCOPES, true).await
}

pub async fn login_start(State(state): State<AppState>, headers: HeaderMap, Query(_query): Query<LoginStartQuery>) -> Result<Redirect, AppError> {
    let redirect_uri = oauth_callback_uri(&state, &headers, "login")?;
    tracing::info!(redirect_uri = %redirect_uri, "starting Streambot cloud user login");
    oauth_start(&state, "login", None, None, None, redirect_uri, None, LOGIN_SCOPES, true).await
}

async fn oauth_start(
    state: &AppState,
    kind: &str,
    streamer_id: Option<Uuid>,
    streamer_login: Option<String>,
    return_url: Option<String>,
    redirect_uri: String,
    pairing_id: Option<Uuid>,
    scopes: &[&str],
    force_verify: bool,
) -> Result<Redirect, AppError> {
    let nonce = random_state();
    let payload = OauthState { kind: kind.into(), streamer_id, streamer_login, return_url, redirect_uri: redirect_uri.clone(), pairing_id };
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let _: () = conn.set_ex(format!("oauth:{nonce}"), serde_json::to_string(&payload).unwrap(), 600).await?;
    Ok(Redirect::temporary(&state.twitch.authorize_url(&redirect_uri, &nonce, scopes, force_verify)))
}

fn route_name(kind: &str) -> &str { if kind == "message_bot" { "message-bot" } else { kind } }

fn oauth_callback_uri(state: &AppState, headers: &HeaderMap, kind: &str) -> Result<String, AppError> {
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let host = forwarded_host.or_else(|| headers.get("host").and_then(|v| v.to_str().ok()));

    let origin = if let Some(host) = host {
        let proto = forwarded_proto.unwrap_or_else(|| {
            if state.config.app_public_url.starts_with("https://") { "https" } else { "http" }
        });
        format!("{proto}://{host}")
    } else {
        state.config.app_public_url.trim_end_matches('/').to_owned()
    };

    Ok(format!("{}/auth/{}/callback", origin.trim_end_matches('/'), route_name(kind)))
}

pub async fn bot_callback(State(state): State<AppState>, Query(query): Query<CallbackQuery>) -> Result<Response, AppError> {
    callback(state, query, "bot").await
}
pub async fn message_bot_callback(State(state): State<AppState>, Query(query): Query<CallbackQuery>) -> Result<Response, AppError> {
    callback(state, query, "message_bot").await
}
pub async fn login_callback(State(state): State<AppState>, Query(query): Query<CallbackQuery>) -> Result<Response, AppError> {
    callback(state, query, "login").await
}

async fn callback(state: AppState, query: CallbackQuery, expected_kind: &str) -> Result<Response, AppError> {
    tracing::info!(kind = expected_kind, has_code = query.code.is_some(), has_error = query.error.is_some(), "Twitch OAuth callback received");
    if let Some(error) = query.error { return Err(AppError::BadRequest(format!("Twitch OAuth error: {error}"))); }
    let code = query.code.ok_or_else(|| AppError::BadRequest("missing authorization code".into()))?;
    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let oauth_key = format!("oauth:{}", query.state);
    let raw: Option<String> = conn.get(&oauth_key).await?;
    let _: () = conn.del(&oauth_key).await?;
    let oauth: OauthState = serde_json::from_str(&raw.ok_or(AppError::BadRequest("invalid or expired OAuth state".into()))?)
        .map_err(|e| AppError::Internal(e.into()))?;
    if oauth.kind != expected_kind { return Err(AppError::BadRequest("OAuth flow mismatch".into())); }

    let token = state.twitch.exchange_code(&code, &oauth.redirect_uri).await.map_err(AppError::Internal)?;
    let user = state.twitch.current_user(&token.access_token).await.map_err(AppError::Internal)?;

    match expected_kind {
        "bot" | "message_bot" => complete_streambot_oauth(
            &state,
            expected_kind,
            user,
            token,
            oauth.return_url.ok_or(AppError::BadRequest("missing return URL".into()))?,
        ).await,
        "login" => complete_user_login(&state, user).await,
        _ => Err(AppError::BadRequest("unknown OAuth flow".into())),
    }
}

async fn complete_streambot_oauth(
    state: &AppState,
    kind: &str,
    user: crate::twitch::TwitchUser,
    token: crate::twitch::TokenResponse,
    return_url: String,
) -> Result<Response, AppError> {
    let exchange_code = random_token(32);
    let payload = StreambotOauthResult {
        client_id: state.config.twitch_client_id.clone(),
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        obtainment_timestamp: chrono::Utc::now().timestamp_millis(),
        scope: token.scope,
        user_id: user.id.clone(),
        login: user.login.clone(),
        display_name: user.display_name.clone(),
    };

    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let _: () = conn.set_ex(
        format!("twitch_exchange:{exchange_code}"),
        serde_json::to_string(&payload).map_err(|e| AppError::Internal(e.into()))?,
        120,
    ).await?;

    tracing::info!(
        kind = kind,
        login = %user.login,
        user_id = %user.id,
        exchange_ttl_seconds = 120,
        "Twitch OAuth completed; created one-time Streambot exchange code"
    );

    redirect_to_streambot(&return_url, kind, &exchange_code, &user.login)
}

fn validate_local_return_url(value: &str) -> Result<(), AppError> {
    let url = url::Url::parse(value).map_err(|_| AppError::BadRequest("invalid return_url".into()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(AppError::BadRequest("return_url must use http or https".into()));
    }
    let host = url.host_str().ok_or_else(|| AppError::BadRequest("return_url must contain a host".into()))?;
    let allowed = host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.parse::<std::net::IpAddr>().map(|ip| match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
        }).unwrap_or(false);
    if !allowed {
        return Err(AppError::BadRequest("return_url must point to localhost or a private network address".into()));
    }
    Ok(())
}

fn redirect_to_streambot(return_url: &str, kind: &str, exchange_code: &str, login: &str) -> Result<Response, AppError> {
    let mut url = url::Url::parse(return_url).map_err(|_| AppError::BadRequest("invalid return_url".into()))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("cloud_auth", if kind == "message_bot" { "message-bot" } else { "bot" });
        query.append_pair("status", "success");
        query.append_pair("code", exchange_code);
        query.append_pair("login", login);
    }
    Ok(Redirect::to(url.as_str()).into_response())
}

pub async fn exchange_streambot_token(
    State(state): State<AppState>,
    axum::Json(body): axum::Json<ExchangeRequest>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    if body.code.trim().is_empty() {
        return Err(AppError::BadRequest("exchange code is required".into()));
    }

    let mut conn = state.valkey.get_multiplexed_async_connection().await?;
    let key = format!("twitch_exchange:{}", body.code.trim());
    let raw: Option<String> = conn.get(&key).await?;
    let _: () = conn.del(&key).await?;
    let raw = raw.ok_or_else(|| AppError::BadRequest("invalid, expired, or already used exchange code".into()))?;
    let result: StreambotOauthResult = serde_json::from_str(&raw)
        .map_err(|e| AppError::Internal(e.into()))?;

    tracing::info!(
        login = %result.login,
        user_id = %result.user_id,
        "one-time Twitch OAuth result exchanged by Streambot"
    );

    Ok(axum::Json(serde_json::to_value(result).map_err(|e| AppError::Internal(e.into()))?))
}

async fn complete_user_login(
    state: &AppState,
    user: crate::twitch::TwitchUser,
) -> Result<Response, AppError> {
    let own_streamer_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO streamers (id, twitch_user_id, login, display_name, profile_image_url)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (twitch_user_id) DO UPDATE SET
            login = EXCLUDED.login,
            display_name = EXCLUDED.display_name,
            profile_image_url = EXCLUDED.profile_image_url,
            updated_at = NOW()
        RETURNING id
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&user.id)
    .bind(user.login.to_lowercase())
    .bind(&user.display_name)
    .bind(&user.profile_image_url)
    .fetch_one(&state.db)
    .await?;

    sqlx::query(
        "INSERT INTO user_settings (twitch_user_id, language) VALUES ($1, 'en') ON CONFLICT (twitch_user_id) DO NOTHING"
    )
        .bind(&user.id)
        .execute(&state.db)
        .await?;

    let streamer_ids = vec![own_streamer_id];


    tracing::info!(
        twitch_user_id = %user.id,
        login = %user.login,
        accessible_streamers = streamer_ids.len(),
        "cloud user login completed"
    );

    let session = Session {
        twitch_user_id: user.id,
        login: user.login,
        display_name: user.display_name,
        streamer_ids,
        owner_streamer_ids: vec![own_streamer_id],
    };

    redirect_with_session(state, session).await
}

async fn redirect_with_session(state: &AppState, session: Session) -> Result<Response, AppError> {
    let token = create_session(state, &session).await?;
    let secure = if state.config.app_public_url.starts_with("https://") { "; Secure" } else { "" };
    let cookie = format!("{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}", state.config.session_cookie_name, token, state.config.session_ttl_seconds, secure);
    let mut response = Redirect::to(&state.config.frontend_url).into_response();
    response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie).map_err(|e| AppError::Internal(e.into()))?);
    Ok(response)
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    delete_session(&state, &headers).await?;
    let secure = if state.config.app_public_url.starts_with("https://") { "; Secure" } else { "" };
    let cookie = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", state.config.session_cookie_name, secure);

    tracing::info!("cloud user logged out");

    let mut response = Redirect::to(&state.config.frontend_url).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|e| AppError::Internal(e.into()))?,
    );
    Ok(response)
}
