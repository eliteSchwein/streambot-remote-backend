mod config;
mod error;
mod models;
mod routes;
mod session;
mod state;
mod twitch;

use std::{collections::HashMap, sync::Arc};

use axum::{
    Router,
    http::{Method, header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE}},
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use tower_http::{cors::{AllowOrigin, CorsLayer}, trace::TraceLayer};
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, state::AppState, twitch::TwitchClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let config = Config::from_env()?;
    let db = PgPoolOptions::new().max_connections(10).connect(&config.database_url).await?;
    sqlx::migrate!().run(&db).await?;
    let valkey = redis::Client::open(config.valkey_url.clone())?;
    let twitch = TwitchClient::new(config.twitch_client_id.clone(), config.twitch_client_secret.clone());
    let state = AppState {
        config: config.clone(),
        db,
        valkey,
        twitch,
        streambot_connections: Arc::new(RwLock::new(HashMap::new())),
        user_connections: Arc::new(RwLock::new(HashMap::new())),
        instance_connections: Arc::new(RwLock::new(HashMap::new())),
    };

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(config.frontend_url.parse()?))
        .allow_credentials(true)
        .allow_headers([ACCEPT, AUTHORIZATION, CONTENT_TYPE])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/login", get(routes::auth::login_start))
        .route("/auth/login/callback", get(routes::auth::login_callback))
        .route("/auth/bot", get(routes::auth::bot_start))
        .route("/auth/bot/callback", get(routes::auth::bot_callback))
        .route("/auth/message-bot", get(routes::auth::message_bot_start))
        .route("/auth/message-bot/callback", get(routes::auth::message_bot_callback))
        .route("/api/v1/twitch/exchange", post(routes::auth::exchange_streambot_token))
        .route("/auth/logout", get(routes::auth::logout).post(routes::auth::logout))
        .route("/api/v1/instance-auth", post(routes::api::instance_auth))
        .route("/api/v1/streambot/registration/start", post(routes::streambot::registration_start))
        .route("/api/v1/streambot/registration/verify", post(routes::streambot::registration_verify))
        .route("/api/v1/streambot/registration/status", get(routes::streambot::registration_status))
        .route("/ws/streambot", get(routes::streambot::ws_streambot))
        .route("/ws/user", get(routes::streambot::ws_user))
        .route("/ws/instance/{instance_id}", get(routes::streambot::ws_instance))
        .route("/webhooks/kofi/{webhook_id}", post(routes::kofi::webhook))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "streambot remote backend listening");
    axum::serve(listener, app).await?;
    Ok(())
}
