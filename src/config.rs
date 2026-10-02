use std::{env, net::SocketAddr};

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub app_public_url: String,
    pub frontend_url: String,
    pub database_url: String,
    pub valkey_url: String,
    pub twitch_client_id: String,
    pub twitch_client_secret: String,
    pub session_cookie_name: String,
    pub session_ttl_seconds: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind: env::var("APP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into()).parse()?,
            app_public_url: required("APP_PUBLIC_URL")?,
            frontend_url: required("FRONTEND_URL")?,
            database_url: required("DATABASE_URL")?,
            valkey_url: required("VALKEY_URL")?,
            twitch_client_id: required("TWITCH_CLIENT_ID")?,
            twitch_client_secret: required("TWITCH_CLIENT_SECRET")?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "streambot_remote_session".into()),
            session_ttl_seconds: env::var("SESSION_TTL_SECONDS").unwrap_or_else(|_| "604800".into()).parse()?,
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| anyhow::anyhow!("missing required environment variable {name}"))
}
