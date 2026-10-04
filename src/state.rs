use std::{collections::HashMap, sync::Arc};

use sqlx::PgPool;
use axum::extract::ws::Message;
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::{config::Config, twitch::TwitchClient};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub valkey: redis::Client,
    pub twitch: TwitchClient,
    pub streambot_connections: Arc<RwLock<HashMap<Uuid, mpsc::Sender<Message>>>>,
    pub user_connections: Arc<RwLock<HashMap<String, Vec<mpsc::Sender<String>>>>>,
    pub instance_connections: Arc<RwLock<HashMap<Uuid, HashMap<String, Vec<mpsc::Sender<String>>>>>>,
}
