use serde::Serialize;
use uuid::Uuid;

#[derive(sqlx::FromRow, Serialize)]
pub struct StreamerSummary {
    pub id: Uuid,
    pub login: String,
    pub display_name: String,
    pub profile_image_url: Option<String>,
    pub bot_connected: bool,
    pub message_bot_connected: bool,
    pub instance_count: i64,
    pub role: String,
}
