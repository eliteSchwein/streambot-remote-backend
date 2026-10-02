use serde::Deserialize;

#[derive(Clone)]
pub struct TwitchClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TwitchUser {
    pub id: String,
    pub login: String,
    pub display_name: String,
    pub profile_image_url: String,
}

#[derive(Deserialize)]
struct UsersResponse { data: Vec<TwitchUser> }

impl TwitchClient {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self { http: reqwest::Client::new(), client_id, client_secret }
    }

    pub fn authorize_url(&self, redirect_uri: &str, state: &str, scopes: &[&str], force_verify: bool) -> String {
        let mut url = url::Url::parse("https://id.twitch.tv/oauth2/authorize").expect("valid Twitch URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state);
        if force_verify {
            url.query_pairs_mut().append_pair("force_verify", "true");
        }
        url.to_string()
    }

    pub async fn exchange_code(&self, code: &str, redirect_uri: &str) -> anyhow::Result<TokenResponse> {
        let response = self.http.post("https://id.twitch.tv/oauth2/token")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
            ])
            .send().await?.error_for_status()?.json().await?;
        Ok(response)
    }

    pub async fn current_user(&self, access_token: &str) -> anyhow::Result<TwitchUser> {
        let response: UsersResponse = self.http.get("https://api.twitch.tv/helix/users")
            .header("Client-Id", &self.client_id)
            .bearer_auth(access_token)
            .send().await?.error_for_status()?.json().await?;
        response.data.into_iter().next().ok_or_else(|| anyhow::anyhow!("Twitch returned no user"))
    }
}
