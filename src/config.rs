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
    pub mediamtx_auth_secret: String,
    pub mediamtx_api_url: String,
    /// Browser-facing WHEP base (`http://<host>:<webrtc port>` unless
    /// MEDIAMTX_PUBLIC_URL overrides it for a reverse proxy).
    pub mediamtx_public_url: String,
    pub mediamtx_srt_host: String,
    pub mediamtx_srt_port: u16,
    pub mediamtx_rtsp_host: String,
    pub mediamtx_rtsp_port: u16,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mediamtx = mediamtx_endpoints()?;
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
            mediamtx_auth_secret: required_non_empty("MEDIAMTX_AUTH_SECRET")?,
            mediamtx_api_url: env::var("MEDIAMTX_API_URL").unwrap_or_else(|_| "http://mediamtx:9997".into()).trim_end_matches('/').to_owned(),
            mediamtx_public_url: mediamtx.public_url,
            mediamtx_srt_host: mediamtx.srt_host,
            mediamtx_srt_port: mediamtx.srt_port,
            mediamtx_rtsp_host: mediamtx.host,
            mediamtx_rtsp_port: mediamtx.rtsp_port,
        })
    }
}

struct MediamtxEndpoints {
    host: String,
    public_url: String,
    srt_host: String,
    srt_port: u16,
    rtsp_port: u16,
}

/// Every client-facing MediaMTX URL is built from one public host and the
/// same port variables docker-compose publishes, so they cannot drift apart.
/// MEDIAMTX_PUBLIC_URL / MEDIAMTX_SRT_HOST remain as optional overrides
/// (reverse proxy, separate ingest host).
fn mediamtx_endpoints() -> anyhow::Result<MediamtxEndpoints> {
    let host = optional("MEDIAMTX_HOST")
        .or_else(|| optional("MEDIAMTX_SRT_HOST"))
        .ok_or_else(|| anyhow::anyhow!("missing required environment variable MEDIAMTX_HOST"))?;
    let srt_port = port("MEDIAMTX_SRT_PORT", 18890)?;
    let webrtc_port = port("MEDIAMTX_WEBRTC_PORT", 18889)?;
    let rtsp_port = port("MEDIAMTX_RTSP_PORT", 18554)?;

    let derived = format!("http://{}:{webrtc_port}", url_host(&host));
    let public_url = match optional("MEDIAMTX_PUBLIC_URL") {
        Some(url) => {
            let url = url.trim_end_matches('/').to_owned();
            if override_is_usable(&url, &host, webrtc_port) {
                url
            } else {
                tracing::warn!(
                    configured = %url, using = %derived,
                    "ignoring MEDIAMTX_PUBLIC_URL: it points straight at MediaMTX with a port other than MEDIAMTX_WEBRTC_PORT (only set it for a reverse proxy)"
                );
                derived
            }
        }
        None => derived,
    };

    Ok(MediamtxEndpoints {
        srt_host: optional("MEDIAMTX_SRT_HOST").unwrap_or_else(|| host.clone()),
        host,
        public_url,
        srt_port,
        rtsp_port,
    })
}

/// IPv6 literals need brackets inside URLs.
pub fn url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_owned() }
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// MEDIAMTX_PUBLIC_URL is meant for a reverse proxy in front of MediaMTX. An
/// override that points straight at the MediaMTX host with another port than
/// the published WebRTC port is a stale value (it silently breaks every
/// viewer, or hits a different MediaMTX), so it is not used.
fn override_is_usable(url: &str, host: &str, webrtc_port: u16) -> bool {
    let Ok(parsed) = url::Url::parse(url) else { return false };
    let Some(url_host) = parsed.host_str() else { return false };
    let url_host = url_host.trim_matches(['[', ']']);
    let host = host.trim_matches(['[', ']']);
    let same_host = url_host == host || (is_loopback(url_host) && is_loopback(host));
    !(same_host && parsed.port().is_some_and(|port| port != webrtc_port))
}

#[cfg(test)]
mod tests {
    use super::override_is_usable;

    #[test]
    fn stale_direct_port_is_ignored() {
        assert!(!override_is_usable("http://localhost:8889", "localhost", 18889));
        assert!(!override_is_usable("http://127.0.0.1:8889", "localhost", 18889));
        assert!(!override_is_usable("not a url", "localhost", 18889));
    }

    #[test]
    fn proxy_and_matching_urls_are_used() {
        assert!(override_is_usable("https://live.example.com", "203.0.113.5", 18889));
        assert!(override_is_usable("https://live.example.com", "live.example.com", 18889));
        assert!(override_is_usable("http://localhost:18889", "localhost", 18889));
    }
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
}

fn port(name: &str, default: u16) -> anyhow::Result<u16> {
    match optional(name) {
        Some(value) => value.parse().map_err(|_| anyhow::anyhow!("{name} must be a port number")),
        None => Ok(default),
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| anyhow::anyhow!("missing required environment variable {name}"))
}

fn required_non_empty(name: &str) -> anyhow::Result<String> {
    let value = required(name)?;
    if value.trim().is_empty() {
        anyhow::bail!("environment variable {name} must not be empty");
    }
    Ok(value.trim().to_owned())
}
