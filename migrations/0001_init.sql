CREATE TABLE streamers (
    id UUID PRIMARY KEY,
    twitch_user_id TEXT NOT NULL UNIQUE,
    login TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    profile_image_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE twitch_credentials (
    id UUID PRIMARY KEY,
    streamer_id UUID NOT NULL REFERENCES streamers(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL CHECK (credential_type IN ('bot', 'message_bot')),
    twitch_user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    display_name TEXT NOT NULL,
    access_token_enc TEXT NOT NULL,
    refresh_token_enc TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(streamer_id, credential_type)
);

CREATE TABLE streamer_mods (
    streamer_id UUID NOT NULL REFERENCES streamers(id) ON DELETE CASCADE,
    twitch_user_id TEXT NOT NULL,
    login TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(streamer_id, twitch_user_id)
);

CREATE TABLE streambot_instances (
    id UUID PRIMARY KEY,
    streamer_id UUID NOT NULL REFERENCES streamers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(streamer_id, name)
);

CREATE INDEX idx_streamer_mods_twitch_user_id ON streamer_mods(twitch_user_id);
CREATE INDEX idx_streambot_instances_streamer_id ON streambot_instances(streamer_id);
