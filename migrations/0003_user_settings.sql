CREATE TABLE user_settings (
    twitch_user_id TEXT PRIMARY KEY,
    language TEXT NOT NULL DEFAULT 'en',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO user_settings (twitch_user_id, language)
SELECT twitch_user_id, 'en'
FROM streamers
ON CONFLICT (twitch_user_id) DO NOTHING;
