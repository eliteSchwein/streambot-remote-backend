CREATE TABLE IF NOT EXISTS kofi_integrations (
    streamer_id UUID PRIMARY KEY REFERENCES streamers(id) ON DELETE CASCADE,
    webhook_id UUID NOT NULL UNIQUE,
    verification_token_hash TEXT NOT NULL,
    relay_urls JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kofi_integrations_webhook_id
    ON kofi_integrations(webhook_id);
