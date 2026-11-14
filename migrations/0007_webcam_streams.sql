-- One webcam viewer stream per (instance, camera). The stream key is generated
-- on the first start of that camera and never changed afterwards, so the public
-- viewer URL stays stable; it is deleted together with the row (camera removed
-- on the bot or instance deleted).
CREATE TABLE IF NOT EXISTS webcam_streams (
    instance_id UUID NOT NULL REFERENCES streambot_instances(id) ON DELETE CASCADE,
    camera_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    stream_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (instance_id, camera_id)
);

-- Superseded by webcam_streams (single-camera key from 0006).
ALTER TABLE streambot_instances DROP COLUMN IF EXISTS webcam_stream_key;
