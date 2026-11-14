-- Per-instance webcam viewer key. Generated lazily on the first webcam stream
-- start and never changed afterwards, so the public viewer URL stays stable.
ALTER TABLE streambot_instances
    ADD COLUMN IF NOT EXISTS webcam_stream_key TEXT UNIQUE;
