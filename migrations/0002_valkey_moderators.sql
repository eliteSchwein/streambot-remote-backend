-- Moderator membership is supplied by each registered Streambot and cached in Valkey.
-- It is intentionally not durable cloud database state.
DROP TABLE IF EXISTS streamer_mods;
