ALTER TABLE user_settings
    ADD COLUMN dashboard_layouts JSONB NOT NULL DEFAULT '{}'::jsonb;
