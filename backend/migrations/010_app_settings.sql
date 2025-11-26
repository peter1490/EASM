-- Centralized application settings storage
-- Stores encrypted payload of managed configuration that can be edited from the UI

CREATE TABLE IF NOT EXISTS app_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_payload BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- Enforce a single-row singleton table
CREATE UNIQUE INDEX IF NOT EXISTS app_settings_singleton ON app_settings ((true));
