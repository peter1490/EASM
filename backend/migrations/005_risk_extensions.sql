-- Add risk-related columns to assets table
ALTER TABLE assets 
ADD COLUMN IF NOT EXISTS importance INTEGER DEFAULT 0 CHECK (importance >= 0 AND importance <= 5),
ADD COLUMN IF NOT EXISTS risk_score FLOAT,
ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20), -- 'critical', 'high', 'medium', 'low', 'info', 'none'
ADD COLUMN IF NOT EXISTS last_risk_run TIMESTAMPTZ;

-- Create asset_risk_history table
CREATE TABLE IF NOT EXISTS asset_risk_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    risk_score FLOAT NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    factors JSONB NOT NULL, -- Breakdown of risk calculation
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for querying risk history
CREATE INDEX IF NOT EXISTS idx_asset_risk_history_asset_id ON asset_risk_history(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_risk_history_date ON asset_risk_history(calculated_at);

-- Index for querying assets by risk
CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score);
CREATE INDEX IF NOT EXISTS idx_assets_importance ON assets(importance);

