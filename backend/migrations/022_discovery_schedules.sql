-- Discovery schedules for cron-based discovery runs
CREATE TABLE IF NOT EXISTS discovery_schedules (
    id UUID PRIMARY KEY,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    cron VARCHAR(200) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_discovery_schedules_company_id ON discovery_schedules(company_id);
CREATE INDEX IF NOT EXISTS idx_discovery_schedules_next_run ON discovery_schedules(next_run_at);
CREATE INDEX IF NOT EXISTS idx_discovery_schedules_enabled_next_run ON discovery_schedules(next_run_at) WHERE enabled = true;
