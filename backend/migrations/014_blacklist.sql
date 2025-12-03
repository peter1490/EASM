-- Blacklist table for excluding objects from discovery
-- When a blacklisted object is encountered during discovery, it is ignored
-- and no recursive search is performed on it.

CREATE TABLE blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Type of blacklisted object (matches asset_type + cidr for IP ranges)
    object_type VARCHAR(50) NOT NULL,
    -- The value/identifier being blacklisted (domain, IP, org name, CIDR, etc.)
    object_value VARCHAR(500) NOT NULL,
    -- Why this was blacklisted
    reason TEXT,
    -- Who created this blacklist entry
    created_by VARCHAR(255),
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Ensure unique combinations of type and value
    UNIQUE(object_type, object_value)
);

-- Index for quick lookups during discovery
CREATE INDEX idx_blacklist_type_value ON blacklist(object_type, object_value);
CREATE INDEX idx_blacklist_object_type ON blacklist(object_type);

-- Index for pattern matching (useful for wildcard domain blacklisting)
CREATE INDEX idx_blacklist_value_pattern ON blacklist(object_value varchar_pattern_ops);

COMMENT ON TABLE blacklist IS 'Stores blacklisted objects that should be ignored during discovery';
COMMENT ON COLUMN blacklist.object_type IS 'Type: domain, ip, organization, asn, cidr, certificate';
COMMENT ON COLUMN blacklist.object_value IS 'The value to blacklist (e.g., cloudflare.com, 192.168.1.0/24)';
COMMENT ON COLUMN blacklist.reason IS 'Optional explanation for why this was blacklisted';

