-- Drop legacy global uniqueness constraint so blacklist entries are scoped by company only.
-- Multi-tenant uniqueness is enforced by idx_blacklist_company_type_value from migration 020.
ALTER TABLE blacklist
    DROP CONSTRAINT IF EXISTS blacklist_object_type_object_value_key;
