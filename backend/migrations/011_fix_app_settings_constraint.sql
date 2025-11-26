-- Ensure singleton enforcement uses a proper constraint
ALTER TABLE app_settings
    ADD COLUMN IF NOT EXISTS singleton BOOLEAN NOT NULL DEFAULT TRUE;

-- Clean up any old index/constraint using the same name to avoid conflicts
DO $$
BEGIN
    -- Drop constraint if it exists
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'app_settings_singleton'
    ) THEN
        ALTER TABLE app_settings
            DROP CONSTRAINT app_settings_singleton;
    END IF;

    -- Drop index if it exists (from previous migration)
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'app_settings_singleton' AND c.relkind = 'i'
    ) THEN
        DROP INDEX app_settings_singleton;
    END IF;

    -- Recreate as a unique constraint on the singleton column
    ALTER TABLE app_settings
        ADD CONSTRAINT app_settings_singleton UNIQUE (singleton);
END $$;
