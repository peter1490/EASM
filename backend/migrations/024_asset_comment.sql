-- Add optional analyst comment field to assets
ALTER TABLE assets
ADD COLUMN IF NOT EXISTS comment TEXT;

COMMENT ON COLUMN assets.comment IS 'Optional short analyst note visible on the asset details page';
