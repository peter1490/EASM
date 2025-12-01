-- Add display_name and is_active columns for user management
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;

-- Update existing users to have is_active = true
UPDATE users SET is_active = true WHERE is_active IS NULL;

