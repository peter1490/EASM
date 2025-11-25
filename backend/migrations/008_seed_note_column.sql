-- Add note and updated_at columns to seeds table
ALTER TABLE seeds ADD COLUMN IF NOT EXISTS note TEXT;
ALTER TABLE seeds ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

