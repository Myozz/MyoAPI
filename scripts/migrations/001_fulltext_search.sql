-- ============================================================
-- MyoAPI Full-Text Search Migration
-- Run this in Supabase SQL Editor: https://supabase.com/dashboard
-- ============================================================

-- Step 1: Add search_vector column 
-- This stores the pre-computed tsvector for fast full-text search
ALTER TABLE cves ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- Step 2: Create GIN index for fast full-text search
-- GIN index is optimized for tsvector and array lookups
CREATE INDEX IF NOT EXISTS idx_cves_search ON cves USING GIN (search_vector);

-- Step 3: Populate search_vector from existing data
-- Combines id and description into searchable vector
UPDATE cves SET search_vector = 
  setweight(to_tsvector('english', coalesce(id, '')), 'A') ||
  setweight(to_tsvector('english', coalesce(title, '')), 'B') ||
  setweight(to_tsvector('english', coalesce(description, '')), 'C');

-- Step 4: Create trigger function to auto-update search_vector on changes
CREATE OR REPLACE FUNCTION cves_search_vector_trigger() RETURNS trigger AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', coalesce(NEW.id, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.title, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.description, '')), 'C');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Step 5: Create trigger (drop first if exists)
DROP TRIGGER IF EXISTS cves_search_update ON cves;
CREATE TRIGGER cves_search_update
  BEFORE INSERT OR UPDATE ON cves
  FOR EACH ROW
  EXECUTE FUNCTION cves_search_vector_trigger();

-- Verify: Check if index was created
-- SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'cves';

-- Test query (should be fast now):
-- SELECT id, title FROM cves 
-- WHERE search_vector @@ to_tsquery('english', 'log4j') 
-- LIMIT 5;
