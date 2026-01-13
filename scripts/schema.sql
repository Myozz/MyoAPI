-- CVE Database Schema v2 - Multi-Source Support
-- Run this in Supabase SQL Editor to update schema

-- Drop old table and recreate with new structure
DROP TABLE IF EXISTS cves;

CREATE TABLE cves (
  id TEXT PRIMARY KEY,
  
  -- Single source fields (priority: NVD > OSV > vendor)
  title TEXT,
  description TEXT,
  severity TEXT,  -- CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
  
  -- Multi-source fields (JSONB with consistent structure)
  cvss JSONB DEFAULT '{
    "nvd": null,
    "osv": null,
    "vendor": null
  }',
  -- Structure: { "source": { "score": float, "vector": string, "version": string } }
  
  epss JSONB DEFAULT '{
    "score": null,
    "percentile": null
  }',
  
  kev JSONB DEFAULT '{
    "is_known": false,
    "date_added": null,
    "due_date": null
  }',
  
  affected JSONB DEFAULT '{
    "nvd": [],
    "osv": []
  }',
  -- Structure: { "source": [{ "package": string, "versions": array, "ecosystem": string }] }
  
  refs JSONB DEFAULT '{
    "nvd": [],
    "osv": [],
    "vendor": []
  }',
  -- Structure: { "source": ["url1", "url2"] }
  
  aliases TEXT[] DEFAULT '{}',  -- GHSA-xxx, etc.
  
  -- Calculated fields
  priority_score NUMERIC(7,5),
  
  -- Metadata
  published TIMESTAMPTZ,
  modified TIMESTAMPTZ,
  sources TEXT[] DEFAULT '{}',  -- ["nvd", "epss", "kev"]
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_cves_severity ON cves(severity);
CREATE INDEX idx_cves_priority ON cves(priority_score DESC NULLS LAST);
CREATE INDEX idx_cves_published ON cves(published DESC NULLS LAST);
CREATE INDEX idx_cves_sources ON cves USING GIN(sources);

-- Enable RLS
ALTER TABLE cves ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public read" ON cves FOR SELECT USING (true);
