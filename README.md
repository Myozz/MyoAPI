# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API combining vulnerability data from multiple authoritative sources.

[![Deploy](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml)
[![Sync](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml)

## Features

- **328K+ CVEs** aggregated from NVD (1999-2026)
- **5 Data Sources**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Custom scoring = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Multi-source Data**: Scores and packages from all sources with fallback
- **Patch Status**: Track if vulnerabilities are fixed/affected
- **Package Search**: Query CVEs by package name and ecosystem
- **Fast**: Cloudflare Workers edge network
- **Free**: No API keys required

## Live API

```
https://api.myoapi.workers.dev
```

## Endpoints

| Method | Endpoint | Description |
|:------:|----------|-------------|
| `GET` | `/api/v1/cve/:id` | Get CVE by ID |
| `GET` | `/api/v1/cve/search` | Search with filters |
| `GET` | `/api/v1/cve/package` | Search by package name |
| `GET` | `/api/v1/cve/bulk` | Bulk download with pagination |
| `GET` | `/api/v1/cve/recent` | Recent CVEs |
| `GET` | `/api/v1/stats` | Database statistics |

## Response Format

```json
{
  "data": {
    "id": "CVE-2023-4863",
    "title": "Heap buffer overflow in WebP",
    "description": "...",
    "myo_severity": "CRITICAL",
    "myo_score": 0.92,
    "cvss": { "nvd": 9.8, "ghsa": null, "osv": null },
    "epss": { "score": 0.75, "percentile": 0.99 },
    "kev": { "is_known": true, "date_added": "2023-09-13" },
    "affected_packages": [
      {
        "package": "libwebp",
        "ecosystem": "unknown",
        "vendor": "google",
        "affected_versions": ["1.3.1"],
        "fixed_versions": [],
        "status": "affected"
      }
    ],
    "sources": ["nvd", "osv", "epss", "kev"]
  }
}
```

## Data Priority

Data is merged from multiple sources with fallback:

| Field | Priority |
|-------|----------|
| `cvss` | All sources shown independently |
| `affected_packages` | OSV > GHSA > NVD (CPE parsed) |
| `description` | NVD > GHSA |
| `fixed_versions` | OSV/GHSA ranges > patched_versions |

If OSV and GHSA have no package info, packages are extracted from NVD CPE data.

## Data Fields

| Field | Description |
|-------|-------------|
| `myo_severity` | CRITICAL/HIGH/MEDIUM/LOW based on myo_score |
| `myo_score` | Priority score (0.0-1.0) |
| `cvss.nvd/ghsa/osv` | CVSS scores from each source |
| `vendor` | Vendor name from CPE (NVD only) |
| `affected_versions` | Vulnerable version ranges |
| `fixed_versions` | Patched versions |
| `status` | `fixed` / `affected` / `unknown` |

## Myo Score Formula

```
MyoScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Development

```bash
npm install
npm run dev
npx wrangler deploy
```

## License

MIT
