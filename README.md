# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API that combines vulnerability data from multiple authoritative sources.

[![Deploy](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml)
[![Sync](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml)

## Features

- **328K+ CVEs** from NVD (1999-2026)
- **5 Data Sources**: NVD CVSS, OSV packages, GHSA advisories, EPSS scores, CISA KEV
- **Priority Score**: Custom scoring combining CVSS, EPSS, and KEV
- **Fast**: Cloudflare Workers edge network
- **Free**: No API keys required

## Live API

```
https://api.myoapi.workers.dev
```

## Data Statistics

| Source | Count |
|--------|-------|
| Total CVEs | 328,132 |
| NVD CVSS | 303,561 |
| EPSS Scores | 311,012 |
| OSV Packages | 22,624 |
| GHSA Advisories | 714 |
| CISA KEV | 1,488 |
| CRITICAL | 38,646 |
| HIGH | 108,471 |

## Endpoints

| Method | Endpoint | Description |
|:------:|----------|-------------|
| `GET` | `/api/v1/cve/:id` | Get CVE by ID |
| `GET` | `/api/v1/cve/search` | Search with filters |
| `GET` | `/api/v1/cve/recent` | Recent CVEs |
| `GET` | `/api/v1/stats` | Database statistics |
| `GET` | `/api/v1/stats/health` | Health check |

## Usage

```bash
# Get CVE details
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400

# Search CRITICAL CVEs
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"

# Filter by KEV status
curl "https://api.myoapi.workers.dev/api/v1/cve/search?isKev=true&limit=20"
```

## Search Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `severity` | CRITICAL, HIGH, MEDIUM, LOW | `severity=CRITICAL` |
| `isKev` | Known Exploited Vulnerability | `isKev=true` |
| `hasOsv` | Has OSV package data | `hasOsv=true` |
| `limit` | Results per page (max 100) | `limit=20` |

## Data Sources

| Source | Data | Update |
|--------|------|--------|
| [NVD](https://nvd.nist.gov/) | CVSS scores, descriptions | Daily |
| [OSV](https://osv.dev/) | Affected packages | Daily |
| [GHSA](https://github.com/advisories) | GitHub advisories | Daily |
| [EPSS](https://www.first.org/epss/) | Exploit probability | Daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Active exploits | Daily |

## Priority Score

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Development

```bash
npm install
npm run dev
npx wrangler deploy
```

## License

MIT
