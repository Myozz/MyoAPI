# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API that combines vulnerability data from multiple authoritative sources.

[![Deploy](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml)
[![Sync](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml)

## Features

- **328K+ CVEs** from NVD (1999-2026)
- **5 Data Sources**: NVD CVSS, OSV packages, GHSA advisories, EPSS scores, CISA KEV
- **Priority Score**: Custom scoring combining CVSS (30%) + EPSS (50%) + KEV (20%)
- **Package Search**: Query CVEs by package name and ecosystem
- **Bulk Download**: Paginated API for syncing large datasets
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

## Endpoints

| Method | Endpoint | Description |
|:------:|----------|-------------|
| `GET` | `/api/v1/cve/:id` | Get CVE by ID |
| `GET` | `/api/v1/cve/search` | Search with filters |
| `GET` | `/api/v1/cve/package` | Search by package name |
| `GET` | `/api/v1/cve/bulk` | Bulk download with pagination |
| `GET` | `/api/v1/cve/recent` | Recent CVEs |
| `GET` | `/api/v1/stats` | Database statistics |

## Usage Examples

### Get CVE Details

```bash
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400
```

### Search by Package (for vulnerability scanners)

```bash
curl "https://api.myoapi.workers.dev/api/v1/cve/package?ecosystem=npm&name=lodash"
curl "https://api.myoapi.workers.dev/api/v1/cve/package?ecosystem=PyPI&name=requests"
```

### Search CRITICAL CVEs

```bash
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"
```

### Bulk Download (for sync)

```bash
curl "https://api.myoapi.workers.dev/api/v1/cve/bulk?limit=1000&offset=0"
curl "https://api.myoapi.workers.dev/api/v1/cve/bulk?minPriority=0.5&limit=1000"
```

## Response Format

```json
{
  "data": {
    "id": "CVE-2021-23337",
    "title": "Prototype Pollution in lodash",
    "severity": "CRITICAL",
    "priority_severity": "CRITICAL",
    "priority_score": 0.85,
    "cvss_score": 9.8,
    "epss_score": 0.45,
    "is_kev": true,
    "ghsa_id": "GHSA-35jh-r3h4-6jhm",
    "affected_packages": [
      { "package": "lodash", "ecosystem": "npm", "versions": ["<4.17.21"] }
    ]
  }
}
```

## Search Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `severity` | CRITICAL, HIGH, MEDIUM, LOW | `severity=CRITICAL` |
| `isKev` or `kev` | Known Exploited Vulnerability | `kev=true` |
| `hasOsv` or `osv` | Has OSV package data | `osv=true` |
| `limit` | Results per page (max 1000) | `limit=100` |
| `offset` | Pagination offset | `offset=0` |
| `sort` or `sortBy` | Sort field | `sort=priority_score` |
| `order` or `sortOrder` | asc or desc | `order=desc` |

## Package Search Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `ecosystem` | Yes | npm, PyPI, Go, Maven, crates.io, NuGet, etc. |
| `name` or `package` | Yes | Package name |
| `limit` | No | Max results (default 100) |

## Priority Score Formula

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

**Priority Severity Mapping:**

- `≥0.7` → CRITICAL
- `≥0.5` → HIGH
- `≥0.3` → MEDIUM
- `≥0.1` → LOW
- `<0.1` → UNKNOWN

## Data Sources

| Source | Data | Update |
|--------|------|--------|
| [NVD](https://nvd.nist.gov/) | CVSS scores, descriptions | Daily |
| [OSV](https://osv.dev/) | Affected packages | Daily |
| [GHSA](https://github.com/advisories) | GitHub advisories | Daily |
| [EPSS](https://www.first.org/epss/) | Exploit probability | Daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Active exploits | Daily |

## Development

```bash
npm install
npm run dev
npx wrangler deploy
```

## License

MIT
