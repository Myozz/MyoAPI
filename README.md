# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API combining vulnerability data from multiple authoritative sources.

[![Deploy](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml)
[![Sync](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml)

## Features

- **328K+ CVEs** aggregated from NVD (1999-2026)
- **5 Data Sources**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Custom scoring = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Multi-source CVSS**: Scores from NVD, GHSA, and OSV
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
    "id": "CVE-2021-23337",
    "title": "Prototype Pollution in lodash",
    "description": "Lodash versions prior to 4.17.21 are vulnerable to...",
    "myo_severity": "CRITICAL",
    "myo_score": 0.85,
    "cvss": {
      "nvd": 9.8,
      "ghsa": 9.8,
      "osv": null
    },
    "epss": {
      "score": 0.45,
      "percentile": 0.97
    },
    "kev": {
      "is_known": true,
      "date_added": "2023-01-15"
    },
    "ghsa_id": "GHSA-35jh-r3h4-6jhm",
    "cwe": ["CWE-1321"],
    "cpe": ["cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*"],
    "affected_packages": [
      {
        "package": "lodash",
        "ecosystem": "npm",
        "affected_versions": ["<4.17.21"],
        "fixed_versions": ["4.17.21"]
      }
    ],
    "sources": ["nvd", "osv", "ghsa", "epss", "kev"]
  }
}
```

## Data Fields

| Field | Source | Description |
|-------|--------|-------------|
| `myo_severity` | Calculated | CRITICAL/HIGH/MEDIUM/LOW |
| `myo_score` | Calculated | 0.0-1.0 priority score |
| `cvss.nvd` | NVD | CVSS score from NVD |
| `cvss.ghsa` | GHSA | CVSS score from GitHub |
| `cvss.osv` | OSV | CVSS score from OSV |
| `epss.score` | EPSS | Exploit probability |
| `epss.percentile` | EPSS | Percentile ranking |
| `kev.is_known` | CISA KEV | Known exploited vulnerability |
| `kev.date_added` | CISA KEV | Date added to KEV catalog |
| `cwe` | NVD + GHSA | Weakness types |
| `cpe` | NVD | Product identifiers |
| `affected_packages` | OSV + GHSA | Packages with versions |

## Myo Score Formula

```
MyoScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

**Myo Severity:**

- `≥0.7` → CRITICAL
- `≥0.5` → HIGH
- `≥0.3` → MEDIUM
- `≥0.1` → LOW

## Data Sources

| Source | Data | Update |
|--------|------|--------|
| [NVD](https://nvd.nist.gov/) | CVSS, CWE, CPE, descriptions | Daily |
| [OSV](https://osv.dev/) | Affected packages, CVSS | Daily |
| [GHSA](https://github.com/advisories) | Advisories, CVSS, fixed versions | Daily |
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
