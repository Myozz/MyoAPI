# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API combining vulnerability data from multiple authoritative sources.

[![Deploy](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/deploy.yml)
[![Sync](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml/badge.svg)](https://github.com/Myozz/myoapi/actions/workflows/daily-sync.yml)

## Features

- **328K+ CVEs** aggregated from NVD (1999-2026)
- **5 Data Sources**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Custom scoring = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Multi-source CVSS**: Scores from NVD, GHSA, and OSV
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
    "id": "CVE-2021-23337",
    "title": "Prototype Pollution in lodash",
    "description": "Lodash versions prior to 4.17.21 are vulnerable to...",
    "myo_severity": "CRITICAL",
    "myo_score": 0.85,
    "cvss": { "nvd": 9.8, "ghsa": 9.8, "osv": null },
    "epss": { "score": 0.45, "percentile": 0.97 },
    "kev": { "is_known": true, "date_added": "2023-01-15" },
    "ghsa_id": "GHSA-35jh-r3h4-6jhm",
    "cwe": ["CWE-1321"],
    "cpe": ["cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*"],
    "affected_packages": [
      {
        "package": "lodash",
        "ecosystem": "npm",
        "affected_versions": ["<4.17.21"],
        "fixed_versions": ["4.17.21"],
        "status": "fixed"
      }
    ],
    "sources": ["nvd", "osv", "ghsa", "epss", "kev"]
  }
}
```

## Data Fields

| Field | Description |
|-------|-------------|
| `myo_severity` | CRITICAL/HIGH/MEDIUM/LOW based on myo_score |
| `myo_score` | Priority score (0.0-1.0) |
| `cvss.nvd/ghsa/osv` | CVSS scores from each source |
| `epss.score` | Exploit probability (0.0-1.0) |
| `kev.is_known` | Known exploited vulnerability |
| `affected_packages[].affected_versions` | Vulnerable version ranges |
| `affected_packages[].fixed_versions` | Patched versions |
| `affected_packages[].status` | `fixed` / `affected` / `unknown` |

## Myo Score Formula

```
MyoScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Data Sources

| Source | Data |
|--------|------|
| [NVD](https://nvd.nist.gov/) | CVSS, CWE, CPE, descriptions |
| [OSV](https://osv.dev/) | Affected packages, fixed versions |
| [GHSA](https://github.com/advisories) | Advisories, CVSS, fixed versions |
| [EPSS](https://www.first.org/epss/) | Exploit probability |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Active exploits |

## Development

```bash
npm install
npm run dev
npx wrangler deploy
```

## License

MIT
