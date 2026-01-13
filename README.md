# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API that combines vulnerability data from multiple authoritative sources.

![Cloudflare Workers](https://img.shields.io/badge/platform-Cloudflare%20Workers-orange.svg)
![Supabase](https://img.shields.io/badge/database-Supabase-green.svg)

## Features

- **327K+ CVEs** from NVD (1999-2026)
- **Multi-source data**: CVSS, EPSS, CISA KEV
- **Priority Score**: Custom scoring combining CVSS, EPSS, and KEV
- **Fast**: Cloudflare Workers edge network
- **Free**: No API keys required

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/cve/:id` | Get CVE by ID |
| `GET /api/v1/cve/search` | Search CVEs with filters |
| `GET /api/v1/cve/recent` | Recent CVEs |
| `GET /api/v1/stats` | Statistics |

## Usage

```bash
# Get CVE details
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400

# Search CRITICAL CVEs
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"
```

## Data Sources

| Source | Data | Update |
|--------|------|--------|
| NVD | CVSS scores, descriptions | Daily |
| EPSS | Exploit probability | Daily |
| CISA KEV | Actively exploited | Daily |

## Priority Score

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Development

```bash
npm install
npm run dev
npm run deploy
```

## License

MIT
