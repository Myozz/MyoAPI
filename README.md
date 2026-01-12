# MyoAPI - CVE Aggregator API

Free, open-source CVE aggregator API that combines vulnerability data from multiple sources.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Cloudflare Workers](https://img.shields.io/badge/platform-Cloudflare%20Workers-orange.svg)

## Features

- **Multi-source data**: OSV.dev, EPSS, CISA KEV, NVD
- **Priority Score**: Custom scoring combining CVSS, EPSS, and KEV status
- **Fast**: Powered by Cloudflare Workers edge network
- **Free**: No API keys required

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/cve/:id` | Get CVE by ID |
| `GET /api/v1/cve/search` | Search CVEs with filters |
| `GET /api/v1/cve/recent` | Recent CVEs |
| `GET /api/v1/stats` | Statistics |
| `GET /api/v1/stats/health` | Health check |

## Usage

```bash
# Get CVE info
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400

# Search
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"

# Stats
curl https://api.myoapi.workers.dev/api/v1/stats
```

## Priority Score Formula

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV_bonus × 0.2)
```

| Component | Weight | Description |
|-----------|--------|-------------|
| CVSS | 30% | Technical severity (0-10) |
| EPSS | 50% | Exploit probability (0-1) |
| KEV | 20% | Actively exploited in the wild |

## Development

```bash
# Install
npm install

# Dev server
npm run dev

# Type check
npm run typecheck

# Deploy
npm run deploy
```

## Data Sync

Data is synced daily via GitHub Actions at 09:00 Vietnam time.

Manual sync: Run the workflow from GitHub Actions tab.

## License

MIT
