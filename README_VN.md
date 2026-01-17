# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Điểm ưu tiên = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Multi-source CVSS**: Điểm từ NVD, GHSA, OSV
- **Tìm theo Package**: Query CVE theo package và ecosystem
- **Miễn phí**: Không cần API key

## Live API

```
https://api.myoapi.workers.dev
```

## Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /api/v1/cve/:id` | Lấy CVE theo ID |
| `GET /api/v1/cve/search` | Tìm kiếm với filters |
| `GET /api/v1/cve/package` | Tìm theo package |
| `GET /api/v1/cve/bulk` | Download hàng loạt |
| `GET /api/v1/cve/recent` | CVE gần đây |
| `GET /api/v1/stats` | Thống kê |

## Định dạng Response

```json
{
  "data": {
    "id": "CVE-2021-23337",
    "title": "Prototype Pollution in lodash",
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

## Các trường dữ liệu

| Trường | Nguồn | Mô tả |
|--------|-------|-------|
| `myo_severity` | Tính toán | CRITICAL/HIGH/MEDIUM/LOW |
| `myo_score` | Tính toán | Điểm ưu tiên 0.0-1.0 |
| `cvss.nvd` | NVD | Điểm CVSS từ NVD |
| `cvss.ghsa` | GHSA | Điểm CVSS từ GitHub |
| `cvss.osv` | OSV | Điểm CVSS từ OSV |
| `epss.score` | EPSS | Xác suất bị khai thác |
| `epss.percentile` | EPSS | Xếp hạng percentile |
| `kev.is_known` | CISA KEV | Đang bị khai thác |
| `kev.date_added` | CISA KEV | Ngày thêm vào KEV |
| `affected_packages` | OSV + GHSA | Packages bị ảnh hưởng |

## Công thức Myo Score

```
MyoScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

**Myo Severity:**

- `≥0.7` → CRITICAL
- `≥0.5` → HIGH
- `≥0.3` → MEDIUM
- `≥0.1` → LOW

## Phát triển

```bash
npm install
npm run dev
npx wrangler deploy
```

## Giấy phép

MIT
