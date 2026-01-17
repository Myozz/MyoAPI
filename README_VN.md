# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Điểm ưu tiên = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Multi-source CVSS**: Điểm từ NVD, GHSA, OSV
- **Trạng thái bản vá**: Theo dõi fixed/affected
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
    "cvss": { "nvd": 9.8, "ghsa": 9.8, "osv": null },
    "epss": { "score": 0.45, "percentile": 0.97 },
    "kev": { "is_known": true, "date_added": "2023-01-15" },
    "ghsa_id": "GHSA-35jh-r3h4-6jhm",
    "cwe": ["CWE-1321"],
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

## Các trường dữ liệu

| Trường | Mô tả |
|--------|-------|
| `myo_severity` | CRITICAL/HIGH/MEDIUM/LOW |
| `myo_score` | Điểm ưu tiên 0.0-1.0 |
| `cvss.nvd/ghsa/osv` | Điểm CVSS từ từng nguồn |
| `epss.score` | Xác suất bị khai thác |
| `kev.is_known` | Đang bị khai thác |
| `affected_versions` | Phiên bản bị ảnh hưởng |
| `fixed_versions` | Phiên bản đã sửa |
| `status` | `fixed` / `affected` / `unknown` |

## Công thức Myo Score

```
MyoScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Phát triển

```bash
npm install
npm run dev
npx wrangler deploy
```

## Giấy phép

MIT
