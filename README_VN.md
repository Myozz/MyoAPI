# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Priority Score**: Điểm ưu tiên = CVSS (30%) + EPSS (50%) + KEV (20%)
- **CWE & CPE**: Loại lỗ hổng và định danh sản phẩm từ NVD
- **Tìm theo Package**: Query CVE theo tên package và ecosystem
- **Fixed Versions**: Thông tin khắc phục từ GHSA/OSV
- **Miễn phí**: Không cần API key

## Live API

```
https://api.myoapi.workers.dev
```

## Thống kê dữ liệu

| Nguồn | Số lượng |
|-------|----------|
| Tổng CVEs | 328,132 |
| NVD CVSS | 303,561 |
| EPSS Scores | 311,012 |
| OSV Packages | 22,624 |
| GHSA Advisories | ~20,000+ |
| CISA KEV | 1,488 |

## API Endpoints

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
    "severity": "CRITICAL",
    "priority_severity": "CRITICAL",
    "priority_score": 0.85,
    "cvss_score": 9.8,
    "epss_score": 0.45,
    "is_kev": true,
    "ghsa_id": "GHSA-35jh-r3h4-6jhm",
    "cwe": ["CWE-1321"],
    "cpe": ["cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*"],
    "fixed_versions": ["4.17.21"],
    "affected_packages": [...],
    "sources": ["nvd", "osv", "ghsa", "epss", "kev"]
  }
}
```

## Các trường dữ liệu

| Trường | Nguồn | Mô tả |
|--------|-------|-------|
| `id` | NVD/OSV/GHSA | CVE ID (deduplicated) |
| `cwe` | NVD + GHSA | Loại lỗ hổng (merged) |
| `cpe` | NVD | Định danh sản phẩm |
| `fixed_versions` | GHSA/OSV | Phiên bản đã sửa |
| `affected_packages` | OSV + GHSA | Packages bị ảnh hưởng |
| `priority_severity` | Calculated | CRITICAL/HIGH/MEDIUM/LOW |

## Công thức Priority Score

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Phát triển

```bash
npm install
npm run dev
npx wrangler deploy
```

## Giấy phép

MIT
