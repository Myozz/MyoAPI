# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Điểm ưu tiên = CVSS (30%) + EPSS (50%) + KEV (20%)
- **CWE & CPE**: Loại lỗ hổng và định danh sản phẩm
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
    "cvss_score": 9.8,
    "epss_score": 0.45,
    "is_kev": true,
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
| `cvss_score` | NVD > GHSA > OSV | Điểm CVSS |
| `epss_score` | EPSS | Xác suất bị khai thác |
| `affected_versions` | OSV/GHSA | Phiên bản bị ảnh hưởng |
| `fixed_versions` | OSV/GHSA | Phiên bản đã sửa |

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
