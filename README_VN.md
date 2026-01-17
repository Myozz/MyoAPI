# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD, OSV, GHSA, EPSS, CISA KEV
- **Myo Score**: Điểm ưu tiên = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Multi-source Data**: Dữ liệu từ tất cả nguồn với fallback
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
    "id": "CVE-2023-4863",
    "myo_severity": "CRITICAL",
    "myo_score": 0.92,
    "cvss": { "nvd": 9.8, "ghsa": null, "osv": null },
    "epss": { "score": 0.75, "percentile": 0.99 },
    "kev": { "is_known": true, "date_added": "2023-09-13" },
    "affected_packages": [
      {
        "package": "libwebp",
        "ecosystem": "unknown",
        "vendor": "google",
        "affected_versions": ["1.3.1"],
        "fixed_versions": [],
        "status": "affected"
      }
    ],
    "sources": ["nvd", "osv", "epss", "kev"]
  }
}
```

## Ưu tiên dữ liệu

| Trường | Ưu tiên |
|--------|---------|
| `cvss` | Hiển thị từ tất cả nguồn |
| `affected_packages` | OSV > GHSA > NVD (từ CPE) |
| `fixed_versions` | OSV/GHSA ranges > patched_versions |

Nếu OSV và GHSA không có package info, sẽ lấy từ NVD CPE.

## Các trường dữ liệu

| Trường | Mô tả |
|--------|-------|
| `myo_severity` | CRITICAL/HIGH/MEDIUM/LOW |
| `myo_score` | Điểm ưu tiên 0.0-1.0 |
| `vendor` | Tên vendor từ CPE (chỉ NVD) |
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
