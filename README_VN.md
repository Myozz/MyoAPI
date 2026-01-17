# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD CVSS, OSV packages, GHSA advisories, EPSS scores, CISA KEV
- **Priority Score**: Điểm ưu tiên = CVSS (30%) + EPSS (50%) + KEV (20%)
- **Tìm theo Package**: Query CVE theo tên package và ecosystem
- **Bulk Download**: API phân trang để sync dữ liệu lớn
- **Nhanh**: Chạy trên Cloudflare Workers
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
| GHSA Advisories | 714 |
| CISA KEV | 1,488 |

## API Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /api/v1/cve/:id` | Lấy CVE theo ID |
| `GET /api/v1/cve/search` | Tìm kiếm với filters |
| `GET /api/v1/cve/package` | Tìm theo package (cho scanner) |
| `GET /api/v1/cve/bulk` | Download hàng loạt |
| `GET /api/v1/cve/recent` | CVE gần đây |
| `GET /api/v1/stats` | Thống kê |

## Ví dụ sử dụng

### Lấy chi tiết CVE

```bash
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400
```

### Tìm theo Package (cho vulnerability scanner)

```bash
curl "https://api.myoapi.workers.dev/api/v1/cve/package?ecosystem=npm&name=lodash"
curl "https://api.myoapi.workers.dev/api/v1/cve/package?ecosystem=PyPI&name=requests"
```

### Tìm CVE CRITICAL

```bash
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"
```

### Bulk Download

```bash
curl "https://api.myoapi.workers.dev/api/v1/cve/bulk?limit=1000&offset=0"
```

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
    "affected_packages": [...]
  }
}
```

## Tham số Package Search

| Tham số | Bắt buộc | Mô tả |
|---------|----------|-------|
| `ecosystem` | Có | npm, PyPI, Go, Maven, etc. |
| `name` | Có | Tên package |
| `limit` | Không | Số kết quả (max 1000) |

## Công thức Priority Score

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

**Priority Severity:**

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
