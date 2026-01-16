# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **328K+ CVEs** từ NVD (1999-2026)
- **5 nguồn dữ liệu**: NVD CVSS, OSV packages, GHSA advisories, EPSS scores, CISA KEV
- **Priority Score**: Điểm ưu tiên tổng hợp từ CVSS, EPSS và KEV
- **Nhanh**: Chạy trên Cloudflare Workers edge network
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
| `GET /api/v1/cve/recent` | CVE gần đây |
| `GET /api/v1/stats` | Thống kê database |

## Ví dụ sử dụng

```bash
# Lấy chi tiết CVE
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400

# Tìm CVE CRITICAL
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"
```

## Nguồn dữ liệu

| Nguồn | Dữ liệu |
|-------|---------|
| NVD | CVSS scores, mô tả chi tiết |
| OSV | Packages bị ảnh hưởng |
| GHSA | GitHub Security Advisories |
| EPSS | Xác suất bị khai thác |
| CISA KEV | CVE đang bị khai thác |

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
