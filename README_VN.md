# MyoAPI - API Tổng hợp Lỗ hổng CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **327K+ CVEs** từ NVD (1999-2026)
- **Đa nguồn dữ liệu**: NVD CVSS, OSV packages, EPSS scores, CISA KEV
- **Priority Score**: Điểm ưu tiên tổng hợp từ CVSS, EPSS và KEV
- **Nhanh**: Chạy trên Cloudflare Workers edge network
- **Miễn phí**: Không cần API key

## Live API

```
https://api.myoapi.workers.dev
```

## API Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /api/v1/cve/:id` | Lấy CVE theo ID |
| `GET /api/v1/cve/search` | Tìm kiếm với filters |
| `GET /api/v1/cve/recent` | CVE gần đây |
| `GET /api/v1/stats` | Thống kê database |
| `GET /api/v1/stats/health` | Health check |

## Ví dụ sử dụng

```bash
# Lấy chi tiết CVE
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400

# Tìm CVE CRITICAL
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"

# Lọc theo KEV (đang bị khai thác)
curl "https://api.myoapi.workers.dev/api/v1/cve/search?isKev=true&limit=20"
```

## Tham số tìm kiếm

| Tham số | Mô tả | Ví dụ |
|---------|-------|-------|
| `severity` | CRITICAL, HIGH, MEDIUM, LOW | `severity=CRITICAL` |
| `isKev` | Đang bị khai thác | `isKev=true` |
| `hasOsv` | Có dữ liệu package | `hasOsv=true` |
| `limit` | Số kết quả (max 100) | `limit=20` |

## Nguồn dữ liệu

| Nguồn | Dữ liệu |
|-------|---------|
| NVD | CVSS scores, mô tả chi tiết |
| OSV | Packages bị ảnh hưởng |
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
