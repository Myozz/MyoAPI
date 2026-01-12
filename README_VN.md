# MyoAPI - API Tổng hợp CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí từ nhiều nguồn khác nhau.

## Tính năng

- **Đa nguồn dữ liệu**: OSV.dev, EPSS, CISA KEV, NVD
- **Priority Score**: Điểm ưu tiên kết hợp CVSS, EPSS và KEV
- **Nhanh**: Chạy trên Cloudflare Workers edge network
- **Miễn phí**: Không cần API key

## API Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /api/v1/cve/:id` | Lấy thông tin CVE theo ID |
| `GET /api/v1/cve/search` | Tìm kiếm CVE |
| `GET /api/v1/cve/recent` | CVE gần đây |
| `GET /api/v1/stats` | Thống kê |
| `GET /api/v1/stats/health` | Health check |

## Cách dùng

```bash
# Lấy thông tin CVE
curl https://api.myoapi.workers.dev/api/v1/cve/CVE-2024-3400

# Tìm kiếm CVE nghiêm trọng
curl "https://api.myoapi.workers.dev/api/v1/cve/search?severity=CRITICAL&limit=10"

# Xem thống kê
curl https://api.myoapi.workers.dev/api/v1/stats
```

## Công thức Priority Score

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV_bonus × 0.2)
```

| Thành phần | Trọng số | Mô tả |
|------------|----------|-------|
| CVSS | 30% | Mức độ nghiêm trọng kỹ thuật (0-10) |
| EPSS | 50% | Xác suất bị khai thác trong 30 ngày tới (0-1) |
| KEV | 20% | Đã bị khai thác trong thực tế (CISA KEV) |

## Phát triển

```bash
# Cài đặt
npm install

# Chạy dev server
npm run dev

# Kiểm tra TypeScript
npm run typecheck

# Deploy lên Cloudflare
npm run deploy
```

## Đồng bộ dữ liệu

Dữ liệu được đồng bộ tự động hàng ngày lúc 09:00 (giờ Việt Nam) thông qua GitHub Actions.

Đồng bộ thủ công: Chạy workflow từ tab GitHub Actions.

## Giấy phép

MIT
