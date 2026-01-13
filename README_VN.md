# MyoAPI - API Tổng hợp CVE

API tổng hợp dữ liệu lỗ hổng bảo mật (CVE) miễn phí, mã nguồn mở.

## Tính năng

- **327K+ CVEs** từ NVD (1999-2026)
- **Đa nguồn dữ liệu**: CVSS, EPSS, CISA KEV
- **Priority Score**: Điểm ưu tiên tổng hợp
- **Nhanh**: Cloudflare Workers edge network
- **Miễn phí**: Không cần API key

## API Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /api/v1/cve/:id` | Lấy CVE theo ID |
| `GET /api/v1/cve/search` | Tìm kiếm CVE |
| `GET /api/v1/cve/recent` | CVE gần đây |
| `GET /api/v1/stats` | Thống kê |

## Nguồn dữ liệu

| Nguồn | Dữ liệu |
|-------|---------|
| NVD | CVSS scores, mô tả |
| EPSS | Xác suất bị khai thác |
| CISA KEV | CVE đã bị khai thác |

## Công thức Priority Score

```
PriorityScore = (CVSS/10 × 0.3) + (EPSS × 0.5) + (KEV × 0.2)
```

## Phát triển

```bash
npm install
npm run dev
npm run deploy
```

## Giấy phép

MIT
