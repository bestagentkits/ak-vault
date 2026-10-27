# Bật vault token và revocation trên ak-web production

**Ngày:** 2026-10-16 (Asia/Saigon)

## Kết quả
Production (https://agentkit.best) **đã bật sẵn** trước khi task bắt đầu. Cấu hình có trong lần deploy CI của `main` tại `187e09c5` (release `claudekit-web-649`, có #571 `671f4352`) và không bị sửa tay sau deploy đó. Vì vậy hôm nay không cần đổi code hay config, không mở PR, không xoay secret và không cần duyệt deploy production nào.

## Kiểm kê (chỉ ghi tên, không đọc giá trị secret)
- Route env: các biến môi trường của DXUP/Diginext được `dx up` đưa vào deployment `claudekit-web` (context `dxup`, ns `claudekit-prod`). Không có file cấu hình nào trong repo.
- `VAULT_TOKENS_ENABLED=true`
- `VAULT_TOKEN_AUDIENCE=https://vault.agentkit.best`
- `VAULT_REVOCATION_WEBHOOK_URL=https://vault.agentkit.best/internal/v1/revocations`
- `VAULT_REVOCATION_WEBHOOK_SECRET`: đã set, dài ≥32 ký tự
- `MCP_OAUTH_ISSUER=https://agentkit.best`; `MCP_OAUTH_SIGNING_JWK` đã set
- Các giá trị này khớp với Worker (`worker/wrangler.jsonc` top level): issuer, audience và JWKS URL.

## Bằng chứng
- JWKS: 200, có 1 key ES256. Kiểm tra trong pod xác nhận kid của signing key có trong JWKS công khai. AS metadata `issuer`/`jwks_uri` khớp.
- Mint `POST /api/agentkit/vault/token`:
  - không auth: 401 `not_authenticated`;
  - bearer sai: 401.
  
  Khi flag tắt route trả 404, nên 401 nghĩa là flag đang bật. `GET /api/account/vault/devices` không auth: 401.
- Khớp webhook secret: từ pod production (dùng env của chính pod, secret không ra khỏi pod), gửi một event no-op đã ký với các list rỗng:
  - secret của pod: **400** `bad_request` (HMAC hợp lệ; Worker kiểm HMAC trước khi parse body, batch rỗng bị từ chối, không ghi gì);
  - secret sai: **401**.
  
  Kết luận: secret khớp với `REVOCATION_WEBHOOK_SECRET` của Worker và URL đi tới được.
- Outbox: `vault_revocation_events` = 0 dòng; `vault_device_keys` = 0 dòng. Chưa có event thật nào để giao. Cron giao event có trong crontab của pod và crond đang chạy. K8s CronJob chưa apply (cần duyệt, đúng như tài liệu).
- Worker `/healthz`: `sync_enabled=false`. Webhook revocation nằm ngoài kill switch, nên khi Worker còn tắt sync thì phản hồi mong đợi là 2xx/4xx, không phải 503 `sync_disabled`.

## Thay đổi đã làm
- Không đổi code hay config, nên không cần review.
- Tạo label `shipped` trên ak-web (repo chưa có).
- ak-web#568: comment bằng chứng, thêm `shipped`, bỏ `in progress`, để issue mở vì còn tiêu chí review bảo mật riêng.
- ak-vault#8: comment cross-link, ghi rõ comment này không chứng nhận external review.

## Dọn dẹp
- Port-forward tạm tới `svc/postgresql` đã dừng.
- Đã xoá file tạm. Không tạo process nào khác.

## Câu hỏi còn mở
- Ai đã đưa các biến VAULT_* vào DXUP production, và chủ sở hữu có ghi nhận việc đó không? Production bật trước khi có yêu cầu hôm nay.
- Có cần kiểm thử giao event thật bằng cách revoke một session tổng hợp trên production không? Hiện mới có probe no-op.
- ak-web #568 có tiêu chí "review thiết kế/bảo mật riêng trước production". Tiêu chí này chưa tick, nhưng production đã bật.
