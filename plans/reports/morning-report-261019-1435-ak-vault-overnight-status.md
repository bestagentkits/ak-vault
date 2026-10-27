# Báo cáo trạng thái — ak-vault / ak-web / agentkit

Thời điểm: 2026-10-19 14:35 (Asia/Saigon). Báo cáo trễ vì agent #2299 và phiên này chạm giới hạn sử dụng tuần từ sáng 17/10 đến 19/10 14:00.

## 1. Đã land

**ak-vault**
- #100 policy binding (spec §8.1, vectors `policy-binding.json`: 14 accepted / 31 rejected) — commit 90d4e72.
- Deploy run 38952924204 (90d4e72): gate ✅, staging ✅, production ✅ — chủ sở hữu đã duyệt. Không còn run nào đang chờ duyệt.
- Không tạo tag (quyết định release thuộc chủ sở hữu).

**agentkit (dev, qua train)**
- 05e27fe5f — #2507 từ chối log khôi phục mọc vượt kept head.
- 7d7f6b965 — #2510 khoá digest release manifest bằng secret riêng mỗi home.
- 107983e3c — #2517 mở sync state chỉ-đọc cho reader trên release path.
- 2d8447a43 — client #2475: đăng ký thiết bị sync qua API-key device session (#2499 đã đóng).
- 798bbfc41, 90432ee22 — sửa ref ký tự vô hình, allowlist `ak secrets annotate`.
- Beta tự động: v3.0.0-beta.32 → beta.34 (18/10). Không cắt beta thủ công.

**ak-web (dev → production)**
- #605, #612, #620, #622 (gia hạn kit 12 tháng, giá gia hạn admin, provider reference, endpoint xác minh thanh toán) — từ phiên khác, ghi nhận để biết.

## 2. Đang mở

| PR | Trạng thái | Ghi chú |
|---|---|---|
| agentkit#2500 | CONFLICTING | profile chọn secret; agent #2299 đang rebase |
| agentkit#2511 | draft, mergeable, CI xanh | `ak secrets request` + scope exec |
| agentkit#2512 | draft, mergeable, CI xanh | chạy chương trình với secret được cấp |
| agentkit#2509 | draft | desktop hiển thị profile; phiên cloud của nó liên tục thêm lại attribution |
| PR4 (#7 mục 1, 5) | chưa mở | thay port kept-head bằng `akv1.VerifyChangeLog` upstream |
| ak-web#593 | mergeable chưa xác định | vẫn mở, cần xem lại xung đột |

Agent #2299 đã được tiếp tục lúc 14:30: rebase #2500 → restack #2511/#2512 → PR4 (đo latency, full suite, review cô lập, draft).

## 3. Kết quả kiểm thử

- **Lab ramp / registry throughput**: xong trước đó (báo cáo 261016-1830).
- **Staging API-key sync**: **BLOCKED** — staging trả 401 với `AGENTKIT_API_KEY` (key production). Chi tiết: `tester-261017-0130-staging-api-key-sync.md`.
- **Red-team kịch bản 13 (chạy lại)**: chưa chạy; chờ stack #2500/#2511/#2512 + PR4 land. Phiên peer phụ trách.

## 4. Gate #8

#8 vẫn OPEN, nhãn `blocked`. Production sync chạy dưới waiver của chủ sở hữu (16/10) — **không phải** sign-off; review bên ngoài vẫn chờ. Các mục mở còn lại xem `docs/security/release-gates.md`.

## 5. Quyết định tự chủ cần chủ sở hữu xem lại

1. #2500: thu hẹp phạm vi fingerprint lưu trữ chỉ cho giá trị dạng token (≥22 ký tự, ≥128 bit ước tính, entropy ≥3.0, không chuỗi giống từ) để tránh oracle đoán offline — lệch so với câu chữ đã duyệt.
2. Từ vựng sensitivity của profile: `normal|high`.
3. Giữ `decrypt_failed` từ chối toàn vault khi một record không mở được (thông báo cho người dùng phải rõ).
4. PR4 pin pseudo-version của ak-vault, không tạo tag.
5. Đóng #2484 vì bị thay thế.
6. Tách mục 1 và 5 của #7 sang PR4 riêng.

## 6. Việc khác

- Đã gỡ dòng attribution AI khỏi body: ak-web#623; agentkit#2596, #2594, #2581, #2572, #2567, #2562, #2561, #2560, #2549, #2529.
- Không có dev server / watcher nào của phiên này đang chạy.

## Câu hỏi chỉ chủ sở hữu trả lời được

1. Cấp `AGENTKIT_STAGING_API_KEY` (key staging, bật vault sync) để chạy lại kiểm thử staging API-key? Đặt vào `.env` của ak-vault, không dán vào chat.
2. Chấp nhận phạm vi fingerprint dạng token của #2500 (mục 5.1) hay quay về câu chữ ban đầu?
3. Khi nào tạo tag ak-vault để PR4 chuyển từ pseudo-version sang tag?
4. Tiến độ review bên ngoài cho #8?
