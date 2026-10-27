# Gói tài liệu review bảo mật cho owner: ak-vault (issue #8)

- Ngày soạn: 2026-10-16 16:09 (Asia/Saigon). Người soạn: agent (chỉ đọc, không sửa repo).
- Mục đích: owner tự làm review cho release gate "External review" trên
  [#8](https://github.com/bestagentkits/ak-vault/issues/8), theo quyết định của owner lúc 16:09 ngày 2026-10-16.
  Review này **không phải review độc lập của bên thứ ba**. Giới hạn đó phải ghi rõ trong kết quả.
- Thời lượng dự kiến: khoảng 100 phút (xem phân bổ ở cuối mục 2).

## 0. Commit cần ghim trước khi bắt đầu

Ghi các commit này vào kết quả trên #8. Nếu một repo đã đổi trước khi bạn post, ghi commit mới.

| Repo | Ref đã đọc | Ghi chú |
|---|---|---|
| ak-vault | `origin/main` = `02748f4` | Mọi path:line `ak-vault:` bên dưới là ở commit này |
| ak-web (claudekit-web) | `origin/main` = `187e09c5` | Theo ak-web#568, production chạy `187e09c5`. `origin/dev` có cùng nội dung các file vault |
| agentkit | `v3.0.0-beta.31` = `origin/dev` = `4aff1984b` | Đã có fence client `67ff8e6` (agentkit#2469 đóng lúc 2026-10-16 08:53Z) |

Lệnh kiểm tra nhanh: `git -C <repo> rev-parse --short origin/main`. Riêng agentkit: `git rev-parse --short 'v3.0.0-beta.31^{commit}'`.

---

## 1. Hệ thống đảm bảo gì và KHÔNG đảm bảo gì

**Các đảm bảo được nêu** (nguồn: [threat-model.md](../../docs/security/threat-model.md), mục Invariants dòng 55-72, và [spec](../../docs/protocol/v1/spec.md)):

1. Server chỉ giữ ciphertext. Nó không bao giờ nhận plaintext của value, name, profile, policy hay audit, và không giữ key nào giải mã được chúng ([data-classification.md](../../docs/security/data-classification.md)).
2. Mỗi request chỉ được phục vụ khi qua đủ bốn kiểm tra: token ES256 (iss/aud/exp/nbf chính xác), `AKV-Proof` ký bằng key của device, tra revocation live, và membership. Nếu không tra được revocation thì trả 503 (fail closed).
3. Mọi device/member/recipient đều phải do một event có chữ ký owner thêm vào, trong một chuỗi hash. Device chỉ dùng wrap nằm trong tập mà `wraps_digest` đã ký bao phủ.
4. Mọi lần ghi đều là CAS theo `base_revision`. Khi xung đột, server trả `409` và giữ lại nhánh xung đột. Không có last-writer-wins. Tombstone tồn tại suốt đời vault.
5. Removal fence: mỗi lần remove đều ký `log_fence` và `log_head`. Client từ chối một prefix log khác với bản đã ký, và từ chối record của device đã bị remove nằm phía trên fence.
6. Checkpoint do client ký: client không chấp nhận state cũ hơn, hoặc rẽ nhánh khỏi, checkpoint mà nó đã chứng kiến.
7. Version, alg, loại event, epoch hay chữ ký không xác định đều bị từ chối (fail closed).
8. Khi sync tắt, client không gửi request mạng nào. `resolve` không bao giờ phải chờ mạng.

**KHÔNG đảm bảo** (threat-model.md dòng 111-205, "Explicit limitations"):

- **Giữ lại update chưa từng thấy:** server độc hại có thể "đóng băng" một device mới hoặc offline lâu ở bất kỳ state nào nó chưa chứng kiến. v1 không có transparency log. Test: `ak-vault: packages/protocol/test/red-team-withheld-updates.test.ts`.
- **Key dùng chung cho cả vault:** role không tạo ra ranh giới đọc theo từng secret.
- **Không thu hồi được (no clawback):** giá trị mà device bị remove đã giải mã thì vẫn lộ. Bắt buộc phải rotate ở phía provider.
- `run` giao plaintext cho child process. Giao thức không bảo vệ được một client local đã bị chiếm.
- **Recovery bundle:** ai giữ session sống của tài khoản owner đều tải được ciphertext và đoán mật khẩu offline. Machine identity trên tài khoản owner cũng đi được đường này ([#42](https://github.com/bestagentkits/ak-vault/issues/42)).
- **Audit không ký theo tác giả.** Record không được đối chiếu với lịch sử role ([#22](https://github.com/bestagentkits/ak-vault/issues/22)).
- **Fence chỉ ràng buộc log như người remove đã thấy nó.** Phía trên fence mới nhất, chỉ có checkpoint bảo vệ.
- **Restore là rollback:** chỉ device nào đã chứng kiến checkpoint mới hơn mới phát hiện được (T8, dòng 95). v1 không tự hội tụ lại (ADR, Open items dòng 141).
- **Live tail lộ giá trị header `AKV-Proof` và `AKV-Webhook-Signature`** (owner đã waiver, [#61](https://github.com/bestagentkits/ak-vault/issues/61)).
- **Production sync đang chạy trước review** (owner waiver). Chưa khuyến nghị dùng cho credential production.
- **Metadata server nhìn thấy được:** số item, kích thước, thời điểm, revision, membership, public key của device.

---

## 2. Checklist review (rủi ro cao nhất trước)

Với mỗi mục, đọc theo thứ tự: **Câu hỏi**, **Đọc**, **Bằng chứng tự nhận**, **Pass khi**. Riêng **Ghi chú agent** là những điểm agent thấy khi đọc. Hãy tự kiểm chứng, đừng tin sẵn.

### R1. Xác thực token: alg/iss/aud/exp/nbf, nguồn key, jti (≈15 phút)

- **Câu hỏi:** Worker có chấp nhận token nào không do ak-web production mint cho đúng audience vault không? Có token nào được chấp nhận với alg/key/claim yếu hơn không?
- **Đọc:**
  - `ak-vault: worker/src/auth/jwt-verify.ts:81-130`. Thứ tự kiểm tra: `alg` phải đúng `ES256` (87); cấm `crit/jku/jwk/x5u/x5c` (37, 89); verify chữ ký trước khi đọc claims (99-102); `iss` chính xác (105); `aud` chính xác, mảng chỉ được 1 phần tử (64-67, 106); exp/nbf/iat với skew 60 s (107-114); `did` phải là b64 của 16 byte (115-120); `scope` ⊆ {vault:read, vault:write} (69-78).
  - `ak-vault: worker/src/auth/jwks.ts:57-87`. Chỉ nhận JWKS qua `https://` (66), cache 5 phút, khi lỗi thì backoff 30 s và fail closed (94-103). **`VAULT_JWKS_JSON` inline được ưu tiên hơn URL (58-64, 80).**
  - `ak-vault: worker/wrangler.jsonc:35-40` (prod) và `:55-61` (staging): issuer, audience, JWKS URL.
  - ak-web: `lib/oauth/keys.ts:71-82` (`signVaultAccessToken`: iss, aud, sub, iat=nbf, exp, jti, sid, did, scope) và `app/api/agentkit/vault/token/route.ts:13` (TTL 300 s).
  - ak-web: `lib/oauth/keys.ts:33-40` (`signAccessToken` lấy `aud` từ `resource`) và `lib/oauth/protocol.ts:103-107` (`resourcePolicy` là allowlist `OAUTH_RESOURCES`).
- **Bằng chứng tự nhận:** `ak-vault: worker/test/auth-token.test.ts:32-114` (sai aud/iss, expired, nbf ở tương lai, alg none/HS256, kid lạ, tách audience giữa môi trường, issuer/JWKS URL đã deploy không có key inline, JWKS không tới được thì 503); `worker/test/red-team-token-and-proof.test.ts:40-66` (key giả mạo dùng kid thật, jwk/jku nhúng, đổi nhãn alg); `worker/test/jwks-cache.test.ts`.
- **Pass khi:**
  - Không có đường nào chấp nhận token khi chưa verify chữ ký ES256 bằng key lấy từ JWKS URL của chính môi trường đó.
  - Production **không** có secret `VAULT_JWKS_JSON`. Test chỉ kiểm tra `wrangler.jsonc`, không kiểm tra secret. Kiểm tra bằng `wrangler secret list --env=""` (chỉ in tên).
  - `OAUTH_RESOURCES` không chứa `https://vault.agentkit.best`, nên OAuth server chung của ak-web không mint được token có aud là vault. Đây là lớp phòng thủ thứ hai: token OAuth không có `did/sid` và scope vault, nên `jwt-verify.ts:115-128` vẫn từ chối.
  - JWKS staging và production không chung key material (so sánh `x`/`y`). Mục này **vẫn mở** theo release-gates.md:20-22, 179-182.
- **Ghi chú agent:** `jti` của token là bắt buộc nhưng **không** được đánh dấu dùng một lần. Đây là thiết kế (spec §9.1, spec.md:400-406). Chống replay dựa vào `jti` của proof (R2) cộng với TTL 300 s. Nếu bạn chấp nhận như vậy, ghi rõ điều đó trong kết quả.

### R2. Proof gắn với device (`AKV-Proof`) (≈10 phút)

- **Câu hỏi:** Kẻ có token bị đánh cắp nhưng không có private key của device có làm được gì không? Một proof có bị replay, hoặc chuyển sang URL/body/token/vault khác được không?
- **Đọc:**
  - `ak-vault: packages/protocol/src/proof.ts:100-110`. Thứ tự: chữ ký, rồi htm, htu (URL đầy đủ, kèm query), rồi ±60 s, rồi `ath` = sha256(token), rồi `bh` = sha256(body), rồi replay.
  - `ak-vault: worker/src/vault/request-guard.ts:34-54`. `jti` bị "đốt" theo từng `did` trong SQLite của DO vault, TTL 120 s (`limits.ts:68-70`).
  - `ak-vault: worker/src/vault/vault-authorization.ts:130-145`. Membership được kiểm tra trước (`memberDevice`, request-guard.ts:61-66: `did` phải là device hiện tại **của chính `sub`**), sau đó tới proof, scope, rồi role.
  - Đường recovery identity: `vault-authorization.ts:114-128` (device ngoài membership của tài khoản owner, `did == kid(AKV-Device-Key)`).
  - `ak-vault: worker/src/routes/api-handler.ts:34-56`: `htu = request.url`.
  - Go: `go/akv1/proof.go:159` (`VerifyProof`). Client: `agentkit: apps/cli/internal/runtime/secretsync/akvhttp/proof_headers.go:64`.
- **Bằng chứng tự nhận:** `worker/test/auth-token.test.ts:116-155`; `worker/test/red-team-token-and-proof.test.ts:67-110` (proof của query khác, proof của token khác, proof chuyển giữa hai vault, token bị đánh cắp không có key); vector `protocol/v1/vectors/proof.json`.
- **Pass khi:** Không route nào đọc hay ghi dữ liệu vault trước khi proof qua. `jti` được lưu trước khi trả lời. Kiểm tra skew và TTL dùng chung một nguồn `LIMITS`.
- **Ghi chú agent:** Rate limit chạy **trước** proof (`vault-durable-object.ts:77`). Vì vậy kẻ chỉ có token cũng đốt được quota của device đó ([#41](https://github.com/bestagentkits/ak-vault/issues/41), DoS, không lộ dữ liệu). Genesis (`vault-authorization.ts:72-82`) cho phép bất kỳ tài khoản đăng nhập nào tạo vault tại một vault ID chưa tồn tại. Hãy xác nhận vault ID là ngẫu nhiên 16 byte do client sinh ra (`packages/protocol/src/device-keys.ts:40`, `randomId`), để việc chiếm trước ID không có ý nghĩa.

### R3. Webhook revocation, registry và fail-closed (≈15 phút)

- **Câu hỏi:** Session/device bị thu hồi có bị từ chối ở request kế tiếp không? Nếu webhook lỗi, khoảng hở tối đa là bao lâu? Có ai giả mạo hoặc replay được webhook không?
- **Đọc:**
  - `ak-vault: worker/src/routes/revocation-webhook.ts:67-100`: secret ≥ 32 ký tự, nếu không có thì 503 (69-70); timestamp ±300 s (75); HMAC trên `ts\nbody`, so sánh thời gian hằng (26-30, 86-89); thiếu chữ ký thì không parse body; `event_id` trùng thì trả 409.
  - `ak-vault: worker/src/revocation/revocation-registry.ts:43-68`: đơn điệu (`INSERT OR IGNORE`, `MAX(min_iat)`), `event_id` được nhớ 15 phút.
  - `ak-vault: worker/src/auth/revocation-check.ts:12-21`: lỗi bất kỳ thì 503, kết quả khác `false` thì 401.
  - ak-web: `lib/vault/vault-revocation-delivery.ts:50-61` (ký; 2xx/409 = đã giao), `:64-66` (backoff 30 s tới 1 h), `:33` (`VAULT_WEBHOOK_MAX_ATTEMPTS = 20`, sau đó là `failed` và phải requeue thủ công).
  - ak-web: các nơi enqueue trong cùng transaction: `lib/agentkit-registry/device-sessions.ts:228, 347, 375`; `lib/vault/vault-device-keys.ts:106-133`; xoá tài khoản `app/api/gdpr/delete-account/route.ts:84`; admin orphan/claim-email/merge.
  - ak-web: `app/api/cron/deliver-vault-revocations/route.ts:12-25` (Bearer `CRON_SECRET`, `timingSafeEqual`).
- **Bằng chứng tự nhận:** `worker/test/revocation.test.ts:13-77` (sid bị thu hồi, did bị thu hồi, min_iat, HMAC sai, timestamp cũ, replay, secret cũ trong lúc rotate, không có secret thì 503, registry hỏng thì 503); ak-web `__tests__/lib/vault/vault-revocation-delivery.test.ts`, `__tests__/api/cron-deliver-vault-revocations.test.ts`.
- **Pass khi:** Mọi đường đăng xuất, thu hồi device hay xoá tài khoản ở ak-web đều enqueue trong cùng transaction. Registry lỗi thì luôn 503.
- **Ghi chú agent:**
  - Khoảng hở khi webhook không tới được bị chặn bởi TTL token 300 s. Lý do: lúc mint, ak-web kiểm tra lại session (`token/route.ts:63, 85`) và trạng thái revoked của device (`vault-device-keys.ts:47-67`). Hãy xác nhận lập luận này.
  - Sau 20 lần gửi thất bại, event bị bỏ cho tới khi có người requeue. Cần có alert.
  - Registry là **một DO toàn cục**, trần đo được khoảng 10 lượt kiểm tra/giây (release-gates.md:36-42). Vượt trần thì 503 cho mọi người. Chưa có alert ([#65](https://github.com/bestagentkits/ak-vault/issues/65)).
  - `revoked_dids` là danh sách toàn cục. An toàn vì ak-web ràng buộc vĩnh viễn `did = kid(sign_pub)` với một tài khoản (`vault-device-keys.ts:37-56`), nên user A không thu hồi được did của user B.

### R4. Membership, chữ ký và removal fence (≈20 phút, phần lõi mật mã)

- **Câu hỏi:** Server hoặc member có thể chèn device/recipient, dựng lại một record đã bị thay, hoặc chấp nhận record của device đã bị remove nằm trên fence không? TypeScript và Go có hành xử giống hệt nhau không?
- **Đọc:**
  - `ak-vault: packages/protocol/src/membership-log.ts:67-105`: seq/prev/epoch; genesis đối chiếu `trustedAnchor` (88); `key_epoch` không giảm; witnessed checkpoint chống rollback/fork (98-103). **`trustedAnchor` và `witnessedCheckpoint` là tuỳ chọn.** Client bắt buộc phải truyền vào (xem R6).
  - `ak-vault: packages/protocol/src/membership-rules.ts`: chỉ device human có role owner mới được làm tác giả (dòng 100-101); recovery key chỉ được `device_add` owner (96, 116-117); không được remove/demote owner cuối cùng (135, 167, 178); rekey tăng đúng 1 (184).
  - `ak-vault: packages/protocol/src/removal-fence.ts:40-62` (`verifyLoggedRecord`) và `packages/protocol/src/change-log.ts:103-138` (`verifyChangeLog`: liên tục, khớp head tại fence, `keptHeads`, `complete`).
  - Go tương ứng: `go/akv1/membership_log.go:76`, `go/akv1/removal_fence.go:20`, `go/akv1/change_log.go:104`, `go/akv1/checkpoints.go:123`.
  - Phía Worker: `worker/src/vault/membership-handlers.ts:43-56` (fence phải bằng đúng head: lớn hơn thì 400, nhỏ hơn thì 409; `log_head` phải khớp log đang lưu); `membership-store.ts:46`.
- **Bằng chứng tự nhận:** các vector `protocol/v1/vectors/{membership,removal-fence,device-add-wraps,checkpoints,records}.json`, chạy ở cả TS (`packages/protocol/test/vectors-*.test.ts`) lẫn Go (`go/akv1/vectors_*_test.go`), và CI kiểm tra vector tái tạo được (`.github/workflows/ci.yml:29-30`); `worker/test/removal-fence-binds-log.test.ts:51-120`; `worker/test/removal-fence-and-recovery-rotation.test.ts`; `worker/test/signed-wrap-sets.test.ts`; `worker/test/membership.test.ts`.
- **Pass khi:**
  - Mọi vector bị từ chối đều cho cùng error code ở cả TS và Go.
  - Không có đường nào lấy kind/revision/resolution từ field server gửi.
  - Bạn tự chạy `pnpm test` và `cd go && go test ./...` ở commit đã ghim, và cả hai đều xanh.
- **Ghi chú agent:**
  - Hiện **không có** test hay vector chứng minh rằng log bị restore rồi mọc lại sẽ bị từ chối. Chỉ `checkRollback` thì lại cho qua trường hợp đó ([#76](https://github.com/bestagentkits/ak-vault/issues/76)).
  - Record không được đối chiếu với lịch sử role ([#22](https://github.com/bestagentkits/ak-vault/issues/22)).

### R5. Restore và rollback; gating của route restore cho operator (≈10 phút)

- **Câu hỏi:** Ai làm được restore? Có thể replay, chạy sai môi trường, hay đụng vào registry không? Sau khi restore, client xử lý ra sao?
- **Đọc:**
  - `ak-vault: worker/src/routes/operator-restore.ts:112-148`: không có secret ≥ 32 ký tự thì trả 404 (113-115); HMAC nằm **trong body** chứ không ở header (118-128, 71-74); `origin` và ±60 s (77-84); chỉ binding `VAULT` (132), không có registry.
  - `ak-vault: worker/src/vault/point-in-time-restore.ts:71-79`: CAS trên bookmark; `markPending` chạy trước lời gọi platform.
  - `ak-vault: worker/src/vault/vault-durable-object.ts:72, 98-100, 108-143`: trong lúc restore đang pending thì từ chối mọi request.
  - `ak-vault: worker/src/index.ts:37-41`: route này độc lập với kill switch.
  - Runbook: `docs/operations/runbooks.md:263` (Durable Object backup and restore). Bằng chứng: `docs/operations/rehearsal-2026-10.md` (staging restore 2026-10-16).
- **Bằng chứng tự nhận:** `worker/test/operator-restore.test.ts:50-252` (404 khi không có secret, sai chữ ký, origin/±60 s, CAS cũ, pending, restart, không echo lỗi platform).
- **Pass khi:**
  - Production hiện **không** có `VAULT_OPERATOR_SECRET`. Kiểm tra bằng `wrangler secret list --env=""` và `POST /internal/v1/operator` trả 404.
  - Bạn chấp nhận rằng người giữ secret có thể rollback membership về trước một lần remove/rekey (T8, threat-model.md:95), và rằng device chưa chứng kiến state mới hơn sẽ không phát hiện được.

### R6. Phía client agentkit: có thật sự verify không (≈15 phút)

- **Câu hỏi:** Client có truyền trust anchor và witnessed checkpoint, có verify change log từ head do chính nó tính, và có pin origin không?
- **Đọc** (`agentkit: apps/cli/internal/runtime/secretsync/`):
  - `verify_membership.go:121-146`: `TrustedAnchor`, `VaultID`, witnessed; rollback thì báo alarm; device không còn hiện diện thì `ErrDeviceRemoved`.
  - `device_membership.go:279-291`: state đã lưu được verify lại cùng anchor.
  - `change_log_verify.go:32-61`: `VerifyChangeLog` với `From`, `Complete`, `KeptHeads`. Các head được lưu ở `syncstate/log_heads.go`.
  - `pull_changes.go:337-345`: `CheckRollback` so với checkpoint đã chứng kiến; `:421` verify checkpoint của peer.
  - `enroll_joiner.go:701-716, 787` (joiner: chuỗi, checkpoint, `VerifyDeviceWraps`); `recover.go:385-396`.
  - `akvhttp/vault_origin.go:107-123` (origin chỉ là prod/staging; override phải là https, hoặc http với loopback, xem 58-100) và `:171-247` (`FetchMeta` kiểm tra issuer/audience chính xác).
- **Bằng chứng tự nhận:** `change_log_reread_test.go` (86, 216, 250, 279), `removal_fence_log_head_test.go` (110, 131, 223), `engine_integrity_test.go`, `akv1_conformance_test.go`, `akvhttp/vault_origin_test.go`. Release gate dẫn agentkit#2425 cho phần sync-off và offline resolve (release-gates.md:87-97).
- **Pass khi:** Không có đường pull, enroll hay recover nào gọi `VerifyMembershipChain` mà thiếu anchor. Riêng `enroll_joiner.go:708` và `recover.go:392` verify **prefix** chỉ với `VaultID`. Đọc 701-716 và 385-396 để xác nhận anchor đã được kiểm tra trên toàn chuỗi ngay trước đó. Release `v3.0.0-beta.31` chứa đúng code này (đã kiểm tra: tag = `origin/dev`).

### R7. Quy tắc mint ở ak-web (≈10 phút)

- **Câu hỏi:** Chỉ session CLI email OTP còn sống mới mint được không? Device key có thật sự gắn với một tài khoản không? Giới hạn số device có hiệu lực không?
- **Đọc:** ak-web `app/api/agentkit/vault/token/route.ts:46-107`:
  - flag tắt thì 404 (48); thiếu audience hoặc webhook thì 503 (51-54);
  - `authMethod === 'email_otp'` và có `sessionId` (58);
  - session active được kiểm tra trước và sau bind (63, 85);
  - ký request bằng Ed25519 trên `{aud, scope, sid, sign_pub, ts}` ±60 s (`lib/vault/vault-token-request.ts:67-98`), strict encoding ở `:54-65`;
  - bind `did` một lần cho một tài khoản và giới hạn 50 device (`lib/vault/vault-device-keys.ts:15, 21-68`).
- **Bằng chứng tự nhận:** ak-web `__tests__/api/agentkit-vault-token-route.test.ts:56-163` (từ chối `api_key` ở 131, device limit ở 120, bị bind cho tài khoản khác ở 149, did bị thu hồi ở 156, sign-out trong lúc đang bind ở 107); `__tests__/lib/vault/vault-token-request.test.ts`; `__tests__/lib/vault/vault-device-keys.test.ts`.
- **Pass khi:** Không có đường mint nào khác cho aud vault (xem R1). Key HS256 của CLI chỉ dùng ở `verifyCliSessionToken` và không bao giờ có trong Worker.
- **Ghi chú agent:**
  - Giới hạn device chỉ là "best effort, not a lock" (`vault-device-keys.ts:26`), nên race có thể vượt 50.
  - Binding xảy ra trước khi ký. Nếu ký lỗi, device vẫn bị bind và tốn một slot ([ak-web#584](https://github.com/bestagentkits/ak-web/issues/584), issue về device binding).
  - Agent không thấy rate limit cho route mint trong `route.ts` hay `middleware.ts`. Hãy xác nhận lớp edge hoặc infra có giới hạn.

### R8. Log và lộ secret, kể cả waiver #61 (≈10 phút)

- **Câu hỏi:** Có plaintext, tên secret, token, proof hay key nào lọt vào log, error, metric hoặc dump không?
- **Đọc:**
  - `ak-vault: worker/src/http/operational-logger.ts:24-29`: chỉ ghi route template, status, code, ms, và tag hash của vault.
  - `worker/src/http/errors.ts`: thông điệp generic, không echo.
  - `worker/wrangler.jsonc:14`: `invocation_logs: false`.
  - `docs/security/data-classification.md:41-80`: handling rules, ngoại lệ waiver ở 67-80.
  - ak-web `token/route.ts:52, 104` chỉ log tên class lỗi.
- **Bằng chứng tự nhận:** `worker/test/red-team-disclosure-scan.test.ts:53-54`; `worker/test/disclosure-scan.test.ts`; quét log platform trên lab Worker (`docs/security/red-team-evidence.md:77-131`, PR #62). `wrangler tail` là chỗ lộ duy nhất ([#61](https://github.com/bestagentkits/ak-vault/issues/61)).
- **Pass khi:** Bạn đồng ý với lập luận của waiver: proof chỉ dùng một lần và gắn với token, method, URL và body trong ±60 s; chữ ký webhook gắn với một body có `event_id` dùng một lần. Bạn cũng đã thực sự giới hạn quyền Workers Tail trên production. Comment cuối của #8 ghi đây là lời xác nhận của owner và agent không kiểm tra. Lưu ý: lần quét log platform chạy trên source ở `d097c41`, không phải ở `02748f4`.

### R9. Kill switch (≈5 phút)

- **Đọc:** `ak-vault: worker/src/routes/meta-routes.ts:6-8` (chỉ đúng chuỗi `"true"` mới bật); `worker/src/routes/api-handler.ts:28` (kiểm tra trước auth); `worker/wrangler.jsonc:35`; runbook `docs/operations/runbooks.md:35-154` (kill switch thường, khẩn cấp, freeze); `.github/workflows/deploy.yml:41-53, 105-117` (`DEPLOY_FREEZE` fail closed).
- **Bằng chứng tự nhận:** `worker/test/public-endpoints.test.ts:33-55`; diễn tập trên staging ngày 2026-10-15 (`docs/operations/rehearsal-2026-10.md`).
- **Pass khi:**
  - Token kill switch khẩn cấp vẫn còn sống. Theo runbook dòng 97-106, đó chính là token CF của staging (chung với bootstrap). Quyền của nó cần được ghi trên #53.
  - Bạn chấp nhận rằng webhook revocation và route operator vẫn chạy khi sync tắt (đây là thiết kế).

### R10. Kiểm soát deploy: CODEOWNERS, ruleset, môi trường production, token (≈10 phút)

- **Đọc:**
  - `.github/CODEOWNERS:1-5`: chỉ phủ `/.github/` và `/worker/wrangler.jsonc`.
  - `.github/workflows/deploy.yml:27-141`: chỉ chạy trên `main`, sau khi CI xanh; credential chỉ có ở bước deploy; action được pin theo SHA. Bước `npx wrangler` chạy wrangler lấy từ lockfile, xem [#68](https://github.com/bestagentkits/ak-vault/issues/68).
  - `docs/security/release-gates.md:208-267`.
- **Trạng thái live mà agent đọc được** (`gh api`, chỉ đọc, 2026-10-16):
  - Ruleset `main: CI required` (id 24972946) đang active. Bắt buộc 3 check (TypeScript, Go, Secret scan) và `require_code_owner_review: true`.
  - Tuy nhiên `required_approving_review_count: 0`, `dismiss_stale_reviews_on_push: false`, `require_last_push_approval: false`, `strict_required_status_checks_policy: false`.
  - Bypass: RepositoryRole id 5 (admin) ở chế độ `pull_request`.
  - Environment `production`: reviewer duy nhất là `mrgoonie`, `prevent_self_review: false`, branch policy tuỳ chỉnh. Environment `staging`: không có reviewer.
- **Pass khi:** Bạn chấp nhận hoặc từ chối một cách có ý thức các điểm sau:
  - (a) Agent hành động qua tài khoản `mrgoonie`, nên về mặt kỹ thuật nó **có thể** approve environment production và bypass code-owner review. Rào cản duy nhất là quy tắc trong AGENTS.md.
  - (b) Nếu các commit đẩy lên sau khi approve vẫn giữ approval (không dismiss stale review), thì một thay đổi ở path code-owned có thể lọt qua sau review.
  - (c) Token CF của staging với tới được Worker production. Staging tự deploy từ `main`.
  - (d) Lockfile và `package.json` không được code-own (#68).
- **Bước kiểm tra lại:**
  - `gh api repos/bestagentkits/ak-vault/rulesets/24972946`
  - `gh api repos/bestagentkits/ak-vault/environments`
  - Settings, mục Security: secret scanning, push protection, private vulnerability reporting (release-gates.md:265-267).

### Phân bổ thời gian gợi ý

| Mục | Thời gian |
|---|---|
| R4 | 20 phút |
| R1 | 15 phút |
| R3 | 15 phút |
| R6 | 15 phút |
| R2, R5, R7, R8, R10 | 10 phút mỗi mục |
| R9 | 5 phút |
| Tự chạy `pnpm install && pnpm typecheck && pnpm test` và `cd go && go test ./...` ở `02748f4` | khoảng 10 phút, chạy song song |

---

## 3. Issue mở và waiver: owner cần chấp nhận hoặc từ chối có ý thức

| Issue | Trạng thái (2026-10-16) | Rủi ro, một dòng |
|---|---|---|
| [ak-vault#42](https://github.com/bestagentkits/ak-vault/issues/42) | open | Một machine/CI device trên tài khoản owner tải được recovery bundle và membership của vault khác, rồi đoán mật khẩu offline. Bản sửa phụ thuộc ak-web#578. |
| [ak-vault#61](https://github.com/bestagentkits/ak-vault/issues/61) | open, đã waiver | Ai có quyền Workers Tail đều thấy giá trị `AKV-Proof` và `AKV-Webhook-Signature`. Mức độ phụ thuộc hoàn toàn vào việc giới hạn quyền tail. |
| [ak-vault#63](https://github.com/bestagentkits/ak-vault/issues/63) | open | Chi phí: mỗi lần pull đều ghi row. Đây là rủi ro tài chính và khả dụng, không phải rủi ro bảo mật. |
| [ak-vault#65](https://github.com/bestagentkits/ak-vault/issues/65) | open | Chưa có alert cho registry toàn cục. Trần khoảng 10 lượt/giây; vượt trần thì toàn bộ sync trả 503 mà không ai được báo. |
| [ak-vault#68](https://github.com/bestagentkits/ak-vault/issues/68) | open | Một thay đổi dependency hoặc lockfile có thể chạy code với token deploy mà không cần owner review. |
| [ak-vault#71](https://github.com/bestagentkits/ak-vault/issues/71) | open | Landing page vẫn ghi ADR là chưa duyệt. Đây là lệch tài liệu, làm người dùng hiểu sai trạng thái. |
| [ak-vault#74](https://github.com/bestagentkits/ak-vault/issues/74) | open | Chưa hỗ trợ sync cho đăng nhập bằng API key. Đây là khoảng trống tính năng. Rủi ro nằm ở chỗ thiết kế exchange sau này (ak-web#583) có thể nới rộng đường mint. |
| [ak-vault#76](https://github.com/bestagentkits/ak-vault/issues/76) | open | Chưa có test nào chứng minh client từ chối log bị restore rồi mọc lại quá vị trí đã chứng kiến. Riêng `checkRollback` thì cho qua trường hợp đó. |
| [ak-web#569](https://github.com/bestagentkits/ak-web/issues/569) | open | Chưa có UX trên dashboard cho vault, pairing, recovery. Người dùng khó thu hồi device đúng lúc khi bị mất máy. |
| [ak-web#578](https://github.com/bestagentkits/ak-web/issues/578) | open | Chưa có claim đánh dấu session machine/CI, nên #42 chưa đóng được. Đây là điều kiện tiên quyết cho machine identity (#6). |
| [ak-web#582](https://github.com/bestagentkits/ak-web/issues/582) | open | Đăng nhập không qua email chỉ nhận `not_authenticated` chung chung. Đây là vấn đề UX, không làm yếu bảo mật. |
| [ak-web#583](https://github.com/bestagentkits/ak-web/issues/583) | open | Đề xuất đổi API key lấy device session. Nếu làm sai, nó mở thêm một đường mint token vault. |
| [ak-web#584](https://github.com/bestagentkits/ak-web/issues/584) (device binding) | open | Bind xảy ra trước khi ký, nên khi mint lỗi vẫn để lại device active và tốn slot (đã xảy ra trên staging). |
| [agentkit#2469](https://github.com/bestagentkits/agentkit/issues/2469) | **closed**: beta.31 đã phát hành | Rủi ro còn lại: người dùng vẫn ở beta.30 (trước fence) không remove hay recover được và không kiểm tra fence. Tài liệu vẫn ghi beta.30 là bản mới nhất, xem dưới. |
| [agentkit#2474](https://github.com/bestagentkits/agentkit/issues/2474) | open | Nâng đăng nhập API key lên session email. Đây là UX, nhưng sẽ chạm vào luồng auth. |
| [agentkit#2475](https://github.com/bestagentkits/agentkit/issues/2475) | open | Client cho exchange API key và approve device. Đi kèm rủi ro của ak-web#583. |

**Các waiver đã ghi** (release-gates.md:184-197). Mỗi waiver cần được xác nhận lại trong kết quả:

- live tail (#61);
- e2e Docker thay cho soak trên staging;
- bỏ qua external review để bật `VAULT_SYNC_ENABLED` trên production;
- production sync live hoàn toàn;
- ADR được chấp nhận trong khi phần reconcile sau restore vẫn mở;
- token CF của staging với tới được production, giảm thiểu bằng code-owner review.

**Lệch tài liệu agent phát hiện** (không chặn, nhưng không nên tick khi tài liệu sai):

- `docs/security/release-gates.md:26-34` và `docs/security/threat-model.md:174-179` vẫn ghi "`v3.0.0-beta.30` là bản mới nhất, chưa có fence client". Trong khi đó agentkit#2469 đã đóng và beta.31 có fence client.
- release-gates.md:149-151 vẫn gọi gate này là "External review". Quyết định ở #8 nói rằng PR cập nhật cho việc này sẽ làm sau.

---

## 4. Cách ghi nhận kết quả

- **Owner tự post kết quả lên #8.** Agent không được post, tick hay xác nhận thay, vì agent hành động qua tài khoản GitHub của owner. Nếu agent post thì không thể phân biệt được với chữ ký của owner.
- Kết quả là một trong ba mức: **pass**, **pass có điều kiện**, hoặc **fail**.
- Mẫu gợi ý:

```text
Owner security review (not an independent third-party review)
Result: pass | pass with conditions | fail
Reviewer: @mrgoonie, date (Asia/Saigon)
Scope: R1–R10 of the review packet; ak-vault <sha>, ak-web <sha>, agentkit v3.0.0-beta.31 (<sha>)
Commands run at those commits: <pnpm test / go test results>
Findings: <one line each, link a new issue per finding; no exploit details or secret values>
Accepted risks/waivers: <list from section 3 accepted, with reason>
Conditions (if any): <issue + deadline, e.g. #65 alert before inviting more users>
```

- Phát hiện nhạy cảm (có thể khai thác) không đưa lên issue công khai. Hãy dùng private vulnerability reporting (README.md:69-71).
- Sau khi owner post: agent có thể mở PR cập nhật `release-gates.md` để link tới comment đó, nhưng không tự tick gate khi không có link.

---

Status: DONE
Summary: Đã soạn gói review khoảng 280 dòng, gồm đảm bảo và giới hạn, checklist R1–R10 có path:line đã đọc, bảng issue và waiver, và hướng dẫn ghi kết quả. Các số dòng ghim ở ak-vault `02748f4`, ak-web `187e09c5`, agentkit beta.31 `4aff1984b`.
Concerns: (1) Agent hành động qua tài khoản owner, nên về kỹ thuật vẫn approve được production (`prevent_self_review: false`) và bypass code-owner. (2) Tài liệu vẫn ghi beta.30 là bản mới nhất. (3) Agent không đọc secret hay cấu hình Cloudflare, nên phải tự kiểm tra trên production: không có `VAULT_JWKS_JSON`, không có `VAULT_OPERATOR_SECRET`, và quyền Tail.
