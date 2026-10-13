# ak-vault protocol v1 (`akv1`) — normative wire specification

Status: **Proposed** (see [ADR 0001](../../adr/0001-opt-in-zero-knowledge-sync.md)).
Not approved for production credentials until the security gate in issue #8 records
an external review sign-off.

The key words MUST, MUST NOT, SHOULD and MAY are normative. Every implementation
(TypeScript reference in `packages/protocol`, Go in `go/akv1`, the Worker in `worker/`)
MUST reproduce the deterministic vectors in `protocol/v1/vectors/` byte for byte.

## 1. Primitives (no custom cryptography)

| Purpose | Algorithm | TypeScript | Go |
|---|---|---|---|
| AEAD | XChaCha20-Poly1305, 24-byte nonce, 16-byte tag | `@noble/ciphers` | `golang.org/x/crypto/chacha20poly1305.NewX` |
| Signatures | Ed25519 (RFC 8032, pure) | `@noble/curves/ed25519` | `crypto/ed25519` |
| Key agreement | X25519 (RFC 7748) | `@noble/curves/ed25519` `x25519` | `crypto/ecdh` X25519 |
| KDF | HKDF-SHA256 (RFC 5869) | `@noble/hashes/hkdf` | `golang.org/x/crypto/hkdf` |
| Hash | SHA-256 | `@noble/hashes/sha2` | `crypto/sha256` |
| Password KDF | Argon2id v1.3 (RFC 9106) | `@noble/hashes/argon2` | `golang.org/x/crypto/argon2.IDKey` |
| Server tokens | ES256 JWT (P-256) | WebCrypto (Worker) | issuer side (ak-web) |

Algorithm identifiers are closed sets. A verifier MUST reject an unknown `v`, `alg`,
event `type` or `suite` value (fail closed). Crypto agility = a new identifier plus a
new protocol version; never silent negotiation down.

## 2. Encodings

- **Binary on the wire:** base64url without padding (`b64`). Decoders MUST reject
  padding, non-alphabet characters and non-canonical trailing bits.
- **Canonical JSON (`cjson`)** — restricted RFC 8785:
  - Values: objects, arrays, strings, booleans, `null`, and integers in
    `[0, 2^53-1]`. Floats, negative numbers and exponents MUST be rejected.
  - Object keys are ASCII `[a-z0-9_]+`, sorted by byte order, no duplicates.
  - No insignificant whitespace.
  - Strings: escape `"` as `\"`, `\` as `\\`, `\b \f \n \r \t` as such, other
    U+0000–U+001F as `\u00xx` (lowercase hex). Every other code point is emitted
    as raw UTF-8 (no `\u` escaping of `<`, `>`, `&`, U+2028, U+2029). Lone
    surrogates MUST be rejected.
- **Signing input:** `utf8(context) || 0x0A || cjson(object_without_sig)`.
- **Key ID (`kid`):** `b64(SHA-256(utf8("akv1/kid") || 0x0A || pubkey)[0:16])`.
  A device ID is the `kid` of its Ed25519 signing public key.
- Opaque IDs (`vault_id`, `item_id`, `conflict_id`, `event ids`) are `b64` of 16
  random bytes. They MUST NOT be derived from names or values.

## 3. Key hierarchy

```
Device (per install): Ed25519 signing key  (sign_pub)   -> device_id = kid(sign_pub)
                      X25519 exchange key  (kx_pub)
Vault key VK[e] (32 random bytes) per vault per key_epoch e
  ItemKey = HKDF(ikm=VK[e], salt=b64decode(vault_id),
                 info=utf8("akv1/item-key\n") || cjson({item_id, key_epoch}), L=32)
  VK[e] is wrapped to: every current member device (X25519 wrap),
                       the owner's password KEK and recovery KEK (symmetric wrap)
```

Personal and shared vaults use the same vault-wide key. **A vault key grants
decryption of every item in that vault.** v1 therefore makes no per-secret access
claim; least privilege is achieved with separate vaults (e.g. a dedicated CI vault).

### 3.1 AEAD envelope

```json
{"v":1,"alg":"xc20p","kid":"<key id or epoch tag>","n":"<b64 24B>","ct":"<b64 ct||tag>"}
```

AAD = `cjson(aad_object)`; the AAD object is defined by each use below and is never
transmitted — the receiver rebuilds it from authenticated context. Limits: plaintext
≤ 65 536 bytes. Nonces are random (24 bytes); a sender MUST NOT reuse a nonce under
the same key; vectors inject fixed nonces.

### 3.2 Item payload

Plaintext = `cjson({"name":…,"value":…,"meta":{…},"sensitivity":"normal"|"high"})`.
Names, values, descriptions, tags and profile data are all inside the ciphertext.
Item AAD:

```json
{"ctx":"akv1/item","vault_id":…,"item_id":…,"base_revision":n,"key_epoch":e,"author":device_id,"tombstone":bool}
```

### 3.3 Device key wrap (`x25519-xc20p`)

```
esk, epk  = fresh X25519 keypair
shared    = X25519(esk, recipient.kx_pub)       ; reject all-zero output
wrap_key  = HKDF(ikm=shared, salt=epk||recipient.kx_pub, info="akv1/wrap/x25519", L=32)
ct        = XC20P(wrap_key, n, VK[e], aad={"ctx":"akv1/wrap","vault_id","key_epoch","recipient":device_id})
wire      = {"v":1,"alg":"x25519-xc20p","rcpt":device_id,"key_epoch":e,"epk":b64,"n":b64,"ct":b64}
```

### 3.4 Password and recovery wraps

```
KEK_pw = Argon2id(password_utf8_nfc, salt16, t, m_KiB, p, L=32)
wire   = {"v":1,"alg":"argon2id-xc20p","key_epoch":e,"s":b64,"t":t,"m":m,"p":p,"n":b64,"ct":b64}
aad    = {"ctx":"akv1/pw-wrap","vault_id","key_epoch","t","m","p"}
```

Defaults `t=3, m=65536, p=1`. Verifiers MUST reject `t<2`, `m<19456`, `p<1`,
`m>1048576`. Clients re-wrap with current defaults after a successful unlock under
weaker parameters (parameter upgrade). Test vectors use `t=2,m=19456,p=1`.

Recovery key: 32 random bytes shown as Crockford base32 in groups of 4.
`KEK_rk = HKDF(ikm=rk, salt=utf8("akv1"), info="akv1/recovery-kek", L=32)`,
wire `alg:"rk-xc20p"`, aad `{"ctx":"akv1/rk-wrap","vault_id","key_epoch"}`.

The **recovery bundle** (stored by the server, opaque) is an AEAD envelope under a
random bundle key BK, which is wrapped under KEK_pw and under KEK_rk; the plaintext is
`cjson({"v":1,"vault_id","bundle_seq","vk":{epoch:b64},"owner_sign_pub","recovery_sign_sk":b64,"checkpoint":<signed checkpoint>})`.
Exact wire format, AADs and checks: §11 "Recovery bundle". It gives a fresh device the owner trust anchor and the newest checkpoint the owner
witnessed, so recovery is not a TOFU on the server's word.

### 3.5 Owner recovery signing key and SAS enrollment

At genesis the owner generates an Ed25519 **recovery signing key**; its public key is
`genesis.body.recovery_sign_pub` and its private key is stored only inside the recovery
bundle (`cjson` field `recovery_sign_sk`). If every owner device is lost, a fresh device
unlocks the bundle with the password or recovery key and authors `device_add` for itself
with the recovery key, so ownership is restored without trusting the server.

**Bundle fetch by a device outside membership.** The server returns the opaque bundle
(`GET /v1/vaults/{vid}/recovery`) to a current owner device, or to a fresh device when
all of these hold: the token `sub` is the vault's `owner_account`; the token `did` is
neither a current nor a removed device; the request carries
`AKV-Device-Key: <b64 Ed25519 sign_pub>` with `kid(sign_pub) == did`; and `AKV-Proof`
verifies against that key. Exposure: anyone holding an owner-account token can obtain
the bundle ciphertext and attempt offline guessing, which the Argon2id parameters
(§3.4) and the 256-bit recovery key bound. The server refuses a removed device ID on
this path, but a thief who still holds a live owner-account session can mint a token
for a new device ID and fetch the ciphertext; after a loss the owner MUST revoke their
ak-web sessions, and the password or recovery key remains the barrier.

SAS transcript = `cjson({"ctx":"akv1/sas","vault_id","initiator":device_id,"joiner":device,
"nonce_i":b64 16B,"nonce_j":b64 16B})`; both devices display
`uint32be(sha256(transcript)[0:4]) mod 10^6` as six digits; `device_add.body.sas` is
`b64(sha256(transcript))`. A mismatch aborts enrollment.

## 4. Membership log (owner-signed, hash-chained)

```json
{"v":1,"type":T,"vault_id":…,"seq":n,"prev":"<b64 sha256 of previous event signing input or ''>",
 "membership_epoch":m,"key_epoch":e,"ts":unix_ms,"author":device_id,"body":{…},"sig":"<b64 ed25519>"}
```

Signing context `akv1/membership`. `seq` starts at 0 (genesis) and increments by 1;
`membership_epoch` = `seq`; `key_epoch` changes only on `rekey`. Device record:
`{"device_id","sign_pub","kx_pub","account","role":"owner"|"editor"|"reader","kind":"human"|"machine"}`.

| type | body | rules |
|---|---|---|
| `genesis` | `{"vault_kind":"personal"|"shared"|"ci","owner_account","recovery_sign_pub","devices":[device]}` | seq 0, key_epoch 1, author ∈ devices with role owner. The genesis author `sign_pub` is the pinned trust anchor (TOFU, or from the recovery bundle / SAS). `recovery_sign_pub` is the owner recovery signing key (§3.5). |
| `device_add` | `{"device":device,"sas":"<b64 sha256 of SAS transcript>"}` | author is an owner device or the recovery signing key (§3.5). `sas` = `""` only when authored by the recovery key. |
| `device_remove` | `{"device_id","reason":"lost"|"stolen"|"retired"|"compromised"}` | closed reason set; sets `rekey_required`. |
| `member_add` | `{"account","role","devices":[device]}` | shared vaults only. |
| `member_remove` | `{"account"}` | removes all its devices; sets `rekey_required`. |
| `role_set` | `{"account","role"}` | cannot demote the last owner. |
| `rekey` | `{"new_key_epoch":e+1,"wraps_digest":b64,"needs_rotate":[item_id…]}` | clears `rekey_required`; `wraps_digest` = sha256 over cjson of the sorted wrap list for the new epoch. |

Only devices whose current role is `owner` may author events; additionally the
recovery signing key (author = `kid(recovery_sign_pub)`) may author `device_add`
(role `owner`) and `device_remove`. After a `device_add`, owners upload wraps of
every retained key epoch to the new device (older epochs are accepted for current
members only), so items written before a rekey stay readable. A verifier replays the
chain from genesis (or from a trusted checkpoint) and MUST reject: bad signature,
wrong `prev`, non-sequential `seq`, author not an owner at that point, a removed
device reappearing without a fresh `device_add`, `key_epoch` decreasing, or any wrap
whose `rcpt` is not a current member device (**injected recipient**).

## 5. Records, revisions, conflicts and tombstones

```json
{"v":1,"vault_id","item_id","base_revision":n,"key_epoch":e,"tombstone":bool,"author":device_id,
 "ts":unix_ms,"resolves":[conflict_id…],"env":{"v":1,"alg":"xc20p","kid":…,"n":…,"ct":…},"sig":…}
```

Signing context `akv1/record`. The server assigns `revision = base_revision + 1` only
if `base_revision` equals the item's current revision (0 for a new item) —
**compare-and-swap**. There is no last-writer-wins:

- Mismatch → `409 conflict`; the rejected record is **preserved** as a conflict branch
  (`conflict_id`) and returned on pull so a client can resolve explicitly by writing a
  record whose `resolves` lists the branch IDs.
- A tombstone is a record with `tombstone:true` (ciphertext of `{"deleted":true}`).
  Writes with `base_revision` lower than the tombstone revision get `409 tombstoned`
  and are **not** preserved as live branches — a stale offline device cannot resurrect a
  deleted secret. Re-creating requires `base_revision` = tombstone revision.
- `key_epoch` MUST equal the vault's current key epoch; writes are refused while
  `rekey_required` is set.
- Requests carry `Idempotency-Key`; a retried key with an identical body returns the
  original response; a different body under the same key is `422`.

## 6. Checkpoints (anti-rollback)

```json
{"v":1,"vault_id","membership_seq","membership_head","log_seq","state_digest","key_epoch","ts","author","sig"}
```

Signing context `akv1/checkpoint`. `state_digest` = b64 sha256 of cjson of the sorted
list `[[item_id, revision, b64 sha256(record signing input)]…]`. Clients sign a
checkpoint after verifying a pull and keep the highest one they witnessed. On every
pull a client MUST reject (rollback/fork alarm): a membership head with lower `seq`
than witnessed, the same `seq` with a different hash, a `log_seq` below the witnessed
one, or a state that no longer matches a witnessed `state_digest` at that `log_seq`.

**Server restore:** a legitimate point-in-time restore looks exactly like a rollback
and MUST raise the alarm. Clients never accept it silently; the operator-confirmed
recovery path re-uploads the client's witnessed records and membership (re-seed),
then signs a new checkpoint. See `docs/operations/runbooks.md`.

**Acknowledged limitation:** a malicious server can withhold updates a device has never
witnessed (freeze attack against a new or long-offline device). Detection needs a
second channel (another device's checkpoint, SAS-transferred checkpoint, or recovery
bundle). Transparency/gossip is out of scope for v1.

## 7. Encrypted audit stream

Each audit entry is an AEAD envelope (aad `{"ctx":"akv1/audit","vault_id","seq","prev"}`)
chained by `prev = b64 sha256(previous entry wire cjson)`. Entries are appended in
batches and covered by audit checkpoints (context `akv1/audit-checkpoint`,
`{"vault_id","seq","head","author","ts"}`). Reordering, dropping or overwriting since a
witnessed audit checkpoint is detected by chain replay. The server's operational log
is separate and never contains item names or values.

## 8. Portable policy (restrictive only)

Encrypted item with `meta.kind = "policy"`. Fields are maxima only:
`{"max_ttl_s","require_approval","allowed_projects":[…],"allowed_purposes":[…],"deny_agents":[…]}`.
Effective grant = local grant ∩ portable policy. A policy can only narrow; a missing
field means "no extra restriction", never "allow". `sensitivity:"high"` always
requires fresh operator approval. Policy text, URLs, `when_to_use` and descriptions
are untrusted, author-attributed data and are never interpreted as instructions.

## 9. Transport authentication (Worker)

1. `Authorization: Bearer <ES256 JWT>` from the configured issuer. Required claims:
   `iss` (exact), `aud` = `https://vault.agentkit.best` (exact), `sub`, `exp`, `nbf`,
   `iat`, `jti`, `scope` ⊆ {`vault:read`,`vault:write`}, `sid`, `did`. Header `alg`
   MUST be `ES256` and `kid` MUST match a JWKS key; skew tolerance 60 s. If the JWKS
   cannot be loaded the server fails closed (`503`) and backs off for 30 s before
   fetching again; it never serves expired keys.
2. `AKV-Proof: <b64(cjson(proof))>.<b64(sig)>`, proof =
   `{"htm","htu","ts","jti","ath","bh"}` (`ath`/`bh` = b64 sha256 of token / body),
   signed with context `akv1/proof` by the device whose `device_id == did`. Valid for
   ±60 s; `jti` single-use per device for 120 s.
3. Live revocation: every request consults the revocation registry (revoked `sid`,
   revoked `did`, per-`sub` minimum `iat`). Registry errors fail closed (`503`).
   The registry is fed by `POST /internal/v1/revocations` with headers
   `AKV-Webhook-Timestamp: <unix s>` (±300 s) and
   `AKV-Webhook-Signature: b64(HMAC-SHA256(secret, utf8(ts) || "\n" || body))`, body
   `{"v":1,"event_id","revoke_sids":[…],"revoke_dids":[…],"min_iat":[{"sub","iat"}]}`.
   `event_id` is single-use: a retry of an already-applied event answers `409
   conflict`, which the sender MUST treat as delivered. Any `5xx` is retried.
4. Authorization = token scope ∩ vault membership: `sub` must be a current member
   account and `did` a current device of that account. `reader` role and `machine`
   devices are read-only: they cannot write items, membership, wraps, checkpoints,
   audit entries or the recovery bundle. Scope never grants cross-vault access. The
   only requests from a device outside membership are the recovery bundle fetch and
   the recovery-signed `device_add` that enrolls it (§3.5).

## 10. Errors and limits

Errors are `{"error":{"code","message"}}` with stable codes: `unauthorized`,
`forbidden`, `not_found`, `conflict`, `tombstoned`, `rekey_required`,
`unsupported_version`, `invalid_signature`, `rollback`, `rate_limited`,
`quota_exceeded`, `idempotency_mismatch`, `sync_disabled`, `bad_request`, and the
server-only `internal` (HTTP 500, fail closed, generic message; a retry may succeed).
Messages never echo request bodies, item IDs beyond the path, tokens or names.
Limits are published by `GET /v1/meta` and owned by `worker/src/limits.ts`.
They include per-vault totals for stored records (`records_per_vault`) and record
bytes (`record_bytes_per_vault`), conflict branches included; exceeding either
returns `quota_exceeded`. A request for a vault that has no genesis returns
`not_found` and writes nothing; a rejected genesis also writes nothing, because the
server checks the event, author, scope and proof signature before creating storage.

## 11. Clarifications fixed by the reference implementation (normative)

These resolve points the sections above leave open; the vectors in
`protocol/v1/vectors/` encode them and every `expect_error` uses these codes.

- **Client-side error code:** an AEAD authentication failure (wrong key, wrong AAD,
  tampered ciphertext, reordered audit entry) is `decrypt_failed`. It never appears in
  a server response.
- **Envelope `kid`:** envelopes under a vault-key-derived key use the epoch tag
  `e<key_epoch>` (e.g. `e1`). A record whose `env.kid` differs from `e<record.key_epoch>`
  is `bad_request`.
- **Item payload:** `name` and `value` are strings, `meta` is an object; a tombstone
  plaintext is exactly `{"deleted":true}`.
- **Argon2id bounds:** in addition to §3.4, verifiers MUST reject `t>10` and `p>16`
  before any KDF work (bounded client work against a malicious server).
- **Recovery key display:** MSB-first Crockford base32, uppercase, 52 symbols in 13
  groups of 4 joined by `-`. Decoders accept ASCII input only: any non-ASCII character
  (including look-alikes such as `ı` U+0131, `ſ` U+017F, fullwidth digits and non-ASCII
  spaces) is `bad_request`. They are ASCII case-insensitive (only `a`–`z` fold), ignore
  `-` and ASCII whitespace (tab, LF, VT, FF, CR, space), map `I`/`L`→`1` and `O`→`0`,
  and reject other symbols, wrong length or non-zero padding bits
  (vectors: `wrap-recovery.json`, `edge-cases.json`).
- **Passwords:** implementations normalize the raw password to Unicode NFC before
  Argon2id (§3.4); APIs take the raw user input. An empty password is `bad_request`.
- **Key lengths:** an X25519 secret or public key, or an Ed25519 seed, that is not
  exactly 32 bytes is `bad_request` (key derivation, X25519, wrap and unwrap), never an
  untyped library error (vectors: `edge-cases.json`).
- **Ed25519 verification** is strict RFC 8032 and identical everywhere: `S < L`;
  `A` and `R` MUST be canonical encodings (`y < p`, and no sign bit when `x = 0`);
  `A` MUST NOT be of small order (the eight torsion points); and the cofactorless
  equation MUST hold byte-exactly: `encode([S]B − [k]A) = R` with
  `k = SHA-512(R ‖ A ‖ M) mod L`. A signature that only satisfies the cofactored
  equation (torsion component in `R` or `A`) is invalid. Every failure is
  `invalid_signature` (vectors: `edge-cases.json`).
- **Membership roles:** a role belongs to an account; every device record's `role`
  MUST equal its account's role (`role_set` updates all of the account's devices).
  Genesis devices are owner devices of `owner_account`. Only human owner devices (or
  the recovery key, §3.5) author events; `machine` devices never author. `device_add`
  requires the device's account to be a member. A removed device ID may only return
  through `device_add`. Removing or demoting the last owner account, or the last human
  owner device, is `forbidden`. `member_add`/`member_remove` outside `shared` vaults is
  `forbidden`.
- **Membership error codes:** malformed fields, non-sequential `seq`, wrong `prev`,
  `membership_epoch != seq`, `key_epoch` change without `rekey` → `bad_request`; bad
  signature → `invalid_signature`; unauthorized author, removed device reappearing,
  untrusted anchor, injected wrap recipient → `forbidden`; `key_epoch` decrease, chain
  behind or forked from a witnessed checkpoint → `rollback`; unknown `v`/`type`/`alg`
  → `unsupported_version`.
- **Heads and digests:** `membership_head` is the hash of the event at
  `membership_seq` (the same value the next event carries as `prev`). `wraps_digest`
  sorts wraps by `rcpt` byte order. `state_digest` omits items at revision 0; the
  third element is `b64 sha256(record signing input)` of the record at that revision.
- **Records:** checks run in order: record already seen for the item (replay) →
  `conflict`, not preserved; `base_revision` below the highest tombstone revision →
  `tombstoned`; CAS mismatch → preserved branch (`409 conflict`); deleting a missing or
  deleted item, or `resolves` naming an unknown branch → `bad_request`. Writers are human
  `owner`/`editor` devices (`forbidden` otherwise); `rekey_required` set →
  `rekey_required`; `key_epoch` ≠ current → `bad_request`.
- **Audit:** the first entry has `seq` 0 and `prev` `""`. Audit checkpoints carry
  `"v":1` and a `sig`; `head` is the hash of entry `seq`. Reused nonces within a chain
  are `bad_request`.
- **Transport proof:** `ts` is unix milliseconds, `jti` is b64 of 16 random bytes,
  `htm` is an uppercase method and `htu` is compared exactly. The proof blob MUST be
  canonical. Bad signature → `invalid_signature`; every other proof failure →
  `unauthorized`.
- **Portable policy:** unknown fields or wrong types are `bad_request` (the caller
  denies). `description`, `when_to_use` and `urls` are carried as inert text.
- **Recovery bundle** (vectors: `recovery-bundle.json`).
  - Plaintext `P = cjson({"v":1,"vault_id","bundle_seq","vk":{"<epoch>":b64 32B},"owner_sign_pub":b64 32B,"recovery_sign_sk":b64 32B seed,"checkpoint":<signed checkpoint>})`.
    `bundle_seq` ≥ 1 and MUST increase each time the bundle is replaced. `vk` keys are
    decimal epochs ≥ 1 without leading zeros (1–10 000 entries) and MUST include
    `checkpoint.key_epoch`.
  - `BK` = 32 random bytes. `env = XC20P(BK, n_env, P, aad={"ctx":"akv1/recovery-bundle","vault_id","bundle_seq"})`
    as an AEAD envelope with `kid:"bk"`.
  - `pw = {"v":1,"alg":"argon2id-xc20p","s","t","m","p","n","ct"}`, `ct = XC20P(KEK_pw, n, BK,
    aad={"ctx":"akv1/bundle-pw-wrap","vault_id","bundle_seq","t","m","p"})`, KEK_pw and
    parameter bounds as §3.4 (no `key_epoch` field).
  - `rk = {"v":1,"alg":"rk-xc20p","n","ct"}`, `ct = XC20P(KEK_rk, n, BK, aad={"ctx":"akv1/bundle-rk-wrap","vault_id","bundle_seq"})`.
  - Wire: `{"v":1,"vault_id","bundle_seq","pw","rk","env"}`; unknown fields are `bad_request`.
  - Opening, in order: parse the wire (`unsupported_version` / `bad_request`, including
    Argon2id bounds); `vault_id` ≠ expected → `bad_request`; `bundle_seq` lower than the
    highest one the client knows → `rollback` (before any KDF work); unwrap BK with the
    password or recovery key (exactly one; `decrypt_failed`); open `env`
    (`decrypt_failed`); the plaintext MUST be canonical and repeat the wire `vault_id`
    and `bundle_seq` (`bad_request`); `checkpoint.vault_id` MUST match (`bad_request`),
    `checkpoint.author` MUST equal `kid(owner_sign_pub)` (`forbidden`) and its
    `akv1/checkpoint` signature MUST verify against `owner_sign_pub` (`invalid_signature`).
    Sealers apply the same plaintext checks.
- **Rekey wrap sets** (vectors: `rekey-wraps.json`). `verifyRekeyWraps(event, wraps, state?)`,
  where `event` comes from a verified chain. In order: `event.type` ≠ `rekey` →
  `bad_request`; each wrap parses (§3.3), has `key_epoch = body.new_key_epoch` and a unique
  `rcpt` (`bad_request`). If a membership state is supplied, it MUST be the state
  immediately after the event (`seq` and `head` equal, else `bad_request`), every `rcpt`
  MUST be a current device (`forbidden`) and every current device MUST have a wrap
  (`bad_request`). Finally `b64 sha256(cjson(wraps sorted by rcpt))` MUST equal
  `body.wraps_digest` (`bad_request`). Input order of the wraps does not matter.
