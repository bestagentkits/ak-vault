# ak-vault protocol v1 (`akv1`) — normative wire specification

Status: **Proposed**; the review gate on #8 was accepted by the owner on 2026-10-16
(owner instruction recorded by an agent, no written findings,
[record](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212706397)); that is the owner's review, not an independent third-party review.
The design rationale,
[ADR 0001](../../adr/0001-opt-in-zero-knowledge-sync.md), was accepted by the owner on
2026-10-16. Not approved for production credentials until every security gate in
issue #8 is met.

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

**Signed wrap sets.** Every device wrap belongs to the set of exactly one
owner-signed membership event whose body commits to it with `wraps_digest`: the
event that added the recipient (`genesis`, `device_add`, `member_add`) or a
`rekey`. The set is uploaded in the same request as the event and stored as
uploaded; there is no other way to deliver a wrap. A device MUST NOT unwrap a
vault key from a wrap that has not passed `verifyDeviceWraps` or
`verifyRekeyWraps` against the event from its verified chain (§11). The server
cannot substitute a recipient's key, add a wrap or drop one without changing the
digest the owner signed.

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
with the recovery key, so ownership is restored without trusting the server. Before
signing, the device MUST verify the membership chain from the pinned owner anchor and
check that the bundle's recovery key is the chain's current `recovery_sign_pub`
(`openRecoveryBundle` option `recoverySignPub`, `forbidden` on mismatch), and that the
bundle holds `VK` of the chain's current `key_epoch`. A bundle without it cannot enroll
a device (§4: every device-adding event delivers the current epoch), so the device MUST
refuse before posting anything; finishing the stopped rekey-and-reseal on a device that
still syncs is the only way to make that bundle usable again. The recovery
key authors `device_add` only: it cannot read the change log, so it cannot sign an
honest removal fence (§5). The enrolled device removes the lost devices itself and
rekeys.

**Recovery-key rotation.** An owner device replaces the recovery signing key with a
`recovery_rotate` event (§4) whose body names the new public key. The request carries
the resealed bundle (`bundle_seq` incremented, `recovery_sign_sk` = the new key) and
the server stores the event and the bundle in one transaction: a `recovery_rotate`
without a bundle, or with a `bundle_seq` not above the stored one, is refused and the
chain does not advance. From that event on, a `device_add` signed by any earlier
recovery key is `forbidden`; a recovery key is never reused and never collides with a
device key (`bad_request`). The server cannot open the bundle, so it cannot check that
the bundle holds the key the event names; the recovering device does (above).

**Reads by a device outside membership (recovery identity).** The server returns the
opaque bundle (`GET /v1/vaults/{vid}/recovery`) to a current owner device, and the
bundle or the signed membership log (`GET /v1/vaults/{vid}/membership`, read-only) to a
fresh device when all of these hold: the token `sub` is the vault's `owner_account`; the token `did` is
neither a current nor a removed device; the request carries
`AKV-Device-Key: <b64 Ed25519 sign_pub>` with `kid(sign_pub) == did`; and `AKV-Proof`
verifies against that key; and the token's session kind (§9.1) is `email_otp`. A device whose
session kind is `api_key_device` or `machine` is refused (`403`) on this path, on `GET /recovery`,
on `GET /membership` and on recovery enrollment, so a leaked API key or a CI runner cannot
collect recovery bundles. Every other route answers such a device `forbidden`;
without the `AKV-Device-Key` header, a membership read by a non-member is `forbidden`
as before. The membership log is metadata already visible to the server (§4,
[data classification](../../security/data-classification.md)); reading it lets the
fresh device verify the chain before it trusts the bundle. Exposure: anyone holding an owner-account token can obtain
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
| `genesis` | `{"vault_kind":"personal"|"shared"|"ci","owner_account","recovery_sign_pub","devices":[device],"wraps_digest":b64}` | seq 0, key_epoch 1, author ∈ devices with role owner. The genesis author `sign_pub` is the pinned trust anchor (TOFU, or from the recovery bundle / SAS). `recovery_sign_pub` is the owner recovery signing key (§3.5). `wraps_digest` commits to the wrap set of the genesis devices (§3.3). |
| `device_add` | `{"device":device,"sas":"<b64 sha256 of SAS transcript>","wraps_digest":b64}` | author is an owner device or the current recovery signing key (§3.5). `sas` = `""` only when authored by the recovery key. `wraps_digest` commits to the new device's wrap set. |
| `device_remove` | `{"device_id","reason":"lost"|"stolen"|"retired"|"compromised","log_fence":n,"log_head":b64|""}` | closed reason set; `log_fence` and `log_head` are the removal fence (§5); sets `rekey_required`. |
| `member_add` | `{"account","role","devices":[device],"wraps_digest":b64}` | shared vaults only; `wraps_digest` commits to the new devices' wrap set. |
| `member_remove` | `{"account","log_fence":n,"log_head":b64|""}` | removes all its devices, each fenced at `log_fence` and `log_head` (§5); sets `rekey_required`. |
| `role_set` | `{"account","role"}` | cannot demote the last owner. |
| `rekey` | `{"new_key_epoch":e+1,"wraps_digest":b64,"needs_rotate":[item_id…]}` | clears `rekey_required`; `wraps_digest` (§11) commits to the wrap list for the new epoch. |
| `recovery_rotate` | `{"recovery_sign_pub":b64}` | owner device only; replaces the recovery signing key (§3.5). The new key was never a recovery key of this chain and is not the key of a current or removed device (`bad_request`). |

Only devices whose current role is `owner` may author events; additionally the
current recovery signing key (author = `kid(recovery_sign_pub)`) may author
`device_add` (role `owner`) and nothing else. A device whose ID equals any recovery
key ID the chain has trusted is refused (`bad_request`).

**Wrap sets of device-adding events.** The set carried by `genesis`, `device_add` or
`member_add` (checked by `verifyDeviceWraps`, §11) holds only wraps to devices the
event adds, at epochs `1..event.key_epoch`. Every such event, a recovery-authored
`device_add` included, MUST include a wrap at the event's `key_epoch` for every added
device, so every device holds the key of the epoch it joins at, which the audit
verifier requires (§7). It SHOULD include every retained older epoch (for a
recovery-authored `device_add`, every older epoch the bundle holds), so items written
before a rekey stay readable. An epoch missing from the signed set is never delivered
later; items the device cannot read are rotated forward by a device that can. A
bundle sealed before the latest rekey lacks the current epoch and cannot enroll a
device (§3.5): a removal whose author stopped after its rekey and before it resealed
the bundle leaves recovery dependent on a device that still syncs. A verifier replays the
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
  `rekey_required` is set. Only current member devices author accepted records: the
  server refuses a record whose author is not a current device (`forbidden`), whoever
  submits it.
- Requests carry `Idempotency-Key`; a retried key with an identical body returns the
  original response; a different body under the same key is `422`.
- **Change-log positions.** The server assigns every accepted record a position
  `log_seq`, starting at 1 and contiguous (no gaps, no reuse). A client that sees a
  gap, or a different record at a position it already holds, MUST raise the rollback
  alarm (§6).
- **Change-log heads.** Every position has a head that commits to the whole prefix:
  `log_head[0] = ""` and `log_head[n] = b64 sha256(utf8("akv1/log-head") || 0x0A ||
  cjson({"conflict_id","log_seq":n,"prev":log_head[n-1],"record":recordDigest}))`, where
  `conflict_id` is the preserved branch's ID or `null` for an applied record and
  `recordDigest` is `b64 sha256(record signing input)`. The domain tag keeps it
  distinct from every other cjson hash. The change feed returns each entry's
  `log_head` and the head at the current `log_seq`; clients compute the chain
  themselves and never sign or trust a served head. The head binds only
  `log_seq`, `conflict_id` and the record: clients take an entry's kind from
  `conflict_id` and its revision and resolution from their own replay of the
  records (`applyRecord`, `resolves`), never from the served `kind`, `revision` or
  `resolved_revision`.

**Removal fence.** A removed device keeps its signing key and the vault keys it held,
so with a colluding server it could keep appending validly signed records. Every
`device_remove` and `member_remove` therefore signs `log_fence` and `log_head`: the
change-log position its author verified, gap-free, when it removed the device, and the
head it computed itself at that position from the records it verified (`""` exactly
when `log_fence` is 0, else 32 bytes; `bad_request` otherwise). The server MUST refuse a
removal whose `log_fence` is behind the current head (`409 conflict`: pull and
re-sign) or ahead of it (`bad_request`), or whose `log_head` is not the stored head at
the fence (`bad_request`). Right after the removal lands, the remover
MUST sign and post a checkpoint (§6, accepted while `rekey_required` is set) so other
devices witness the log at the fence; the fence itself is the signed `log_fence`, so
verification never depends on the server keeping that checkpoint.

A device that is still live can write between the remover's pull and its removal and
so keep the fence stale. The device MUST therefore be revoked first (§9, live
revocation stops its requests); the remover then retries a `409` fence with backoff.

**Scope of the fence.** `log_fence` guarantees that no record by a removed author is
accepted above the fence; `log_head` binds the contents of every position at or below
it. A device that first reads the log after the removal (newly enrolled, recovered,
or offline when it landed) replays the log with `verifyChangeLog` and refuses
(`rollback`) any prefix whose head differs from a signed fence: a record substituted,
dropped or reordered, or a `conflict_id` changed, at or below the fence changes the head. The fence
binds the log as its remover verified it. It cannot vouch for records the removed
device got accepted before its removal, including any it wrote after it was
compromised but before it was removed, and it says nothing about positions above the
latest fence (§6 checkpoints and the freeze limitation apply there).

A client MUST check every removal of its verified chain against the head it computed
at that removal's `log_fence`. A client that learns of a removal after its cursor
passed the fence compares the head it kept for that position (`keptHeads`), or
replays the log again from position 1; it MUST NOT take the head from the server. Once the client has
read the whole log, a fence beyond the last position means the log is behind a signed
removal (`rollback`).

`verifyLoggedRecord(record, state, log_seq)` (vectors: `removal-fence.json`) checks a
record read from the change log against the verified membership state, in order:
the record parses; same vault; `log_seq ≥ 1` (`bad_request`); the author is a current
device, or a removed device whose record `key_epoch` is not newer than the key epoch
current at its last removal (`forbidden`); the signature verifies under that device's
key (`invalid_signature`); and for every removal of the author whose key epoch is ≥
the record's `key_epoch`, a `log_seq` above that removal's `log_fence` is
`forbidden`. Because writes are refused between a removal and the next rekey, every
legitimate later write, including one by a re-added device ID, uses a newer key epoch
and is unaffected. The membership state lists each removal (`removals`: `device_id`,
`sign_pub`, `removed_seq`, `key_epoch`, `log_fence`, `log_head`).

`verifyChangeLog(entries, state, {from?, complete?, keptHeads?})` (vectors: `removal-fence.json`)
replays change-log entries `{"log_seq","conflict_id","record"}` that continue from
`from` (a cursor `{log_seq, log_head}` the client computed itself; default position 0,
head `""`). In order: `from` is a valid position (`bad_request`); every removal whose
`log_fence` is the `from` position carries `from.log_head` (`rollback`); every removal
whose `log_fence` lies in `1..from.log_seq - 1` has a head in `keptHeads` (heads the
client computed earlier, by position; missing: `bad_request`) equal to its `log_head`
(`rollback`); per entry: exact keys,
`log_seq` an integer ≥ 1, `conflict_id` `null` or an ID (`bad_request`); `log_seq` is the
previous position + 1 (`rollback`: gap, repeat or reorder); `verifyLoggedRecord`; the
head advances. Every removal whose `log_fence` is an entry's position MUST carry the
head computed there (`rollback`). With `complete` (the entries
reach the current head), a `log_fence` beyond the last position is `rollback`. It
returns the new cursor and the verified records.

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
and MUST raise the alarm on every device that witnessed newer state. Clients never
accept it silently. That includes a restored log that has since grown past the
witnessed `log_seq`: the change-log head at that position differs from the one the
client computed (§5) and the state there no longer matches the witnessed
`state_digest`. `checkRollback` on checkpoints alone does not catch that case. A
device that never witnessed newer state cannot tell and accepts the restored state
(the limitation below). v1 defines no client re-seed or other
automatic re-convergence: a device that raised the alarm stops syncing and keeps
its local vault. Recovery is operational (`docs/operations/runbooks.md`): undo the
restore, or the vault owner moves to a fresh vault from a device's local state.

**Acknowledged limitation:** a malicious server can withhold updates a device has never
witnessed (freeze attack against a new or long-offline device). Detection needs a
second channel (another device's checkpoint, SAS-transferred checkpoint, or recovery
bundle). Transparency/gossip is out of scope for v1.

## 7. Encrypted audit stream

Each audit entry is an AEAD envelope under the audit key of one key epoch `e`:

```
AuditKey[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id),
                   info=utf8("akv1/audit-key\n") || cjson({"key_epoch":e}), L=32)
```

with `kid` = the epoch tag `e<e>` and aad `{"ctx":"akv1/audit","vault_id","seq","prev","key_epoch"}`,
chained by `prev = b64 sha256(previous entry wire cjson)`. Key epochs never decrease
along the chain and never exceed the vault's current key epoch (`bad_request`); the
server accepts new entries only at the current key epoch. A verifier MUST hold the
key of the current epoch, and of every entry epoch at or above its minimum epoch (the
`key_epoch` of the event that added it, whose signed wrap set always delivers that
epoch's key (§4), or an older epoch from which it holds every key); a missing required key
is a refusal (`bad_request`), never an opaque result, so every entry at an epoch at
or above the minimum is decrypted. Holding the current key does not prove the chain
has an entry at that epoch: a chain that ends before the first entry at the minimum
epoch (truncated by the server, or read between a rekey and the rekeyer's audit
append) can be entirely opaque and still pass. Only a witnessed audit checkpoint
bounds that; a client MUST NOT present an all-opaque result as verified. An entry at
an older epoch it holds no key for is opaque: still
hash-chained and epoch-checked, returned as `{"seq","key_epoch","opaque":true}`, but
its content is not verified. Entries carry no
author signature, so any holder of `VK[e]` can write entries at epoch `e`; per-epoch
keys stop a removed device from writing entries at a later epoch. A colluding server can
still append epoch-`e` entries from a removed device until the first entry at a later
epoch is in the chain, so the device that rekeys MUST append an audit entry at the
new epoch, and sign an audit checkpoint over it, right after the rekey. Entries are appended in
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
   `iss` (exact), `aud` = the deployment's own origin (exact; production
   `https://vault.agentkit.best`, staging `https://vault-staging.agentkit.best`), `sub`, `exp`, `nbf`,
   `iat`, `jti`, `scope` ⊆ {`vault:read`,`vault:write`}, `sid`, `did`. Optional
   `session_kind` ∈ {`email_otp`, `api_key_device`, `machine`}: how the session behind the
   token signed in. An absent claim means `email_otp` (the only kind issued before the claim
   existed); any other value, or a non-string, is `401 unauthorized`. ak-web sets it; the
   Worker never infers it. Header `alg`
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
   only requests from a device outside membership are the recovery bundle fetch, the
   read-only membership fetch (§3.5) and the recovery-signed `device_add` that
   enrolls it, and only for an `email_otp` session. A device of an `api_key_device`
   session (an AgentKit API key exchanged for a revocable device session) may create a
   new vault with genesis and, once enrolled, acts as a member under its role; it joins an
   existing vault only through a `device_add` signed by an existing owner device, never
   through the recovery identity.
5. Wrap routes. Wraps are uploaded only inside `PUT /v1/vaults/{vid}` (genesis) and
   `POST /v1/vaults/{vid}/membership` (`{"event","wraps"?,"bundle"?}`); there is no
   separate wrap upload. `GET /v1/vaults/{vid}/wraps?membership_seq=n` returns the
   complete stored set of event `n` to any current member, including wraps of devices
   removed since (`not_found` when the event carries none); it cannot be combined with
   other filters. A client unwraps only after checking the set against
   its event, and uses a wrap only if the `rcpt` device record in force at that event
   has its current `kx_pub` (a re-added device ID may hold older sets sealed to an
   earlier key). Without `membership_seq`, the listing returns wraps of current
   devices, each with the `membership_seq` of its set. Wraps on an event type that
   carries none, a set that does not match the signed digest, and a `bundle` on any
   event but `recovery_rotate` are `bad_request`.

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

A membership quota never blocks the rekey a removal requires, nor recovery. Owner
`device_add`/`member_add` may not grow the vault past `devices_per_vault`, and a
recovery `device_add` may add one more, so a rekey of every device fits
`wraps_per_request`. Owner-authored wrap uploads and voluntary rekeys are refused past
`wraps_per_vault`; a `rekey` that clears `rekey_required` and a recovery `device_add`
are exempt (still bounded by `membership_events_per_vault` x `wraps_per_request`).
The last `membership_events_per_vault` slot is kept for a `rekey` that clears
`rekey_required`.

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
  is `b64 sha256(utf8("akv1/wraps") || 0x0A || cjson(wraps))` with the wraps sorted by
  `rcpt` byte order, then by `key_epoch`; the domain tag keeps it distinct from every
  other cjson hash. `state_digest` omits items at revision 0; the
  third element is `b64 sha256(record signing input)` of the record at that revision.
- **Records:** checks run in order: record already seen for the item (replay) →
  `conflict`, not preserved; `base_revision` below the highest tombstone revision →
  `tombstoned`; CAS mismatch → preserved branch (`409 conflict`); deleting a missing or
  deleted item, or `resolves` naming an unknown branch → `bad_request`. Writers are human
  `owner`/`editor` devices (`forbidden` otherwise); `rekey_required` set →
  `rekey_required`; `key_epoch` ≠ current → `bad_request`.
- **Audit:** the first entry has `seq` 0 and `prev` `""`. Audit checkpoints carry
  `"v":1` and a `sig`; `head` is the hash of entry `seq`. Reused nonces within a chain
  are `bad_request`. `verifyAuditChain(entries, {vaultKeys, vaultId, keyEpoch, minKeyEpoch?, witnessed?})`
  takes a vault-key lookup by epoch, the verified state's key epoch and the lowest
  epoch whose key the caller must hold (default: `keyEpoch`; Go takes it explicitly).
  It returns one entry per chain entry: `{"seq","key_epoch","opaque":false,"event"}`
  when decrypted, `{"seq","key_epoch","opaque":true}` otherwise (§7). `minKeyEpoch`
  outside `1..keyEpoch`, a missing key for `keyEpoch` or for an entry epoch at or
  above `minKeyEpoch`, and a `kid` that is not an epoch tag are `bad_request`; a substituted, reordered or relabelled decryptable entry is
  `decrypt_failed` (vectors: `audit.json`).
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
  - Every bundle an owner device uploads (`PUT /recovery` or with `recovery_rotate`)
    MUST hold the chain's current recovery signing key; a device that has not
    replayed the latest `recovery_rotate` MUST NOT reseal.
  - `PUT /v1/vaults/{vid}/recovery` takes `{"bundle":<wire>,"membership_seq":n}`, where
    `n` is the membership position the sealing device had verified. The server cannot
    open the bundle, so it enforces freshness by position: `n` above the current
    membership seq is `bad_request`; `n` below the seq of the latest `recovery_rotate`
    is `409 conflict` (replay the chain and reseal with the current key). A bundle sent
    with `recovery_rotate` is sealed at that event by definition.
  - Opening, in order: parse the wire (`unsupported_version` / `bad_request`, including
    Argon2id bounds); `vault_id` ≠ expected → `bad_request`; `bundle_seq` lower than the
    highest one the client knows → `rollback` (before any KDF work); unwrap BK with the
    password or recovery key (exactly one; `decrypt_failed`); open `env`
    (`decrypt_failed`); the plaintext MUST be canonical and repeat the wire `vault_id`
    and `bundle_seq` (`bad_request`); `checkpoint.vault_id` MUST match (`bad_request`),
    `checkpoint.author` MUST equal `kid(owner_sign_pub)` (`forbidden`) and its
    `akv1/checkpoint` signature MUST verify against `owner_sign_pub` (`invalid_signature`);
    when the caller passes the chain's current `recovery_sign_pub`, the public key of
    `recovery_sign_sk` MUST equal it (`forbidden`). Sealers apply the same plaintext
    checks.
- **Rekey wrap sets** (vectors: `rekey-wraps.json`). `verifyRekeyWraps(event, wraps, state?)`,
  where `event` comes from a verified chain. In order: `event.type` ≠ `rekey` →
  `bad_request`; each wrap parses (§3.3), has `key_epoch = body.new_key_epoch` and a unique
  `rcpt` (`bad_request`). If a membership state is supplied, it MUST be the state
  immediately after the event (`seq` and `head` equal, else `bad_request`), every `rcpt`
  MUST be a current device (`forbidden`) and every current device MUST have a wrap
  (`bad_request`). Finally the `wraps_digest` of the wraps (§11, "Heads and digests") MUST equal
  `body.wraps_digest` (`bad_request`). Input order of the wraps does not matter.
- **Device-adding wrap sets** (vectors: `device-add-wraps.json`). `verifyDeviceWraps(event, wraps)`,
  where `event` comes from a verified chain. In order: the event adds devices
  (`genesis`, `device_add`, `member_add`; else `bad_request`); each wrap parses (§3.3);
  every `rcpt` is a device the event adds (`forbidden`); key epochs lie in
  `1..event.key_epoch` and (`rcpt`, `key_epoch`) pairs are unique (`bad_request`);
  completeness (`bad_request`): every event, a recovery-authored `device_add` (`sas` `""`)
  included, carries a wrap at `event.key_epoch` for every added device;
  finally `wraps_digest(wraps)` MUST equal `body.wraps_digest` (`bad_request`). Input
  order does not matter.

## Revisions

The protocol version stays `1`; these revisions change wire bodies, so data written
under an earlier revision does not verify and is reset rather than migrated.

- **2026-10 (issue #20):** signed wrap sets (`wraps_digest` on `genesis`, `device_add`,
  `member_add`; full sets served per event; no separate wrap upload); recovery identity
  may read membership; per-epoch audit keys; signed removal fence (`log_fence`) and
  contiguous change-log positions; recovery key restricted to `device_add`;
  `recovery_rotate` with an atomically resealed bundle; `PUT /recovery` carries the
  sealer's membership position; a domain-tagged `wraps_digest`; audit verification
  requires the current epoch's key and marks opaque entries explicitly; membership
  quotas leave room for the rekey a removal requires and for recovery.
- **2026-10 (issues #21, #36):** removals also sign `log_head`, the change-log head at
  `log_fence`, and clients replay the head chain against it (`verifyChangeLog`); the
  change feed publishes per-entry and current heads; a recovery-authored `device_add`
  MUST deliver the current key epoch like every other device-adding event.
