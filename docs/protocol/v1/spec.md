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

Remote access (§3.6–§3.10, §9.6, §9.7) adds no primitive. The seal construction
(§3.6), and the write intent (§3.10) that reuses it under its own HKDF `info` and AAD
context, is the §3.3 shape (X25519, HKDF-SHA256, XChaCha20-Poly1305) aimed at a
recipient key derived from `VK[e]`, and a name tag (§3.7) is HKDF-SHA256 output used
as a keyed pseudorandom function. Its new identifiers (`x25519-xc20p-seal`, the
`browser` session kind, the relay frame types) belong to new message types with their
own closed sets; no existing set gains a member that an existing verifier would meet,
so they do not need a new protocol version.

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
verifies against that key; and the token's session kind (§9.1) is `email_otp`. A device outside
membership whose session kind is `api_key_device` or `machine` is refused (`403`) on this
path (the bundle and membership reads) and on recovery enrollment, so a leaked API key or a CI
runner cannot collect recovery bundles by itself. Once an owner device approves such a
device with a signed `device_add`, it is a current member and its role decides: an owner-role
device may read and replace the bundle and rotate the recovery key, but only in an
`email_otp` session; an `api_key_device` or `machine` session may only store the
first bundle of a vault that has none (genesis seal, §9 item 4). Every other route
answers such a device `forbidden`;
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
`b64(sha256(transcript))`. A mismatch aborts enrollment. The joiner and the
initiator exchange the transcript inputs as enrollment codes (§3.8).

### 3.6 Seal key and sealed operations

A **sealed operation** lets the Worker queue a write that a remote MCP client asked
for while no device is online (§9.6), without the Worker holding any vault key. The
Worker encrypts the operation to a per-epoch public key whose private key every
holder of `VK[e]` can derive; an opted-in device later opens it and writes a normal
signed record.

```
SealSK[e]   = HKDF(ikm=VK[e], salt=b64decode(vault_id),
                   info=utf8("akv1/seal-key\n") || cjson({"key_epoch":e}), L=32)
seal_pub[e] = X25519(SealSK[e], 9)        ; the RFC 7748 base point
```

`SealSK[e]` is used unmodified as an X25519 private key; X25519 applies the RFC 7748
scalar clamping itself, so implementations never store a pre-clamped copy.

**Seal-key document.** Owner-signed, stored by the server, never a membership event
(older clients keep verifying the chain unchanged). Signing context `akv1/seal-key`;
exactly these keys:

```json
{"v":1,"vault_id":…,"key_epoch":e,"membership_seq":n,"seal_pub":"<b64 32B>","author":device_id,"ts":unix_ms,"sig":"<b64 ed25519>"}
```

`verifySealKeyDoc(doc, chain, {vault_id, vk?, trusted_anchor?, witnessed_checkpoint?})`
checks, in order, the first failure being the result. `chain` is the verifier's
membership chain, verified in full (with the verifier's own pinned anchor and highest
witnessed checkpoint when it has them, as in §4: a device passes both); its head
MUST be at or after `membership_seq`, and its prefix up to `membership_seq`, verified
under the same anchor, gives the key epoch and the devices current when the
document was signed.

1. shape: exact keys, `v` = 1 (`unsupported_version` otherwise), IDs, `seal_pub` of
   32 bytes, integers (`bad_request`);
2. `vault_id` is the expected vault (`bad_request`);
3. `membership_seq` is at most the verified head seq, and `key_epoch` equals the
   chain's key epoch at `membership_seq` (`bad_request`);
4. `author` is a human `owner` device current at `membership_seq`; the recovery
   signing key never authors a seal-key document (`forbidden`);
5. the signature verifies under the author's `sign_pub` (`invalid_signature`);
6. when the verifier holds `VK[key_epoch]` (`vk`), `seal_pub` equals
   `seal_pub[key_epoch]` recomputed from it (`forbidden`). A device that holds the
   key MUST pass it. A device that finds a mismatch raises a vault alarm, drains
   nothing sealed to that epoch, and, if it is an owner device, publishes a correct
   document.

Owner devices SHOULD publish a document after genesis and after every `rekey`, and
on their first sync when the vault has none for the current key epoch.

**Sealed operation (wire).** Exactly these keys:

```json
{"v":1,"alg":"x25519-xc20p-seal","sealed_id":"<b64 16B>","vault_id":…,"key_epoch":e,
 "epk":"<b64 32B>","n":"<b64 24B>","ct":"<b64 ct||tag>",
 "origin":{"kind":"mcp","account":"<token sub>","client_id":"<string>","grant_id":"<string>"},"ts":unix_ms}
```

```
esk, epk = fresh X25519 keypair
shared   = X25519(esk, seal_pub[e])                      ; reject all-zero output
seal_key = HKDF(ikm=shared, salt=epk || seal_pub[e], info=utf8("akv1/seal"), L=32)
aad      = {"ctx":"akv1/sealed-op","vault_id","sealed_id","key_epoch","origin","ts"}
pt       = cjson({"op":"set","name":…,"value":…,"sensitivity"?:"normal"|"high"})
         | cjson({"op":"delete","name":…})
ct       = XC20P(seal_key, n, pt, aad)
```

- `sealed_id` is 16 random bytes (§2). `origin` has exactly the keys `kind`,
  `account`, `client_id` and `grant_id`; `kind` is the closed set {`mcp`}; `account` is
  the MCP token's `sub`, in the account form device records use (§4); `client_id` is
  1–256 and `grant_id` 1–64 bytes of printable ASCII (0x20–0x7E). The device cannot
  verify `origin` beyond its binding into the AAD: it records who the Worker says
  asked, nothing more.
- `pt` is canonical; `op` is the closed set {`set`, `delete`}; `name` is 1–4096 and
  `value` 0–65 536 UTF-16 code units, the item payload limits the reference
  implementations enforce; a `set` carries `value` and MAY carry `sensitivity`, a
  `delete` carries neither. `pt` ≤ 65 536 bytes (§3.1), which bounds a `value` more
  tightly than its own limit.
- `openSealedOp(SealSK[e], wire, {vaultId})`, in order: parse the wire (`v`/`alg`
  unknown → `unsupported_version`; keys, lengths, `origin` → `bad_request`);
  `vault_id` ≠ expected → `bad_request`; an all-zero shared secret → `bad_request`;
  AEAD failure → `decrypt_failed`; `pt` not canonical, unknown `op`, missing `value` on
  `set`, `value` or `sensitivity` on `delete`, unknown keys → `bad_request`.
  `sealOp` applies the same checks before encrypting.

**Who seals.** Only the Worker's MCP handler creates sealed operations; there is no
public route that accepts one. It seals only when the MCP token carries
`vault-mcp:write` and its `sub` is an `owner` or `editor` member of the vault, only to
the stored seal-key document whose `key_epoch` is the vault's current key epoch, and
never while the vault has `rekey_required` set (a removed device may still derive
that epoch's seal key). Otherwise it does not seal and the tool answers
`no_device_online` (§10). The queue holds at most `sealed_queue_max` operations per
vault, counting acknowledged ones whose ID it still keeps to refuse a replay
(`sealed_queue_full` beyond), and drops an operation `sealed_ttl_s` after its `ts`.

**Draining.** A device drains the queue (`GET …/sealed`, `POST …/sealed/{id}/ack`,
§9.6) only when its operator opted in to sealed writes, and only if it is a human
`owner` or `editor` device of a non-`browser` session. The server serves a device only
operations whose `origin.account` is its token `sub`, so an account's sealed writes
are applied only by that account's own devices. For each operation, in order:

1. open it with `SealSK[key_epoch]` (any failure: refuse), and refuse an
   `origin.account` other than its own account;
2. refuse a `sealed_id` it already applied or refused (it MUST NOT apply one twice;
   it keeps every such ID until at least `sealed_ttl_s` after the later of its `ts`
   and the time it handled it, so an ID is never forgotten while its `ts` still
   passes the age check), and refuse a `ts` more than `sealed_ttl_s` in the past or
   more than 300 s in the future by its own clock. `checkSealedDrain(opened,
   {account, now, sealedTtlS, seen})` runs steps 1 and 2 on the result of
   `openSealedOp`, never on a raw wire, so it reads only authenticated header fields:
   another account → `forbidden`, an applied or refused `sealed_id` → `conflict`, a
   `ts` out of bounds → `bad_request`. Before step 1 it refuses with `bad_request`
   a malformed context (an `account` outside 1..256 UTF-16 code units, no `seen`
   set) and any value `openSealedOp` did not return;
3. resolve `name` against all its own decrypted live items: those whose payload
   `name` equals `name` after NFC normalization of both. More than one match, any
   match that is a policy item (§8.1), or a `delete` with no match → refuse. A `set`
   with no match creates a new item (fresh `item_id`). Resolution uses the device's
   full synced state, never a name-tag lookup (§3.7);
4. write a normal signed record (§5): author = itself, `base_revision` = the
   revision it holds, current `key_epoch`. The payload is what a local set or delete
   by this device would write, including the meta keys its own item mapping requires
   for a new item and the timestamps it updates on a changed value; beyond that, a
   `set` keeps every other payload field of the head (`meta.profile` unchanged, so
   profile provenance is untouched, §5.1). Its sensitivity is the higher of the
   head's (`normal` for a new item) and the requested one, so a sealed write never
   lowers sensitivity. A `delete` writes a tombstone. A `409` is an ordinary conflict
   branch (§5), never retried as an overwrite;
5. append an encrypted audit entry (§7) with `type` `sealed_applied` or
   `sealed_refused` (event envelope, §7.1), the `sealed_id`, `origin.client_id` and, when applied, the
   `item_id`; never the name or value;
6. acknowledge it with the outcome.

Vectors (`seal-key.json`, `sealed-op.json`): `seal_pub` derived for two epochs;
document sign and verify; a `seal_pub` that does not match `VK` → `forbidden`; a
non-owner author → `forbidden`; `set` and `delete` round trips; wrong epoch key and
tampered `origin` (including `account`), `ts` or `sealed_id` (AAD) → `decrypt_failed`;
`delete` with a value → `bad_request`; oversize `pt` → `bad_request`; all-zero shared
secret → `bad_request`; unknown `alg` → `unsupported_version`; a document verified
under a pinned trust anchor and witnessed checkpoint, and refused under another
anchor (`forbidden`) or a forked or longer checkpoint (`rollback`); drain admission:
a replayed `sealed_id`, also after its TTL → `conflict`, another account →
`forbidden`, an expired or too-far-future `ts` → `bad_request`.

### 3.7 Name tags (keyed blind index)

A **name tag** lets a device find an item by name without pulling the vault. Only
devices compute tags; the Worker never holds or derives the index key.

```
NameIndexKey[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id),
                       info=utf8("akv1/name-index\n") || cjson({"key_epoch":e}), L=32)
name_tag        = b64(HKDF(ikm=NameIndexKey[e], salt="", info=utf8("akv1/name-tag\n") || utf8(NFC(name)), L=16))
```

`salt=""` is the RFC 5869 default (HashLen zero bytes). `e` is the record's
`key_epoch`.

- **Upload.** `PUT /v1/vaults/{vid}/items/{iid}` accepts either the bare record (§5,
  unchanged) or the wrapper `{"record":<record>,"name_tag":{"key_epoch":e,"tag":"<b64 16B>"}}`
  (keys exactly `record` and optional `name_tag`; `name_tag` keys exactly `key_epoch`
  and `tag`). The tag is beside the record, not inside it: it is not signed, not
  encrypted and not trusted. The server refuses a `name_tag.key_epoch` other than
  `record.key_epoch` and a `name_tag` on a tombstone (`bad_request`). It stores the tag
  only when the record is applied (never for a conflict branch or a replay); an
  applied record without a tag, a tombstone included, clears the item's stored tag.
  The `Idempotency-Key` covers the whole body. Writers SHOULD send a tag with every
  live secret item record and SHOULD NOT send one for policy items. Where the
  deployment has remote access disabled, the wrapper is `bad_request`; writers send
  it only when `GET /v1/meta` publishes `lookup_tags_max`.
- **Lookup.** `GET /v1/vaults/{vid}/lookup` (§9.6) returns the items whose current
  head carries a requested `(key_epoch, tag)`. A reader computes a tag for each epoch
  it holds that the item may still be at. A hit is a hint: the reader MUST fetch,
  verify (§5) and decrypt the record and compare the decrypted name (NFC) before
  acting on it. A miss is never evidence that no item has the name: items written by
  clients that send no tags, or whose tag the server dropped, are not found this way.
  Before creating an item, a reader checks its full synced state.
- **Leakage.** The server learns which items share a name within an epoch, when an
  item is renamed back to an earlier name, and which tags a reader asks for. It does
  not learn names. A rekey changes the tag of every record written after it; items
  not yet rotated forward keep their old-epoch tags.

Vectors (`name-tag.json`): NFC and NFD spellings give the same tag; another epoch and
another vault give different tags; known-answer tags for ASCII and non-ASCII names.

### 3.8 Enrollment codes

The join code a new device prints and the offer code the approving owner device
answers with carry the SAS inputs (§3.5). They hold only public keys, nonces, IDs and
a signed checkpoint, so they are not secret; the six-digit SAS is what authenticates
the exchange. Each is a prefix followed by `b64(cjson(obj))`. The contexts keep their
`agentkit/` prefix because shipped CLIs already produce and accept these codes.

```
join  = "akj1-" || b64(cjson({"v":1,"ctx":"agentkit/akv1-join","account":…,"device":<device record>,"nonce_j":"<b64 16B>","label":…}))
offer = "ako1-" || b64(cjson({"v":1,"ctx":"agentkit/akv1-offer","vault_origin":…,"vault_id":…,"initiator":device_id,
                               "joiner":device_id,"nonce_i":"<b64 16B>","nonce_j":"<b64 16B>",
                               "trust_anchor":"<b64 32B Ed25519 sign_pub>","checkpoint":<signed checkpoint>}))
```

`parseJoinCode` and `parseOfferCode`, in order, every failure `bad_request` except
`v`:

1. remove every Unicode `White_Space` character (a terminal may wrap a pasted code);
2. the result is at most 8192 bytes and starts with its prefix;
3. the rest decodes as `b64` to a canonical `cjson` object with exactly the keys
   above; `v` other than 1 → `unsupported_version`;
4. `ctx` is the code's own context (a join code is never accepted as an offer);
5. join: `device` parses as a device record (§4) whose `account` equals `account`,
   with `role` `owner` and `kind` `human` (v1 codes enroll another device of an owner
   account, which is what shipped CLIs produce; a browser device is therefore enrolled
   only for an account that owns the vault); `nonce_j` is 16 bytes; `label` is
   0–64 bytes of printable ASCII (0x20–0x7E). The label is chosen by the joiner and is
   display text only;
6. offer: `vault_origin` is in canonical form, `https://host[:port]` with a lowercase
   scheme and host, no default port, no trailing dot, path, query, fragment or
   userinfo (`http://` only for `localhost`, `127.0.0.0/8` or `::1`); `vault_id`,
   `initiator` and `joiner` are IDs; both nonces are 16 bytes; `trust_anchor` is a
   32-byte key; `checkpoint` parses (§6) and names `vault_id`.

Encoders apply the same checks before encoding. Parsing checks no signature. The
joiner MUST then verify the membership chain from `trust_anchor` (the genesis
author's `sign_pub`, §4), the checkpoint signature and its non-rollback against that
chain (§6), and that the `device_add` adding it carries `sas` = `b64(sha256(transcript))`
for its own device record before it trusts any wrap.

**Authenticity of the code channel.** v1 does not commit to the nonces before they are
revealed: the join code carries `nonce_j` and the offer code carries `nonce_i`, and
neither is bound to the other. The six-digit SAS (about 20 bits) therefore authenticates
the exchange only while the two codes travel between the two devices without an active
attacker on that path. An attacker who carries both codes can read `nonce_j`, put its own
device towards the owner, learn the owner's digits, then choose the nonce it hands the
joiner and grind about 10^6 SHA-256 values until both sides show the same six digits. v1
therefore requires an authentic code channel: the user copies the codes between two
terminals or screens they control. A service that relays the codes for the user (the
Worker, ak-web or another service) is outside what v1 protects, and an implementation
MUST NOT offer such a flow on v1 codes. A relayed flow needs a commit-reveal exchange in which the
joiner commits to `nonce_j` before it sees `nonce_i` and reveals it only afterwards, which
is a wire change under the spec-change procedure.

Vectors (`enroll-codes.json`): byte-exact round trips of a join and an offer code in
the format shipped CLIs produce; a code split by whitespace parses; oversize, wrong
prefix, wrong `ctx`, an extra or missing key, non-canonical JSON, a non-owner or
machine device, a non-ASCII label and a non-canonical origin → `bad_request`; `v` 2 →
`unsupported_version`.

### 3.10 Write intents (human write requests)

A **write request** lets an MCP client ask for a secret it must never see: the client
names the secret, the person types the value into the dashboard, and an enrolled
browser device (§9 item 1) writes a normal signed record. The value never reaches the
MCP client or the Worker in plaintext. The secret name and purpose transit Worker
memory once, when the client asks (ADR 0002 D7), and are stored only inside a **write
intent** sealed to the epoch's seal key (§3.6).

**Write intent (wire).** Exactly these keys:

```json
{"v":1,"alg":"x25519-xc20p-seal","request_id":"<b64 16B>","vault_id":…,"key_epoch":e,
 "epk":"<b64 32B>","n":"<b64 24B>","ct":"<b64 ct||tag>",
 "origin":{"kind":"mcp","account":…,"client_id":…,"grant_id":…},
 "operation":"create"|"replace","ts":unix_ms,"expires_at":unix_ms}
```

```
esk, epk = fresh X25519 keypair
shared   = X25519(esk, seal_pub[e])                      ; reject all-zero output
key      = HKDF(ikm=shared, salt=epk || seal_pub[e], info=utf8("akv1/write-intent"), L=32)
aad      = {"ctx":"akv1/write-intent","vault_id","request_id","key_epoch","origin","operation","ts","expires_at"}
pt       = cjson({"name":…,"purpose"?:…,"sensitivity"?:"normal"|"high"})
ct       = XC20P(key, n, pt, aad)
```

- The `alg` identifier is the sealed-operation one, but the HKDF `info` and the AAD
  `ctx` differ, so a write intent never opens as a sealed operation (§3.6) or the
  reverse. `request_id` is 16 random bytes (§2); `origin` is as in §3.6;
  `operation` is the closed set {`create`, `replace`}; `expires_at` > `ts`.
- `pt` is canonical and carries no value: `name` 1–4096 UTF-16 code units (§3.6),
  `purpose` 1–200, `sensitivity` from the item set; any other key → `bad_request`.
  `pt` ≤ 16 384 bytes.
- `openWriteIntent(SealSK[e], wire, {vaultId})`, in order: parse the wire (`v`/`alg`
  unknown → `unsupported_version`; keys, lengths, `origin`, `operation`, `expires_at`
  not after `ts` → `bad_request`); `vault_id` ≠ expected → `bad_request`; an all-zero
  shared secret → `bad_request`; AEAD failure → `decrypt_failed`; `pt` not canonical,
  no `name`, unknown keys, or a field outside its limits → `bad_request`.
  `sealWriteIntent` applies the same checks before encrypting.

**Who requests.** Only the Worker's MCP handler creates write requests, through
`secrets_prepare_write` (§9.8); there is no route that accepts one. As for sealing
(§3.6), it needs `vault-mcp:write`, an `owner` or `editor` account, the stored seal-key
document of the current key epoch, and no pending `rekey_required`. The vault object
stores the request only with a `ts` within 300 s of its own clock, a lifetime between
`write_request_min_ttl_s` and `write_request_ttl_s`, a `request_id` it does not hold, and
room under `write_requests_pending_per_account`, `write_requests_pending_per_client` and
`write_requests_retained_per_account` (§10).
It keeps the intent ciphertext and, in the clear, the requesting account, `client_id`,
`grant_id`, the MCP token's `iat`, the operation, the state and the times.

**States.** A request starts `pending_user` and ends exactly once:

| State | `reason` | When |
|---|---|---|
| `completed` | — | the person's item PUT was applied; carries an opaque `receipt` |
| `conflict` | `revision_conflict` | that PUT lost compare-and-swap; its record is a preserved branch (§5) |
| `cancelled` | `user_cancelled`, `grant_revoked` | the person cancelled, or the requesting grant was revoked |
| `failed` | `already_exists`, `not_found`, `device_error` | the browser device could not complete it |
| `expired` | — | `expires_at` passed while it was open |

The reason set is closed and never carries text from the request. The states
`processing` and `queued` are reserved and not emitted: completion is a single step.
Closing a request clears its intent ciphertext. An expired request is never served;
it is marked `expired` and its ciphertext cleared, and rows closed more than
`write_request_retention_s` ago are purged, whenever the vault next handles a write
request.

**Completing.** The person opens `<origin>/app#write=<request_id>&vault=<vault_id>`
(the fragment never reaches the server). Every route in §9.6 that touches a request
needs a `browser` session of the requesting account; the `request_id` alone
authorizes nothing. The browser device:

1. fetches the request and opens its intent with `SealSK[key_epoch]` (any failure:
   refuse), and refuses a `request_id` or `vault_id` other than the link's;
2. shows the person the name, purpose, operation and requesting `client_id`. They are
   chosen by the MCP client, not by the person;
3. resolves `name` against its own decrypted live items as in §3.6 step 3: `create`
   with a match closes the request `failed`/`already_exists`, `replace` with no single
   match `failed`/`not_found`;
4. writes a normal signed record (§5) carrying the typed value as §3.6 step 4 writes
   a sealed `set` with the intent's `sensitivity` (author itself, `base_revision` the
   revision it holds), and PUTs it with `?write_request=<request_id>`, or closes the
   request `cancelled`/`user_cancelled` when the person declines.

The server cannot read the name, so the name binding and the compare-and-swap base
are the browser device's obligations. The server enforces the account, vault,
operation against the target item (`create`: no live item; `replace`: a live item),
expiry, single use and the requesting grant's liveness. Completion and the item PUT
are one transaction: a request is never consumed without its record, nor completed
twice. Before serving or completing an open request the Worker checks the revocation
registry for the requesting grant (`sid` = `grant_id`, and the account's minimum
`iat`), closes a revoked one `cancelled`/`grant_revoked`, and fails closed (`503`)
when the registry cannot answer.

Vectors (`write-intent.json`): `create`, name-only and `replace` round trips at two
epochs; wrong epoch key and tampered `origin` (account, grant), `operation`, `ts`,
`expires_at`, `request_id`, `key_epoch` or `ct` → `decrypt_failed`; another vault, an
all-zero `epk`, `expires_at` not after `ts`, an unknown `operation` or `origin.kind`,
an extra wire or plaintext key (a `value` included), a missing `name`, an empty
`purpose`, an unknown `sensitivity` and a non-canonical `pt` → `bad_request`; unknown
`alg` and `v` 2 → `unsupported_version`; sealing refuses an empty name, a `value` key
and an oversize `purpose`.

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
head `""`). `keptHeads` are heads the client computed earlier, by position. In order:
`from` is a valid position (`bad_request`); every removal whose `log_fence` is the
`from` position carries `from.log_head` (`rollback`); a kept head at the `from` position
equals `from.log_head` (`rollback`); every removal whose `log_fence` lies in
`1..from.log_seq - 1` has a kept head (missing: `bad_request`) equal to its `log_head`
(`rollback`); per entry: exact keys,
`log_seq` an integer ≥ 1, `conflict_id` `null` or an ID (`bad_request`); `log_seq` is the
previous position + 1 (`rollback`: gap, repeat or reorder); `verifyLoggedRecord`; the
head advances; every removal whose `log_fence` is the entry's position carries the head
computed there (`rollback`); a kept head at the entry's position equals the head
computed there (`rollback`: a different record at a position the client already
holds). With `complete` (the entries reach the current head), a `log_fence` beyond the
last position is `rollback`, then a kept head beyond the last position is `rollback`.
It returns the new cursor and the verified records. Apart from fences below `from`,
no position requires a kept head, and on a page that is not `complete` a kept head
beyond the last entry is not checked.

### 5.1 Profile layout

A secret item MAY carry a **profile**: operator-facing text that helps a person or an
agent choose a credential. It lives inside the item ciphertext as `meta.profile`, an
object whose keys are drawn from the closed set below. A policy item (§8.1) never
carries one. Each value is a field object with exactly the keys `value`, `by`, `at`
and `src`:

```json
"profile":{"provider":{"value":"stripe","by":"<device_id>","at":1767225600000,"src":"local"},
           "tags":{"value":["billing","live"],"by":"<device_id>","at":1767225600000,"src":"import"}}
```

- `by` is the device ID (§2) that last changed the field; `at` is that change's
  unix milliseconds; `src` is the closed set {`local`: typed by that device's
  operator, `import`: derived by an importer on that device}.
- Text rules for every string (a text `value` and each list item): non-empty, at most
  the limit in Unicode code points, and no code point in U+0000–U+001F, U+007F,
  U+0080–U+009F, U+061C, U+200B, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069,
  U+2028, U+2029 or U+FEFF (controls, bidi marks, embeddings, overrides and
  isolates, the zero-width space, line and paragraph separators, and the byte order
  mark). The zero-width non-joiner and joiner (U+200C, U+200D) are allowed: Persian
  and Indic text and emoji sequences need them.
- Lists: 1–32 items, each at most 64 code points, without a comma, no two items equal.

| Key | `value` | Limit |
|---|---|---|
| `description`, `when_to_use`, `when_not_to_use` | text | 1024 |
| `provider`, `account`, `environment`, `owner` | text | 128 |
| `projects`, `tags`, `permissions`, `aliases`, `usage_hosts` | list | 32 × 64 |
| `kind` | one of `api_key`, `token`, `password`, `private_key`, `certificate`, `connection_string`, `webhook_secret`, `client_secret`, `other` | — |
| `sensitivity` | one of `normal`, `high` | — |
| `expires_at` | RFC 3339 UTC text `YYYY-MM-DDTHH:MM:SSZ` | 20 |
| `rotate_url` | text starting `https://` | 512 |

The profile `sensitivity` is a label for whoever chooses a credential. It is not the
payload `sensitivity` (§3.2), and no grant, policy or approval reads it.
`validateProfile(profile)` refuses an unknown key, a field object with other keys, a
wrong type, an unknown `src`, `kind` or `sensitivity`, or a broken text or list rule
(`bad_request`). A receiver whose pulled profile fails it keeps the rest of the item
and drops `meta.profile` (audit `profile_invalid`).

**Provenance.** `checkProfileProvenance(prev, next, record, {selfDeviceId, prevOrigins})`
makes `by` and `at` checkable without new signatures. `prev` is the validated
profile of the item at revision `record.base_revision` as this device verified it
(an empty profile when
`base_revision` is 0 or that revision is a tombstone), or `null` when the device does
not hold that revision. For each field of `next`:

- `prev` holds the field with an equal `value` (lists compared item by item, in
  order): the field MUST be byte-identical to the one in `prev` (same `by`, `at`,
  `src`);
- otherwise (new or changed value): `by` MUST equal `record.author` and `at` MUST
  equal `record.ts`.

A field that breaks the rule is dropped and audited `profile_provenance_invalid` (item
ID and field key, never the text); the record and every other field still apply.
When `prev` is `null` the device cannot check unchanged fields and keeps every field
as claimed.

**Origins.** The check returns an origin for every kept field, and the device stores
those origins with the revision. The origin is transitive, so the own label comes
only from this device's own write history. A field is shown as its own (`src`) only
when `by` is this device's ID, `prev` was held (or the record is a create), and
either:

- the field is new or changed in this record and `record.author` is this device; or
- the field is carried unchanged and its stored origin in `prevOrigins` (the origins
  this check returned when the device accepted `prev`) is that same `src`.

Every other field is shown as `sync` and treated as untrusted text written by a vault
member. That includes every field when `prev` is `null`, even on a record this device
wrote, since such a record may carry a field forged under this device's ID. A field
kept under `prev = null` therefore stays `sync` for as long as it is carried
unchanged. A later revision checked against the held one cannot upgrade it, and
neither can this device's own later record that carries it. A device computes the
origins of its own records with the same check before storing them. Writers MUST
build `next` by the same rule. A conflict branch's profile is never applied; a
resolving record is checked against its `base_revision`.

Writers keep profile data only under `meta.profile`. A writer that carries unknown
`meta` keys forward from the previous head MUST NOT carry forward `kind`, `item_ids`
or `policy` (§8.1), and MUST NOT carry forward any key that, lowercased with `_`, `-`
and `.` removed, equals a profile key with `_` removed. A key such as `whentouse` or
`usagehosts` written by an older client is therefore dropped rather than re-signed by
the next editor. Payload `meta` keys are already `[a-z0-9_]+` (§2 canonical JSON),
so the case, `-` and `.` folds are defensive. Profile text is inert,
author-attributed data: it never creates or widens a grant and is never interpreted
as an instruction (§8).

Vectors (`profile.json`): a changed field with `by` ≠ author, or `at` ≠ record `ts`,
is dropped; an unchanged field relabelled to another device is dropped; an unknown key,
an over-length text, a list with a duplicate or a comma, a bidi mark, a zero-width
space or a byte order mark, and an unknown `kind` → `bad_request`, while text with a
zero-width non-joiner or joiner is accepted; with `prev` `null` every field is
kept and shown `sync`, also on this device's own record; a create (`base_revision` 0)
requires every field by the author. The `chains` replay consecutive revisions for one
device. A field forged in its name under `prev = null`, then carried unchanged by the
forger and by the device itself, stays `sync` at every step. Its own field carried
through other devices' edits stays its `src`.

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
`state_digest`. `checkRollback` on checkpoints alone does not catch that case: a
client that reads positions at or below its highest witnessed `log_seq` again MUST
pass the head it computed there in `keptHeads` (§5) (vectors: `checkpoints.json`
`regrown_past_witnessed_passes_checkpoint_comparison_alone`, `removal-fence.json`
`restored_regrown_*`). Every client that verifies a peer's checkpoint, which carries
no head, MUST compare the `state_digest` it computed at that checkpoint's `log_seq`. A client that resumes from its own cursor does not read those
positions again, so the log alone does not show it the restore. Comparing the
served current head with its own catches an operational restore, not a server that
serves the head the client expects. Such a client keeps the records it holds: a
re-served older revision is a replay (`applyRecord`: `conflict`), while records
current members wrote on the restored line still apply or branch by
compare-and-swap. A
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

### 7.1 Event plaintext

The plaintext of an entry is the canonical JSON of one event object. Every writer
and every reader shares this envelope (the `ak` CLI defines the types below):

```json
{"v":1,"type":"<name>","device_id":"<id>","ts":<unix ms>, ...}
```

- `v` is the integer `1`; any other value, or none, is `unsupported_version`.
- `type` is 1 to 64 bytes of `[a-z0-9_]`, starting with a letter.
- `device_id` is the opaque ID (§2) of the device that acted; `ts` is a non-negative
  safe integer in unix milliseconds.
- Other fields depend on `type`. Events name items and devices by opaque ID only,
  never a secret name, value, profile text, token, key or recovery material
  (data classification: audit).

Types defined today, each with the fields it carries besides the envelope:
`item_put`, `item_delete`, `conflict_settled` (`item_id`, `revision`);
`device_add`, `device_remove` (`subject_device_id`); `rekey`, `recover`,
`recovery_rotate` (none); `profile_invalid` (`item_id`, `revision`);
`profile_provenance_invalid` (`item_id`, `revision`, `field`);
`sealed_applied` (`sealed_id`, `client_id`, `item_id` when it wrote one) and
`sealed_refused` (`sealed_id`, `client_id`); `mcp_call` (`client_id`, `tool`,
`outcome`). The `ak` CLI parses each of these strictly: a field its type does not
carry, or a malformed one, makes it refuse the entry.

**Unknown types.** A reader MUST accept an event whose `type` it does not define when
its envelope is well formed, keep only `type`, `device_id` and `ts`, and read no other
field. It MUST NOT skip or reject the entry or the chain: a newer writer's event type
never stops an older device from verifying or appending. A new type needs no
protocol change; a writer MUST choose a name no existing type uses, and MUST NOT
reuse a defined name with another field set. For example, a `rotation_started`
event from another writer is an unknown type to the CLI, which keeps its envelope only.

A writer that does not use this envelope (for example `action` in place of `type`,
or no `v`) makes a CLI device refuse the chain and stop appending audit entries
(secret sync is unaffected). A verifier of the chain (§7) decrypts entries whose
plaintext is any JSON object; checking the envelope is the event reader's job
(`parseAuditEventEnvelope`; vectors: `audit.json` `event_envelopes`).

## 8. Portable policy (restrictive only)

Encrypted item with `meta.kind = "policy"` (payload layout and binding: §8.1). Fields are maxima only:
`{"max_ttl_s","require_approval","allowed_projects":[…],"allowed_purposes":[…],"deny_agents":[…]}`.
Effective grant = local grant ∩ portable policy. A policy can only narrow; a missing
field means "no extra restriction", never "allow". `sensitivity:"high"` always
requires fresh operator approval. Policy text, URLs, `when_to_use` and descriptions
are untrusted, author-attributed data and are never interpreted as instructions.
Project IDs have no vault or device namespace on the wire: a project named only in
`allowed_projects` and absent from the device-local grant grants nothing
(`policy.json` `foreign_project_ids_grant_nothing`), and a policy item moved to
another vault fails to open (item AAD and item-key salt bind `vault_id`, §3.2;
`item.json` `moved_to_other_vault`). A device that holds a newer policy revision
refuses an older one the server re-serves, as a replay (`applyRecord`: `conflict`) or
as a rollback against its witnessed checkpoint and kept head (§5, §6); a device that
never saw the newer revision is subject to the withholding limitation (§6).

### 8.1 Policy binding

A policy item names the items it governs by item ID, inside its own ciphertext.
Its live payload (§3.2) is exactly:

```json
{"name":"<label>","value":"","meta":{"kind":"policy","item_ids":[item_id…],"policy":{…}},"sensitivity":"normal"|"high"}
```

- `meta.kind` is the string `"policy"`; every other item is not a policy item.
- `meta` has exactly the keys `kind`, `item_ids` and `policy`; `value` is `""`.
- `item_ids`: 1–1024 unique opaque item IDs (§2) of the items this policy governs,
  never the policy item's own ID. Names are never used: an ID is unique in the vault
  and survives a rename. A policy governs exactly the items it lists: an item written
  later, or a secret deleted and re-created under a new ID, is ungoverned until a
  member edits the policy. v1 has no vault-wide default policy.
- `policy`: the §8 policy object, parsed as in §11 ("Portable policy").
- The payload `sensitivity` is the minimum sensitivity the policy imposes on every
  governed item: `"high"` makes every governed item `high`; `"normal"` never lowers one.
- `name` is an inert label (untrusted text).

A writer MUST check a policy item with `parsePolicyItem(item_id, payload)` (binding,
then body) before sealing it; `sealItem` itself does not check the layout.

The binding, the rules and the sensitivity are inside the item ciphertext, which
the author's record signature and the item AAD cover (§3.2, §5). The server sees only
that an item exists, never which items a policy governs. Nothing on the governed
item points back to the policy.

**Resolution.** Before releasing an item, a client calls
`resolveItemPolicy(target, items)` (vectors: `policy-binding.json`). `items` is every
item the device holds for the vault, each `{"item_id","head","branches"}`: the
current head and every unresolved conflict branch (§5), each
`{"tombstone":bool,"payload":<decrypted payload object>|null}`, where `null` means
the device could not open that record. Checks, in order, the first failure being the
result:

1. shape: `target` and every `item_id` are IDs, `item_id`s are unique, every entry
   has exactly `tombstone` and `payload`, a payload is an object or `null`, at most
   1 000 000 items and 4096 branches per item (`bad_request`);
2. any entry with a `null` payload → `decrypt_failed`: an unopened record could be a
   policy governing the target, so the device refuses every item of the vault until
   it can open it;
3. every payload parses as an item payload for its `tombstone` flag (§11; `bad_request`);
4. every live payload with `meta.kind` `"policy"`, head or branch, has a valid
   binding (`parsePolicyBinding`: `value`, the exact `meta` keys and `item_ids`;
   `bad_request`), whichever item it names. An unknown `meta` key, such as a later
   scope field, therefore refuses every item rather than being ignored;
5. the target is present, its head is live, and neither its head nor a branch is a
   policy item (`bad_request`);
6. an item that has unresolved conflict branches, and whose head or any branch is a
   live policy naming the target, is `conflict` (resolve the conflict first);
7. the `policy` body of every governing policy parses (`parsePolicy`, `bad_request`).
   The body of a policy that does not name the target is not parsed, so it affects
   only the items it governs.

The governing policies are the live heads, on items without conflict branches, that
name the target. The result is `{"policy","sensitivity"}`: `policy` is `null` when
nothing governs the target, else the intersection of the governing policies, taken
in the byte order of their base64url `item_id` strings: `max_ttl_s` is the minimum,
`require_approval` the OR, each `allowed_*` list the intersection, `deny_agents` the
union, each present only if some governing policy has it, lists in first-occurrence
order without duplicates and free text dropped. `sensitivity` is `"high"` when any
live record of the target (head or branch) or any governing policy item is
`"high"`. The client then releases at most `effectiveGrant(local, policy, sensitivity)`.

Any failure is a refusal to release: the client MUST NOT fall back to the local
grant alone, and nothing here can widen a local grant. Steps 2 and 4 refuse every
item of the vault, because the device cannot tell which items an unopened record or
an unreadable binding governs; items outside the vault are unaffected. A device that
lacks an older epoch's key (§4) therefore refuses the vault until those items are
rotated forward. A tombstoned policy governs nothing; an ID in `item_ids` that names
no live non-policy item has no effect. A policy moved from another vault does not
open (§3.2) and so refuses at step 2; an older policy revision the server re-serves
never becomes the head (§5, §6). A device that never received a policy item is
subject to the withholding limitation (§6), and any member who can write the vault
can edit or delete a policy, as it can any item: a policy caps the release path of
devices that honor it, not what a vault member can decrypt (§3).

## 9. Transport authentication (Worker)

1. `Authorization: Bearer <ES256 JWT>` from the configured issuer. Required claims:
   `iss` (exact), `aud` = the deployment's own origin (exact; production
   `https://vault.agentkit.best`, staging `https://vault-staging.agentkit.best`), `sub`, `exp`, `nbf`,
   `iat`, `jti`, `scope` ⊆ {`vault:read`,`vault:write`}, `sid`, `did`. Optional
   `session_kind` ∈ {`email_otp`, `api_key_device`, `machine`, `browser`}: how the session behind the
   token signed in. An absent claim means `email_otp` (the only kind issued before the claim
   existed); any other value, or a non-string, is `401 unauthorized`. ak-web MUST set it for
   every session that is not a human email-OTP sign-in; the Worker never infers it, so a
   non-human session minted without it is read as `email_otp` (see the threat model's
   recovery bundle limitation). The audiences `<origin>/mcp` and `<origin>/app` name
   other resources (the remote MCP endpoint and the dashboard sign-in) and are refused
   on every route of this section like any other wrong `aud`.

   **Browser sessions.** `browser` marks a token ak-web minted for the vault dashboard
   in exchange for a dashboard sign-in grant; its `sid` is that grant's ID. The device
   behind it is an ordinary enrolled device record (§4: `kind` `human`, its account's
   role, so `owner` in a personal vault), added by an owner device's `device_add`
   after a SAS match (§3.5, §3.8). The session kind, not the role, restricts it: the
   Worker refuses a `browser` session with `403 forbidden` on genesis
   (`PUT /v1/vaults/{vid}`), on every `POST /v1/vaults/{vid}/membership` (recovery
   enrollment included), on `GET` and `PUT /v1/vaults/{vid}/recovery`, on the
   recovery-identity reads (§3.5), on `PUT /v1/vaults/{vid}/seal-key` and on draining
   sealed operations (`GET …/sealed`, `POST …/sealed/{id}/ack`). Conversely, only a
   `browser` session may read or close a write request or complete one with an item
   PUT (§3.10, §9.6); every other kind is `403 forbidden` there. Every other route
   treats it as the member device it is. Header `alg`
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
   through the recovery identity. **Recovery operations** (`GET` and
   `PUT /v1/vaults/{vid}/recovery`, and a `POST …/membership` carrying a
   `recovery_rotate` event or a `bundle`) additionally require an `email_otp` session,
   whatever the device's role, with one exception, the **genesis seal**: an
   `api_key_device` or `machine` session on an owner-role device may
   `PUT /v1/vaults/{vid}/recovery` while the vault has no stored bundle, under the
   usual role, scope and proof checks. Every other recovery operation by such a
   session (a read, a `PUT` that would replace a stored bundle, a rotation) is
   refused with `403 forbidden` before its proof is consumed, the same refusal as on
   the recovery identity; an exact idempotent retry of the genesis seal (§5) is
   answered with its stored result, so a client whose answer was lost MUST retry
   with the same `Idempotency-Key` and body (it cannot read the bundle to check). The server re-checks "no stored bundle" in the
   transaction that stores it. Such a device keeps every other right of its role,
   removal and rekey included, but cannot reseal: after a rekey it makes, the stored
   bundle cannot enroll a device (§3.5) until an owner device in an `email_otp`
   session reseals it. A token without `session_kind` is read as `email_otp`
   (item 1).
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

### 9.6 Remote-access routes

Served only where the deployment enables remote access (every route below answers
`404` otherwise). While the kill switch is off, the `/v1/vaults/…` routes below answer
`503 sync_disabled` like every other `/v1` path, whatever remote access is set to. Each runs the shared pipeline before touching vault data: token
(item 1), live revocation (item 3), proof (item 2), then membership, scope and role
(item 4). Bodies are JSON objects; unknown keys are `bad_request`.

| Route | Op | Scope | Who |
|---|---|---|---|
| `GET /v1/vaults/{vid}/lookup?tag=<b64>&key_epoch=<e>` (1–`lookup_tags_max` pairs) | `lookup.get` | `vault:read` | any member device |
| `GET /v1/vaults/{vid}/seal-key` | `sealkey.get` | `vault:read` | any member device |
| `PUT /v1/vaults/{vid}/seal-key` | `sealkey.put` | `vault:write` | human `owner` device, not `browser` |
| `GET /v1/vaults/{vid}/sealed?after=<seq>&limit=<n>` | `sealed.get` | `vault:read` | human `owner`/`editor` device, not `browser` |
| `POST /v1/vaults/{vid}/sealed/{sealed_id}/ack` | `sealed.ack` | `vault:write` | human `owner`/`editor` device, not `browser` |
| `GET /v1/vaults/{vid}/write-requests/{request_id}` | `writereq.get` | `vault:read` | `owner`/`editor` device of a `browser` session only |
| `POST /v1/vaults/{vid}/write-requests/{request_id}/close` | `writereq.close` | `vault:write` | `owner`/`editor` device of a `browser` session only |
| `PUT /v1/vaults/{vid}/items/{iid}?write_request=<request_id>` | `item.put` | `vault:write` | `owner`/`editor` device of a `browser` session only |
| `GET /v1/relay` (WebSocket upgrade, §9.7) | `relay.open` | `vault:read` and `vault:write` | human device, not `browser` or `machine` |

- **Lookup.** The *i*-th `tag` pairs with the *i*-th `key_epoch`; unequal counts, more
  than `lookup_tags_max` pairs, a tag that is not 16 bytes or an epoch outside
  `1..current` are `bad_request`. Response
  `{"hits":[{"item_id","revision","key_epoch","tag"}…]}`, items whose current head
  carries a requested pair, in `item_id` byte order; no hit is `{"hits":[]}`, never
  `not_found`.
- **Seal key.** `GET` returns `{"seal_key":<doc>}` for the vault's current key epoch,
  or `not_found`. `PUT` takes `{"seal_key":<doc>}`; the server runs
  `verifySealKeyDoc` steps 1–5 (§3.6) against its stored chain and also refuses a
  `key_epoch` other than the current one (`bad_request`) and an `author` other than
  the token `did` (`forbidden`). It keeps one document per key epoch: a document whose
  `membership_seq` is below the stored one for that epoch is `409 conflict`; otherwise
  it replaces it. Response `{"key_epoch","membership_seq"}`.
- **Sealed queue.** `GET` returns `{"sealed":[{"seq","op":<sealed op wire>}…],"next":<seq>|null}`
  in ascending `seq` (a server-assigned position, starting at 1), operations whose
  `origin.account` is the token `sub` with `seq` above `after` (default 0), at most `limit` (default and maximum
  `sealed_page_max`); expired operations are never served. `ack` takes
  `{"outcome":"applied"|"refused"}`, removes the operation's ciphertext (its ID stays
  until it expires, so a replayed `sealed_id` is refused) and returns `{}`; an
  unknown or already acknowledged `sealed_id`, or one of another account, is
  `not_found`, which the device treats as done. There is no route that creates a sealed operation.
- **Item PUT.** Also accepts the `{record, name_tag}` wrapper (§3.7).
- **Write requests** (§3.10). A request is served only to its requesting account: an
  unknown `request_id` or another account's is `not_found`, a closed or expired one
  `bad_request`. `GET` returns
  `{"request_id","operation","client_id","expires_at","intent":<write intent>}`.
  `close` takes `{"outcome":"cancelled","reason":"user_cancelled"}` or
  `{"outcome":"failed","reason":"already_exists"|"not_found"|"device_error"}` and
  returns `{"state"}`; any other body is `bad_request`. An item PUT with exactly one
  well-formed `write_request` query completes the request in the same transaction: a
  live target item for `create`, or none for `replace`, is `bad_request` and leaves
  the request open; an applied record answers the usual body plus
  `"write_request":{"state":"completed","receipt"}`; a `409` closes it `conflict`; any
  other failure writes nothing and leaves it open. A malformed or repeated
  `write_request`, or one where remote access is disabled, is `bad_request`.

### 9.7 Relay

The relay lets the Worker hand a remote MCP tool call to one of the account's online
devices, which decrypts locally, applies its own grants and approvals, and answers.
One connection per device; the device opts in by opening it.

**Upgrade.** `GET /v1/relay` with `Upgrade: websocket`, `Authorization` (a sync token,
item 1, whose `session_kind` is neither `machine` nor `browser`: the dashboard never
answers relay calls), `AKV-Device-Key: <b64 Ed25519 sign_pub>` with
`kid(sign_pub)` = `did`, and `AKV-Proof` (htm `GET`, htu the exact
`<origin>/v1/relay`, `ath` of the token, `bh` of the empty body) verified
against that key. More than `relay_devices_per_account` open connections for the
token `sub` → `429 rate_limited`. A new connection for the same `did` closes the old
one (4409).

**Frames.** Text frames only, each one canonical `cjson` object of at most
`relay_frame_max_bytes`, with exactly the keys listed for its `type`; the `type` set is
closed. Any other frame closes the connection with 4400.

| Direction | `type` | Object |
|---|---|---|
| device → server | `hello` | `{"v":1,"type":"hello","device_id","vaults":[vault_id…],"tools":[tool…],"ts","sig"}` |
| server → device | `ready` | `{"v":1,"type":"ready","exp":<unix s of the token now in force>}` |
| device → server | `reauth` | `{"v":1,"type":"reauth","token","proof"}` |
| server → device | `call` | `{"v":1,"type":"call","call_id":"<b64 16B>","vault_id","tool","args":{…},"caller":{"client_id","grant_id","scopes":[…]},"deadline_ms"}` |
| device → server | `result` | `{"v":1,"type":"result","call_id","ok":true,"result":{…},"sig"}` or `{"v":1,"type":"result","call_id","ok":false,"error":{"code"},"sig"}` |

- `hello` is the first device frame, within `relay_hello_timeout_ms` of the upgrade,
  and is sent once. Signing context `akv1/relay` over the frame without `sig`, by the
  `did` key. `device_id` = token `did`; `ts` (unix ms) within ±60 s; `vaults` 1–16 unique IDs;
  `tools` 1–7 unique names from the tool set. For every listed vault, `did` MUST be a
  current `human` device of the token `sub` whose `sign_pub` is the upgrade key, else
  close 4403. The server answers `ready`.
- `reauth` carries a fresh sync token for the same `sub` and `did` and its proof (the
  `AKV-Proof` header value: htm `GET`, htu the relay URL, `ath` of the new token, `bh`
  of the empty body, fresh `jti`). It MUST arrive before the token in force expires,
  else close 4401. The server verifies token, revocation and proof as at the upgrade
  and answers `ready`. A token for another `sub` or `did` closes 4401.
- Before each `call` the server checks revocation of the token in force (`sid`, `did`,
  minimum `iat`), closing 4401 when revoked, and checks membership again: `did` MUST
  still be a current `human` device of the token `sub` in `call.vault_id`. A device
  that is no longer one gets no call; the server drops that vault from the
  connection and closes it with 4403 when no listed vault remains. `reauth` repeats
  the membership check for every listed vault. A device has at most
  `relay_calls_inflight_per_device` calls outstanding. `vault_id` is always set (the
  server picks the vault before choosing a device). `deadline_ms` is the time the
  device has from receipt, at most `relay_call_deadline_ms` (`run`:
  `relay_run_deadline_ms`). `caller.scopes` are the MCP token's scopes; a device MUST
  refuse a tool the scopes do not cover (`denied`): `search`, `list`, `describe` need
  `vault-mcp:read`; `set`, `delete` need `vault-mcp:write`; `request`, `run` need
  `vault-mcp:use`.
- `result` answers one `call` once. Signing context `akv1/relay-result` over the frame
  without `sig`, by the `did` key; the server verifies it and drops a result that does
  not verify, arrives after the deadline, or names an unknown `call_id`. `ok:true`
  carries `result` and no `error`; `ok:false` carries `error` (exactly `code`) and no
  `result`. `error.code` is the closed set {`denied`, `pending_approval`, `not_found`,
  `invalid_args`, `conflict`, `unsupported`, `internal`}; a tool the device did not
  list in `hello` is `unsupported`.
- Close codes: 4400 bad frame, 4401 token expired or revoked, 4403 not a member or
  wrong device kind, 4409 replaced by a newer connection of the same device, 4429 the
  device sent frames faster than the server accepts them (more than
  `relay_calls_inflight_per_device` unsolicited `result` frames, or more than
  `relay_reauth_per_token_lifetime` `reauth` frames within one token lifetime).

**Tools.** `tool` is the closed set {`search`, `list`, `describe`, `set`, `delete`,
`request`, `run`}. Arguments and results are `cjson`, so object keys are
`[a-z0-9_]+`. Names and values follow the item payload limits (§3.6); a `set` whose
`{"op":"set","name","value","sensitivity"?}` object would exceed 65 536 bytes in
`cjson` is `invalid_args` before it is relayed or sealed, so a `call` always fits
`relay_frame_max_bytes`. Text fields follow the profile text rules (§5.1).

| Tool | `args` (exact keys; `?` optional) | `result` |
|---|---|---|
| `search` | `{"query":1–200 code points,"fields"?:[…],"limit"?:1–50}`; `fields` ⊆ {`name`, `description`, `provider`, `account`, `environment`, `projects`, `tags`} | `{"items":[entry…]}` |
| `list` | `{"cursor"?:string ≤256 bytes,"limit"?:1–100}` | `{"items":[entry…],"next_cursor"?:string}` |
| `describe` | `{"name"}` | `{"name","profile","sensitivity","created_at"?,"rotated_at"?,"last_device_label"?}`; `sensitivity` is the payload's (§3.2) |
| `set` | `{"name","value","sensitivity"?}` | `{"status":"written","revision"}` or `{"status":"conflict"}` |
| `delete` | `{"name"}` | `{"status":"deleted"}`, `{"status":"conflict"}` or `{"status":"not_found"}` |
| `request` | `{"name","purpose":1–200 code points,"project"?:≤128,"ttl_s"?:1–86400}` | `{"status":"pending"|"granted"|"denied","request_id":≤64 bytes}` |
| `run` | `{"argv":[1–64 strings],"env":[{"var","name"}…1–16],"cwd_project"?:≤128,"timeout_s"?:1–110}` | `{"exit_code","stdout","stderr","truncated"}` |

- `entry` = `{"name","profile","updated_at"}`; `profile` maps each present profile
  key (§5.1) to `{"value","origin"}`, `origin` ∈ {`local`, `import`, `sync`} as this
  device classifies it; `updated_at`, `created_at`, `rotated_at` are unix ms;
  `last_device_label` is display text of at most 64 bytes.
- `run.env` names environment variables (`var` matches `[A-Z_][A-Z0-9_]*`, at most
  128 bytes, unique) and the secret each receives. The device runs only commands an
  `exec` grant pinned on that device allows, never prompts from the relay, and
  answers `pending_approval` when no grant covers the call. `exit_code` is an
  integer ≥ 0 (a child the device killed, including at timeout, reports 137 on every
  OS). `timeout_s` stays below `relay_run_deadline_ms` so the result can still
  arrive. The device decodes output as UTF-8, replacing invalid sequences with U+FFFD,
  truncates `stdout` and `stderr` so the whole frame fits `relay_frame_max_bytes`, and
  sets `truncated` when it cut anything.
- A `result` MUST NOT contain an item value, except `run` output after the device
  redacted every value it released to the child. Redaction removes exact values only;
  output a command transformed (encoded, split, partial) is not caught. A `set` call carries the value from
  the server to the device; nothing carries one back.

Vectors (`relay-frames.json`): each frame type valid; an unknown `type`, an extra or
missing key, a binary-only or oversize frame, a bad `hello` or `result` signature, a
`result` signed by another device, `ok:true` with `error`, and an unknown error code
are refused.

### 9.8 MCP endpoint

`POST /mcp` is the Worker's remote MCP endpoint, served only where remote access is
enabled. It is not a `/v1` route and runs no `AKV-Proof` check; its credential is an
MCP access token. It obeys the sync kill switch: while the switch is off, `/mcp`
answers `503 sync_disabled` (§10 error body) before any token check.

- **Token.** ES256 JWT, header `typ` `at+jwt`, exactly the claims `iss`, `aud` =
  `<origin>/mcp`, `sub`, `client_id`, `grant_id`, `sid` (= `grant_id`), `scope`, `jti`,
  `iat`, `nbf`, `exp`, with `exp` ≤ `iat` + 600 s. `scope` is a space-separated subset
  of {`vault-mcp:read`, `vault-mcp:write`, `vault-mcp:use`}. There is no `did` and no
  `session_kind`. The Worker checks issuer, audience, algorithm, key, times, and live
  revocation of `sid` and `sub` per request (item 3), then that `sub` is a member of
  the selected vault; a vault that does not exist and a vault `sub` is not a member
  of both answer the tool error `invalid_args`, alike, so the answer never says
  whether the vault exists. The `/v1` routes refuse this token (item 1) and `/mcp`
  refuses every other audience.
- **Discovery.** RFC 9728 protected-resource metadata at
  `GET /.well-known/oauth-protected-resource/mcp` names the resource `<origin>/mcp`,
  the authorization server (the token issuer) and the scopes above; no other
  metadata path is served. A missing or invalid token answers `401` with a
  `WWW-Authenticate: Bearer` header carrying `resource_metadata`, plus
  `error="invalid_token"` when a bearer token was presented and refused.
- **Protocol.** MCP revision 2026-07-28, stateless: POST only (other methods `405`),
  `server/discover`, no `Mcp-Session-Id`. A 2026-07-28 request names its version in
  `MCP-Protocol-Version`; an unsupported value answers `400` `-32022` with the
  request's `id`. A request without the header is served as 2025-11-25, statelessly:
  a 2025-11-25 client's `initialize` is answered without a session ID.
- **Rate limits.** Every JSON-RPC request that passes transport validation (method,
  `Origin`, kill switch, token and revocation, headers and protocol version, body and
  JSON-RPC parsing) spends one call from the `mcp_calls_per_minute_per_client` and
  `mcp_calls_per_minute_per_account` budgets (§10), and a `run` call also from
  `mcp_run_calls_per_minute_per_client`; a request refused before that point, and a
  notification, spends nothing. A refused `tools/call` of a known tool within the
  token's scopes whose `arguments` is absent, `null` (treated as absent) or an object
  is the tool error `rate_limited` with `retry_after_s`; any other refused request, including such a call whose `arguments`
  is any other value, is HTTP `429 rate_limited` with `Retry-After` and the §10 error
  body. A call refused as `rate_limited` writes no audit row.
- **Tools** are the relay tools (§9.7), named `secrets_<tool>`, plus two the Worker
  answers itself (below). A relay tool maps one to one onto §9.7 with the same scope. Each
  takes the relay `args` plus an optional `vault_id`. Without it the Worker uses the
  one vault the account's online relay connections list. When they list more than
  one, the call needs `vault_id` (`invalid_args`). When none is online, a read or
  `use` tool answers `no_device_online` with the relay hint, and `set` or `delete`
  needs `vault_id` (`invalid_args`), so a sealed write always names its vault. The
  Worker relays the call to
  one online opted-in device of `sub` that listed that vault and tool in `hello`.
- **Sealed fallback.** With no such device, `set` and `delete` are sealed (§3.6) and
  answer `{"status":"queued","sealed_id"}`; every other tool answers
  `no_device_online`. A `set` puts the value in the MCP client's own tool call, and so
  in the AI's context; a secret the AI must not see goes through a write request.
- **Write requests** (§3.10), scope `vault-mcp:write`, answered by the Worker with no
  device online:
  - `secrets_prepare_write` takes exactly `{"name","operation"?:"create"|"replace","purpose"?,"sensitivity"?,"ttl_s"?,"vault_id"?}`
    (`operation` default `create`; `ttl_s` from `write_request_min_ttl_s` to
    `write_request_ttl_s`, default the maximum). It takes no value: any other key, a
    `value` included, is `invalid_args` and is not echoed. It seals the intent and
    answers `{"status":"pending_user","request_id","vault_id","form_url","expires_at","next"}`,
    `form_url` being the §3.10 link. Besides the general budgets it spends one call
    from `mcp_prepare_write_per_minute_per_client`.
  - `secrets_write_status` takes `{"request_id","vault_id"?}` and answers
    `{"state","reason"?,"receipt"?,"expires_at"}` (§3.10 states), only to the account,
    `client_id` and `grant_id` that asked; any other caller gets `not_found`, as for
    an unknown ID.
  - Vault selection follows the relay tools: without `vault_id` the Worker uses the
    one vault the account's online devices list, else `invalid_args`. A vault the
    account cannot write is `invalid_args`.
- **Errors.** A device `error.code`, `no_device_online`, `device_timeout`,
  `sealed_queue_full`, `no_seal_key`, `too_many_requests` and `rate_limited` are MCP tool errors (`isError` true) carrying
  `{"code"}`; a token or scope failure is an HTTP `401` or `403`, a rate-limited
  request that is not such a tool call (see rate limits) an HTTP `429 rate_limited`, and the
  kill switch an HTTP `503 sync_disabled`, with the §10 error body. Messages never
  echo arguments.

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

Remote access adds three codes, all returned only by the MCP endpoint as tool errors
(§9.8) and never as the HTTP status of a `/v1` route: `no_device_online` (no opted-in
device of the account holds the vault, or none is online for a read or `use` call
without `vault_id`, and the call cannot be sealed),
`device_timeout` (the device missed `deadline_ms`) and `sealed_queue_full` (the vault
already holds `sealed_queue_max` operations, acknowledged ones kept for replay refusal
included). Write requests (§3.10) add two more MCP tool errors: `no_seal_key` (the vault
has no seal-key document for its current epoch) and `too_many_requests` (the account
already has `write_requests_pending_per_account` open requests in the vault, the requesting
client already has `write_requests_pending_per_client` of them, or the account
holds `write_requests_retained_per_account` rows in the vault, closed ones kept until their retention
ends included). `worker/src/limits.ts` owns the relay and MCP limits and `GET /v1/meta`
publishes them where remote access is enabled; the table lists them for orientation,
and `limits.ts` wins on any difference:

| Limit | Value |
|---|---|
| `relay_frame_max_bytes` | 131072 |
| `relay_hello_timeout_ms` | 10000 |
| `relay_calls_inflight_per_device` | 4 |
| `relay_devices_per_account` | 8 |
| `relay_reauth_per_token_lifetime` (per connection) | 3 |
| `relay_call_deadline_ms` | 60000 |
| `relay_run_deadline_ms` | 120000 |
| `sealed_queue_max` (per vault) | 256 |
| `sealed_ttl_s` | 604800 |
| `sealed_page_max` | 50 |
| `lookup_tags_max` | 8 |
| `mcp_calls_per_minute_per_client` | 60 |
| `mcp_run_calls_per_minute_per_client` | 10 |
| `mcp_calls_per_minute_per_account` | 300 |
| `mcp_prepare_write_per_minute_per_client` | 6 |
| `write_request_ttl_s` (default and maximum) | 600 |
| `write_request_min_ttl_s` | 60 |
| `write_request_retention_s` | 86400 |
| `write_requests_pending_per_account` (per vault) | 8 |
| `write_requests_pending_per_client` (per account and vault) | 4 |
| `write_requests_retained_per_account` (open and retained, per vault) | 64 |

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
  `decrypt_failed` (vectors: `audit.json`). `parseAuditEventEnvelope(event)` checks the
  event envelope of a decrypted entry (§7.1) and returns `{type, device_id, ts}`.
- **Transport proof:** `ts` is unix milliseconds, `jti` is b64 of 16 random bytes,
  `htm` is an uppercase method and `htu` is compared exactly. The proof blob MUST be
  canonical. Bad signature → `invalid_signature`; every other proof failure →
  `unauthorized`.
- **Portable policy:** unknown fields or wrong types are `bad_request` (the caller
  denies). `description`, `when_to_use` and `urls` are carried as inert text.
  A policy item's layout and the binding rules are in §8.1; `parsePolicyBinding`,
  `parsePolicyItem` and `resolveItemPolicy` reject a payload whose `meta.kind` is
  `"policy"` in any other layout (`bad_request`). `openItem` and `sealItem` do not
  check the layout.
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
- **2026-10 (issue #7):** policy binding (§8.1): a policy item's payload layout,
  `meta.item_ids` naming the governed items, the payload `sensitivity` as a minimum,
  and `resolveItemPolicy`. Earlier revisions defined no policy-item layout and no
  client applied policy items, so no existing data changes meaning.
- **2026-10 (issue #101, bestagentkits/ak-web#628):** remote access, all additive: the
  seal key and sealed operations (§3.6), name tags and the `{record, name_tag}` item
  PUT wrapper (§3.7), enrollment code formats (§3.8), the profile layout and its
  provenance check (§5.1), the `browser` session kind (§9 item 1), the remote-access
  routes (§9.6), the relay (§9.7) and their errors and limits (§10). A bare record
  PUT, every existing route and every existing body keep their meaning, so clients
  that ignore these additions keep verifying and syncing and no data is reset. One
  limitation: a writer that predates §5.1 does not carry `meta.profile` forward, so
  its edit of an item drops that item's synced profile.
- **2026-10 (issue #119):** human write requests, additive: the write intent (§3.10),
  the write-request routes and the `write_request` item-PUT query (§9.6), the
  `secrets_prepare_write` and `secrets_write_status` MCP tools (§9.8) and their errors
  and limits (§10). Nothing existing changes meaning.
