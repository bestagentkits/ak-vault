/**
 * `@ak-vault/protocol` — TypeScript reference implementation of protocol akv1
 * (normative spec: `docs/protocol/v1/spec.md`; vectors: `protocol/v1/vectors/`).
 * Runtime-neutral: no `node:` imports, only Uint8Array/TextEncoder/WebCrypto RNG,
 * so it runs in Cloudflare Workers, Node and browsers. All failures throw
 * {@link AkvError} with a stable `code` (spec §10, plus client-side `decrypt_failed`).
 *
 * Public API by area:
 *
 * Errors — `AkvError`, `AkvErrorCode`, `AKV_ERROR_CODES`, `isAkvError`.
 *
 * Encodings (§2)
 * - `b64encode(bytes): string`, `b64decode(text): Uint8Array` (strict), `b64decodeLength`, `sha256b64`.
 * - `cjson(value): string`, `cjsonBytes(value): Uint8Array`, `cjsonParse(text|bytes): JsonValue`
 *   (input must already be canonical), `parseJson(text): JsonValue` (strict, order-free).
 * - `signingInput(context, obj): Uint8Array`, `kid(pub)`, `deviceIdFromSignPub(pub): string`,
 *   `signDetached`, `signObject`, `verifyDetached`, `verifyObject`, `SIGN_CONTEXT`.
 *
 * Encryption (§3)
 * - `sealEnvelope(key, pt, aad, {kid, nonce?}): Envelope`, `openEnvelope(key, env, aad, kid?)`,
 *   `parseEnvelope`, `assertUniqueNonces`, `epochTag(e) = "e<e>"`.
 * - Items: `deriveItemKey`, `itemAad`, `sealItem`, `openItem`, `parseItemPayload`.
 * - Wraps: `wrapToDevice`/`unwrapFromDevice` (x25519-xc20p), `wrapWithPassword`/`unwrapWithPassword`
 *   (argon2id-xc20p, `validateArgonParams`), `wrapWithRecoveryKey`/`unwrapWithRecoveryKey` (rk-xc20p),
 *   `encodeRecoveryKey`/`decodeRecoveryKey` (Crockford base32).
 * - Recovery bundle (§3.4, §11): `sealRecoveryBundle(args): RecoveryBundleWire`,
 *   `openRecoveryBundle({bundle, vaultId, password? | rk?, knownBundleSeq?}): OpenedRecoveryBundle`.
 * - SAS (§3.5): `sasTranscript`, `sasCode`, `sasDigest`.
 *
 * Membership (§4)
 * - `verifyMembershipChain(events, {trustedAnchor?, witnessedCheckpoint?, vaultId?}): MembershipState`.
 * - `buildGenesisEvent`, `nextMembershipEvent`, `signMembershipEvent`, `membershipEventHash`, `findDevice`.
 * - `validateWrapRecipients(state, wraps, {keyEpoch?, requireAll?}): X25519Wrap[]`, `wrapsDigest(wraps)`.
 * - `verifyRekeyWraps(rekeyEvent, wraps, {state?}): X25519Wrap[]` checks a wrap set against the signed `wraps_digest`.
 * - `verifyDeviceWraps(addEvent, wraps): X25519Wrap[]` checks the wraps delivered with genesis/device_add/member_add;
 *   `addedDevices(event)`.
 *
 * Records (§5)
 * - `signRecord`, `parseRecord`, `verifyRecord(record, state): SignedRecord`, `verifyRecordSignature`,
 *   `authorizeRecordWrite(state, record): void`, `recordDigest`.
 * - `verifyLoggedRecord(record, state, logSeq)` verifies change-log records, including those by removed
 *   authors, against each removal's signed `log_fence`.
 * - `applyRecord(itemState | undefined, record, {conflictId?, isReplay?}): {state, outcome}` (pure CAS model),
 *   `emptyItemState`, `computeStateDigest(items)`.
 *
 * Checkpoints (§6) — `signCheckpoint`, `parseCheckpoint`, `verifyCheckpoint(cp, state)`,
 * `checkRollback(witnessed, incoming): void`.
 *
 * Audit (§7) — `deriveAuditKey`, `appendAuditEntry`, `verifyAuditChain(entries, {vaultKeys, vaultId, keyEpoch, witnessed?})`,
 * `auditEntryHash`, `signAuditCheckpoint`, `verifyAuditCheckpoint`.
 *
 * Policy (§8) — `parsePolicy`, `effectiveGrant(localGrant, policy, sensitivity): LocalGrant`.
 *
 * Transport (§9) — `buildProof(args): string`, `decodeProof`, `verifyProof(header, opts): TransportProof`.
 *
 * Devices — `createDeviceKeys`, `randomId`, `signKeyPairFromSeed`, `kxKeyPairFromSecret`.
 *
 * @packageDocumentation
 */
export { AKV_ERROR_CODES, AkvError, isAkvError, type AkvErrorCode } from './errors.js';
export { b64decode, b64decodeLength, b64encode, sha256b64 } from './base64url.js';
export { bytesEqual, concatBytes, randomBytes, sha256, utf8Decode, utf8Encode } from './bytes.js';
export { cjson, cjsonBytes, cjsonParse, parseJson, type JsonObject, type JsonValue } from './canonical-json.js';
export {
  SIGN_CONTEXT,
  deviceIdFromSignPub,
  kid,
  kxKeyPairFromSecret,
  signDetached,
  signKeyPairFromSeed,
  signObject,
  signingInput,
  verifyDetached,
  verifyObject,
  type KeyPair,
  type SignContext,
} from './signing.js';
export {
  MAX_PLAINTEXT_BYTES,
  NONCE_BYTES,
  assertUniqueNonces,
  epochTag,
  openEnvelope,
  parseEpochTag,
  parseEnvelope,
  sealEnvelope,
  type Envelope,
  type SealOptions,
} from './aead.js';
export {
  SENSITIVITIES,
  deriveItemKey,
  itemAad,
  openItem,
  parseItemPayload,
  sealItem,
  type ItemContext,
  type ItemPayload,
  type OpenItemArgs,
  type SealItemArgs,
  type Sensitivity,
  type TombstonePayload,
} from './item.js';
export { parseX25519Wrap, unwrapFromDevice, wrapToDevice, x25519Shared, type WrapRecipient, type WrapToDeviceArgs, type UnwrapFromDeviceArgs, type X25519Wrap } from './wrap-x25519.js';
export {
  ARGON2_BOUNDS,
  ARGON2_DEFAULTS,
  argonNeedsUpgrade,
  derivePasswordKek,
  parsePasswordWrap,
  unwrapWithPassword,
  validateArgonParams,
  wrapWithPassword,
  type ArgonParams,
  type PasswordWrap,
  type WrapWithPasswordArgs,
} from './wrap-password.js';
export {
  decodeRecoveryKey,
  deriveRecoveryKek,
  encodeRecoveryKey,
  generateRecoveryKey,
  parseRecoveryWrap,
  unwrapWithRecoveryKey,
  wrapWithRecoveryKey,
  type RecoveryWrap,
} from './recovery-key.js';
export { sasCode, sasDigest, sasTranscript, type SasInput } from './sas.js';
export {
  DEVICE_KINDS,
  MEMBERSHIP_EVENT_TYPES,
  REMOVE_REASONS,
  ROLES,
  VAULT_KINDS,
  parseDevice,
  parseMembershipEvent,
  type DeviceKind,
  type DeviceRecord,
  type DeviceRemoval,
  type MembershipEvent,
  type MembershipEventType,
  type MembershipState,
  type RemoveReason,
  type Role,
  type UnsignedMembershipEvent,
  type VaultKind,
  type VerifyChainOptions,
} from './membership-types.js';
export { buildGenesisEvent, findDevice, membershipEventHash, nextMembershipEvent, signMembershipEvent, verifyMembershipChain } from './membership-log.js';
export {
  addedDevices,
  validateWrapRecipients,
  verifyDeviceWraps,
  verifyRekeyWraps,
  wrapsDigest,
  type ValidateWrapsOptions,
  type VerifyRekeyWrapsOptions,
} from './wrap-recipients.js';
export {
  BUNDLE_ENVELOPE_KID,
  parseRecoveryBundlePlaintext,
  parseRecoveryBundleWire,
  type BundlePasswordWrap,
  type BundleRecoveryWrap,
  type RecoveryBundlePlaintext,
  type RecoveryBundleWire,
} from './recovery-bundle-parse.js';
export { openRecoveryBundle, sealRecoveryBundle, type OpenRecoveryBundleArgs, type OpenedRecoveryBundle, type SealRecoveryBundleArgs } from './recovery-bundle.js';
export { authorizeRecordWrite, parseRecord, recordDigest, signRecord, verifyRecord, verifyRecordSignature, type SignedRecord, type UnsignedRecord } from './records.js';
export { applyRecord, computeStateDigest, emptyItemState, type ApplyOutcome, type ApplyRecordOptions, type ConflictBranch, type ItemState } from './record-state.js';
export { verifyLoggedRecord } from './removal-fence.js';
export { checkRollback, parseCheckpoint, signCheckpoint, verifyCheckpoint, type Checkpoint, type CheckpointView, type UnsignedCheckpoint } from './checkpoints.js';
export {
  appendAuditEntry,
  auditAad,
  auditEntryHash,
  deriveAuditKey,
  parseAuditCheckpoint,
  signAuditCheckpoint,
  verifyAuditChain,
  verifyAuditCheckpoint,
  type AppendAuditArgs,
  type AuditCheckpoint,
  type AuditHead,
  type VerifyAuditOptions,
  type AuditChainEntry,
} from './audit.js';
export { effectiveGrant, parsePolicy, type LocalGrant, type PortablePolicy } from './policy.js';
export { PROOF_JTI_TTL_MS, PROOF_MAX_SKEW_MS, buildProof, decodeProof, verifyProof, type BuildProofArgs, type TransportProof, type VerifyProofOptions } from './proof.js';
export { createDeviceKeys, randomId, type CreateDeviceArgs, type DeviceKeys } from './device-keys.js';
