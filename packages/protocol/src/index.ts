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
 * - `verifyChangeLog(entries, state, {from?, complete?, keptHeads?}): {head, records}` replays change-log
 *   entries, chains `nextLogHead`, checks each removal's signed `log_head` and every head the client kept;
 *   `LOG_START`, `parseLogPosition`.
 * - `applyRecord(itemState | undefined, record, {conflictId?, isReplay?}): {state, outcome}` (pure CAS model),
 *   `emptyItemState`, `computeStateDigest(items)`.
 *
 * Checkpoints (§6) — `signCheckpoint`, `parseCheckpoint`, `verifyCheckpoint(cp, state)`,
 * `checkRollback(witnessed, incoming): void` (checkpoint comparison only; pair it with `verifyChangeLog`
 * and the head kept at the witnessed position to refuse a restored-then-regrown log).
 *
 * Audit (§7) — `deriveAuditKey`, `appendAuditEntry`, `verifyAuditChain(entries, {vaultKeys, vaultId, keyEpoch, witnessed?})`,
 * `auditEntryHash`, `signAuditCheckpoint`, `verifyAuditCheckpoint`.
 *
 * Policy (§8) — `parsePolicy`, `effectiveGrant(localGrant, policy, sensitivity): LocalGrant`;
 * `resolveItemPolicy(targetItemId, items): {policy, sensitivity}` combines the policy items that
 * govern an item (binding by `meta.item_ids`), `parsePolicyBinding`, `parsePolicyItem`, `isPolicyPayload`.
 *
 * Transport (§9) — `buildProof(args): string`, `decodeProof`, `verifyProof(header, opts): TransportProof`.
 *
 * Devices — `createDeviceKeys`, `randomId`, `signKeyPairFromSeed`, `kxKeyPairFromSecret`.
 * External key stores (WebCrypto) — `DeviceSigner`, `DeviceKx`, `signObjectAsync`, `signRecordAsync`,
 * `buildProofAsync`, `unwrapFromDeviceAsync` (byte-identical to the synchronous functions).
 *
 * Remote access
 * - Seal key (§3.6): `deriveSealKeyPair(vk, vaultId, keyEpoch)`, `buildSealKeyDoc`, `signSealKeyDoc`,
 *   `parseSealKeyDoc`, `verifySealKeyDoc(doc, chain, {vaultId, vk?, trustedAnchor?, witnessedCheckpoint?})`, `checkSealKeyDocReplace(stored, incoming)`.
 * - Sealed operations (§3.6): `sealOp(sealPub, args)`, `openSealedOp(sealSecret, wire, {vaultId})`,
 *   `checkSealedDrain(wire, {account, now, sealedTtlS, seen})`, `parseSealedOp`,
 *   `parseSealedOperation`, `parseSealedOrigin`.
 * - Name tags (§3.7): `nameIndexKey(vk, vaultId, keyEpoch)`, `nameTag(indexKey, name)` (NFC).
 * - Enrollment codes (§3.8): `encodeJoinCode`, `parseJoinCode`, `encodeOfferCode`, `parseOfferCode`, `isCanonicalOrigin`.
 * - Profile (§5.1): `validateProfile`, `checkProfileProvenance(prev, next, record, {selfDeviceId?, prevOrigins?})`,
 *   `buildNextProfile`, `carryForwardMeta`, `parseProfileValue`, `asProfileText`.
 * - Relay (§9.7): `parseRelayFrame(data, {maxBytes})`, `parseRelayFrameObject`, `signHello`, `verifyHello`,
 *   `signResult`, `verifyResult`, `parseToolArgs(tool, args)`, `parseToolResult(tool, result)`, `TOOL_SCOPE`.
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
export { openWrapWithShared, parseX25519Wrap, unwrapFromDevice, wrapToDevice, x25519Shared, type WrapRecipient, type WrapToDeviceArgs, type UnwrapFromDeviceArgs, type X25519Wrap } from './wrap-x25519.js';
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
export {
  LOG_START,
  MAX_CHANGE_LOG_ENTRIES,
  nextLogHead,
  parseLogPosition,
  verifyChangeLog,
  type ChangeLogCursor,
  type VerifiedChangeLog,
  type VerifyChangeLogOptions,
} from './change-log.js';
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
export {
  MAX_POLICY_ITEM_IDS,
  MAX_RESOLVE_BRANCHES,
  MAX_RESOLVE_ITEMS,
  POLICY_ITEM_KIND,
  isPolicyPayload,
  parsePolicyBinding,
  parsePolicyItem,
  resolveItemPolicy,
  type PolicyItem,
  type PolicyResolutionEntry,
  type PolicyResolutionItem,
  type PolicyRules,
  type ResolvedItemPolicy,
} from './policy-binding.js';
export { PROOF_JTI_TTL_MS, PROOF_MAX_SKEW_MS, buildProof, decodeProof, encodeProofHeader, proofObject, verifyProof, type BuildProofArgs, type TransportProof, type VerifyProofOptions } from './proof.js';
export { createDeviceKeys, randomId, type CreateDeviceArgs, type DeviceKeys } from './device-keys.js';
export {
  buildProofAsync,
  signObjectAsync,
  signRecordAsync,
  unwrapFromDeviceAsync,
  type DeviceKx,
  type DeviceSigner,
} from './device-signer.js';
export {
  buildSealKeyDoc,
  checkSealKeyDocReplace,
  deriveSealKeyPair,
  parseSealKeyDoc,
  signSealKeyDoc,
  verifySealKeyDoc,
  type SealKeyDoc,
  type UnsignedSealKeyDoc,
  type VerifySealKeyDocOptions,
} from './seal-key.js';
export {
  MAX_ITEM_NAME,
  MAX_ITEM_VALUE,
  SEALED_MAX_FUTURE_MS,
  SEALED_OPS,
  SEALED_OP_ALG,
  SEALED_ORIGIN_KINDS,
  checkSealedDrain,
  openSealedOp,
  parseSealedOp,
  parseSealedOperation,
  parseSealedOrigin,
  sealOp,
  type OpenedSealedOp,
  type SealOpArgs,
  type SealedDrainContext,
  type SealedOpWire,
  type SealedOperation,
  type SealedOrigin,
} from './sealed-op.js';
export { NAME_TAG_BYTES, nameIndexKey, nameTag } from './name-tag.js';
export {
  JOIN_CODE_CONTEXT,
  JOIN_CODE_PREFIX,
  MAX_DEVICE_LABEL_BYTES,
  MAX_ENROLL_CODE_BYTES,
  OFFER_CODE_CONTEXT,
  OFFER_CODE_PREFIX,
  encodeJoinCode,
  encodeOfferCode,
  isCanonicalOrigin,
  parseJoinCode,
  parseOfferCode,
  type JoinCode,
  type OfferCode,
} from './enroll-codes.js';
export {
  PROFILE_KEYS,
  PROFILE_KINDS,
  PROFILE_LIST_KEYS,
  PROFILE_SOURCES,
  PROFILE_TEXT_KEYS,
  asProfileText,
  buildNextProfile,
  carryForwardMeta,
  checkProfileProvenance,
  parseProfileValue,
  validateProfile,
  type CheckedProfile,
  type Profile,
  type ProfileField,
  type ProfileKey,
  type ProfileOrigin,
  type ProfileRecordContext,
  type ProfileSource,
} from './profile.js';
export {
  MCP_SCOPES,
  RELAY_ERROR_CODES,
  RELAY_FRAME_TYPES,
  RELAY_TOOLS,
  TOOL_SCOPE,
  parseRelayFrame,
  parseRelayFrameObject,
  signHello,
  signResult,
  verifyHello,
  verifyResult,
  type CallFrame,
  type HelloFrame,
  type McpScope,
  type ReadyFrame,
  type ReauthFrame,
  type RelayCaller,
  type RelayErrorCode,
  type RelayFrame,
  type RelayFrameType,
  type RelayTool,
  type ResultFrame,
  type UnsignedResult,
} from './relay-frames.js';
export { ENTRY_ORIGINS, SEARCH_FIELDS, parseToolArgs, parseToolResult } from './relay-tools.js';
