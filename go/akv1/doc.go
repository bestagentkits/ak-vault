// Package akv1 is the Go implementation of the ak-vault protocol v1 ("akv1").
//
// The normative wire specification is docs/protocol/v1/spec.md in the
// ak-vault repository; the TypeScript package packages/protocol is the
// reference implementation. This package reproduces every deterministic
// vector in protocol/v1/vectors byte for byte, including the error code of
// every rejection path. It depends only on the Go standard library and
// golang.org/x/crypto (XChaCha20-Poly1305, HKDF-SHA256, Argon2id); Ed25519,
// X25519 and SHA-256 come from the standard library. There is no custom
// cryptography.
//
// # Errors
//
// Every failure is an *Error whose Code is one of the stable Code*
// constants (spec §10 plus CodeDecryptFailed, §11). Use CodeOf(err) or
// errors.As. Messages never contain secret values, names, tokens or bodies.
// Verifiers fail closed: unknown versions, algorithms and event types are
// CodeUnsupportedVersion.
//
// # Value model
//
// Untrusted wire objects enter as generic JSON values: nil, bool, int64,
// string, []any and map[string]any, as produced by ParseJSON (strict,
// order-free) or CJSONParse (input must already be canonical). Parse*/Verify*
// functions validate such values and return typed structs. Typed structs
// implement Valuer, so CJSON(x) yields their canonical wire bytes.
//
// # API by area
//
// Encodings (§2): B64Encode, B64Decode (strict), SHA256B64, CJSON,
// ParseJSON, CJSONParse, SigningInput, Kid, DeviceIDFromSignPub,
// SignDetached, VerifyDetached, VerifyObject, CreateDeviceKeys.
//
// Encryption (§3): SealEnvelope, OpenEnvelope, ParseEnvelope,
// AssertUniqueNonces, EpochTag; items: DeriveItemKey, ItemAAD, SealItem,
// OpenItem, ParseItemPayload; device wraps: WrapToDevice, UnwrapFromDevice,
// X25519Shared; password wraps: WrapWithPassword, UnwrapWithPassword,
// DerivePasswordKEK, ValidateArgonParams; recovery key: EncodeRecoveryKey,
// DecodeRecoveryKey, WrapWithRecoveryKey, UnwrapWithRecoveryKey; recovery
// bundle: SealRecoveryBundle, OpenRecoveryBundle; SAS: SASTranscript,
// SASCode, SASDigest.
//
// Passwords: callers pass raw user input; DerivePasswordKEK normalizes it to
// Unicode NFC (golang.org/x/text/unicode/norm) before Argon2id, matching the
// TypeScript reference. Passwords that are not valid UTF-8 are CodeBadRequest.
//
// Membership (§4): VerifyMembershipChain, BuildGenesisEvent,
// NextMembershipEvent, MembershipEventHash, ValidateWrapRecipients,
// WrapsDigest, VerifyRekeyWraps, AddedDevices, VerifyDeviceWraps (signed
// wrap sets of device-adding events); MembershipState.Removals lists each
// removal (DeviceRemoval) with its signed log_fence and log_head, and
// MembershipState.RoleChanges each role_set per device (RoleChange) with its
// signed log_fence and log_head.
//
// Records (§5): SignRecord, ParseRecord, VerifyRecord, AuthorizeRecordWrite,
// RecordDigest, ApplyRecord (pure CAS / conflict / tombstone model),
// ComputeStateDigest, VerifyLoggedRecord (records read from the change log,
// checked against each removal fence of their author and the role and kind
// their author had at that position), VerifyChangeLog, SignedFences,
// NextLogHead and ParseLogPosition (change-log replay: the head chain checked
// against each signed fence's log_head).
//
// Checkpoints (§6): SignCheckpoint, VerifyCheckpoint, CheckRollback.
//
// Audit (§7): DeriveAuditKey (per key epoch), AppendAuditEntry,
// VerifyAuditChain, SignAuditCheckpoint, VerifyAuditCheckpoint; ParseEpochTag
// reads the e<key_epoch> envelope kid.
//
// Policy (§8): ParsePolicy, EffectiveGrant.
//
// Transport (§9): BuildProof, DecodeProof, VerifyProof.
//
// Remote access: seal key and sealed operations (§3.6) DeriveSealKeyPair,
// BuildSealKeyDoc, ParseSealKeyDoc, VerifySealKeyDoc (against the membership chain),
// CheckSealKeyDocReplace, SealOp, OpenSealedOp (an OpenedSealedOp),
// CheckSealedDrain (on that OpenedSealedOp), ParseSealedOp; name tags (§3.7) NameIndexKey, NameTag, NewItemPutBody;
// enrollment codes (§3.8) EncodeJoinCode, ParseJoinCode, EncodeOfferCode,
// ParseOfferCode, ValidateVaultOrigin; profiles (§5.1) ValidateProfile,
// CheckProfileProvenance, CarryForwardMeta; relay (§9.7) ParseRelayFrame,
// SignHello, VerifyHello (key, signature, ±60 s window), SignResult,
// VerifyResult, ValidateToolArgs, ValidateToolResult, ToolScope; session
// kinds SessionKind* (SessionKindBrowser) and the MCP tool-error codes
// CodeNoDeviceOnline, CodeDeviceTimeout, CodeSealedQueueFull.
//
// Randomness: when a nonce, salt, ephemeral key or ID argument is nil/empty,
// it is drawn from crypto/rand. Injecting fixed values is for test vectors only.
package akv1
