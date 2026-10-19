package akv1

// Seal key (spec §3.6): a per-epoch X25519 key pair every holder of VK[e]
// derives, whose public half the owner publishes in a signed seal-key
// document so the Worker can seal remote MCP writes without any vault key.

// ContextSealKey is the signing context of seal-key documents.
const ContextSealKey = "akv1/seal-key"

// SealKeyPair is the derived seal key of one key epoch. Secret is used
// unmodified as an X25519 private key (X25519 clamps it itself).
type SealKeyPair struct {
	Secret []byte
	Public []byte
}

// DeriveSealKeyPair computes
// SealSK[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id), info=utf8("akv1/seal-key\n")||cjson({"key_epoch":e}), L=32)
// and seal_pub[e] = X25519(SealSK[e], 9).
func DeriveSealKeyPair(vk []byte, vaultID string, keyEpoch int64) (SealKeyPair, error) {
	secret, err := deriveEpochKey(vk, vaultID, keyEpoch, "akv1/seal-key\n")
	if err != nil {
		return SealKeyPair{}, err
	}
	pub, err := KxPublicKey(secret)
	if err != nil {
		return SealKeyPair{}, err
	}
	return SealKeyPair{Secret: secret, Public: pub}, nil
}

// deriveEpochKey is HKDF(ikm=vk, salt=b64decode(vault_id), info=utf8(label)||cjson({"key_epoch":e}), L=32),
// the shape shared by the seal key and the name index key.
func deriveEpochKey(vk []byte, vaultID string, keyEpoch int64, label string) ([]byte, error) {
	if len(vk) != KeyBytes {
		return nil, badRequest("vault key must be 32 bytes")
	}
	if _, err := asInt(keyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return nil, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return nil, err
	}
	salt, _ := B64Decode(vaultID)
	info, err := CJSON(map[string]any{"key_epoch": keyEpoch})
	if err != nil {
		return nil, err
	}
	return hkdf32(vk, salt, concatBytes([]byte(label), info)), nil
}

// SealKeyDoc is the owner-signed seal-key document
// {"v":1,"vault_id","key_epoch","membership_seq","seal_pub","author","ts","sig"}.
type SealKeyDoc struct {
	VaultID       string
	KeyEpoch      int64
	MembershipSeq int64
	SealPub       string // b64 32-byte X25519 public key
	Author        string
	TS            int64
	Sig           string // empty for an unsigned document
}

// JSONValue returns the wire object ("sig" omitted when empty).
func (d SealKeyDoc) JSONValue() any {
	m := map[string]any{
		"v": int64(1), "vault_id": d.VaultID, "key_epoch": d.KeyEpoch, "membership_seq": d.MembershipSeq,
		"seal_pub": d.SealPub, "author": d.Author, "ts": d.TS,
	}
	if d.Sig != "" {
		m["sig"] = d.Sig
	}
	return m
}

// BuildSealKeyDocArgs configures BuildSealKeyDoc.
type BuildSealKeyDocArgs struct {
	VK            []byte // VK[KeyEpoch]
	VaultID       string
	KeyEpoch      int64
	MembershipSeq int64
	Author        string // the signing owner device
	TS            int64
	SignSeed      []byte // the author's Ed25519 seed
}

// BuildSealKeyDoc derives seal_pub[e] from VK[e] and signs the document.
func BuildSealKeyDoc(args BuildSealKeyDocArgs) (SealKeyDoc, error) {
	pair, err := DeriveSealKeyPair(args.VK, args.VaultID, args.KeyEpoch)
	if err != nil {
		return SealKeyDoc{}, err
	}
	doc := SealKeyDoc{
		VaultID: args.VaultID, KeyEpoch: args.KeyEpoch, MembershipSeq: args.MembershipSeq,
		SealPub: B64Encode(pair.Public), Author: args.Author, TS: args.TS,
	}
	if doc.Sig, err = SignDetached(ContextSealKey, doc, args.SignSeed); err != nil {
		return SealKeyDoc{}, err
	}
	return ParseSealKeyDoc(doc)
}

// ParseSealKeyDoc structurally validates an untrusted seal-key document
// (verifySealKeyDoc step 1).
func ParseSealKeyDoc(v any) (SealKeyDoc, error) {
	const what = "seal_key"
	obj, err := asObject(v, what)
	if err != nil {
		return SealKeyDoc{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return SealKeyDoc{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "key_epoch", "membership_seq", "seal_pub", "author", "ts", "sig"}, what); err != nil {
		return SealKeyDoc{}, err
	}
	var d SealKeyDoc
	if d.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return SealKeyDoc{}, err
	}
	if d.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return SealKeyDoc{}, err
	}
	if d.MembershipSeq, err = asUint(obj["membership_seq"], what+".membership_seq"); err != nil {
		return SealKeyDoc{}, err
	}
	if d.SealPub, err = asB64(obj["seal_pub"], what+".seal_pub", KeyBytes); err != nil {
		return SealKeyDoc{}, err
	}
	if d.Author, err = asID(obj["author"], what+".author"); err != nil {
		return SealKeyDoc{}, err
	}
	if d.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return SealKeyDoc{}, err
	}
	if d.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return SealKeyDoc{}, err
	}
	return d, nil
}

// VerifySealKeyDocOptions configures VerifySealKeyDoc.
type VerifySealKeyDocOptions struct {
	// Chain is passed to VerifyMembershipChain for the full chain (pinned
	// anchor, witnessed checkpoint, expected vault).
	Chain VerifyChainOptions
	// VK is VK[doc.key_epoch] when the verifier holds it (nil otherwise). A
	// device that holds the key MUST pass it (step 6).
	VK []byte
}

// VerifySealKeyDoc runs verifySealKeyDoc (spec §3.6), the first failure being
// the result. events is the verifier's membership chain; its head is the
// verified state, which must be at or after doc.membership_seq, and its
// prefix up to membership_seq gives the key epoch and the devices current
// when the document was signed.
//
//  1. shape (unsupported_version / bad_request);
//  2. vault_id is the chain's vault (bad_request);
//  3. membership_seq ≤ head seq and key_epoch equals the chain's key epoch at
//     membership_seq (bad_request);
//  4. author is a human owner device current at membership_seq; never the
//     recovery signing key (forbidden);
//  5. signature under the author's sign_pub (invalid_signature);
//  6. when opts.VK is set, seal_pub equals seal_pub[key_epoch] derived from
//     it (forbidden).
func VerifySealKeyDoc(doc any, events []any, opts VerifySealKeyDocOptions) (SealKeyDoc, error) {
	d, err := ParseSealKeyDoc(doc)
	if err != nil {
		return SealKeyDoc{}, err
	}
	head, err := VerifyMembershipChain(events, opts.Chain)
	if err != nil {
		return SealKeyDoc{}, err
	}
	if d.VaultID != head.VaultID {
		return SealKeyDoc{}, badRequest("seal_key belongs to another vault")
	}
	if d.MembershipSeq > head.Seq {
		return SealKeyDoc{}, badRequest("seal_key.membership_seq is beyond the verified membership head")
	}
	at := head
	if d.MembershipSeq < head.Seq {
		// The prefix of a verified chain is itself a verified chain.
		if at, err = VerifyMembershipChain(events[:d.MembershipSeq+1], VerifyChainOptions{TrustedAnchor: opts.Chain.TrustedAnchor, VaultID: opts.Chain.VaultID}); err != nil {
			return SealKeyDoc{}, err
		}
	}
	if d.KeyEpoch != at.KeyEpoch {
		return SealKeyDoc{}, badRequest("seal_key.key_epoch is not the key epoch at membership_seq")
	}
	author, ok := at.FindDevice(d.Author)
	if !ok || author.Role != RoleOwner || author.Kind != KindHuman || d.Author == at.RecoveryAuthor {
		return SealKeyDoc{}, newErr(CodeForbidden, "seal_key author is not a human owner device at membership_seq")
	}
	if err := VerifyObject(ContextSealKey, d, author.SignPub); err != nil {
		return SealKeyDoc{}, err
	}
	if opts.VK != nil {
		pair, err := DeriveSealKeyPair(opts.VK, d.VaultID, d.KeyEpoch)
		if err != nil {
			return SealKeyDoc{}, err
		}
		if B64Encode(pair.Public) != d.SealPub {
			return SealKeyDoc{}, newErr(CodeForbidden, "seal_key.seal_pub does not match the vault key")
		}
	}
	return d, nil
}
