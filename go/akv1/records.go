package akv1

// MaxResolves bounds the conflict branches a record may resolve.
const MaxResolves = 256

// SignedRecord is a signed item record (spec §5).
type SignedRecord struct {
	VaultID      string
	ItemID       string
	BaseRevision int64
	KeyEpoch     int64
	Tombstone    bool
	Author       string
	TS           int64
	Resolves     []string
	Env          Envelope
	Sig          string // empty for an unsigned record
}

// JSONValue returns the wire object ("sig" omitted when empty).
func (r SignedRecord) JSONValue() any {
	m := map[string]any{
		"v": int64(1), "vault_id": r.VaultID, "item_id": r.ItemID, "base_revision": r.BaseRevision,
		"key_epoch": r.KeyEpoch, "tombstone": r.Tombstone, "author": r.Author, "ts": r.TS,
		"resolves": stringsToAny(r.Resolves), "env": r.Env.JSONValue(),
	}
	if r.Sig != "" {
		m["sig"] = r.Sig
	}
	return m
}

// ItemContext returns the AEAD context of the record's payload.
func (r SignedRecord) ItemContext() ItemContext {
	return ItemContext{VaultID: r.VaultID, ItemID: r.ItemID, BaseRevision: r.BaseRevision, KeyEpoch: r.KeyEpoch, Author: r.Author, Tombstone: r.Tombstone}
}

// SignRecord signs r (its Sig is replaced) with an Ed25519 seed.
func SignRecord(r SignedRecord, seed []byte) (SignedRecord, error) {
	r.Sig = ""
	sig, err := SignDetached(ContextRecord, r, seed)
	if err != nil {
		return SignedRecord{}, err
	}
	r.Sig = sig
	return r, nil
}

// RecordDigest returns b64(sha256(record signing input)), used for state
// digests, heads and replay detection.
func RecordDigest(r SignedRecord) (string, error) {
	in, err := SigningInput(ContextRecord, r)
	if err != nil {
		return "", err
	}
	return SHA256B64(in), nil
}

// ParseRecord structurally validates an untrusted record; env.kid must be the
// epoch tag "e<key_epoch>".
func ParseRecord(v any) (SignedRecord, error) {
	const what = "record"
	obj, err := asObject(v, what)
	if err != nil {
		return SignedRecord{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return SignedRecord{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "item_id", "base_revision", "key_epoch", "tombstone", "author", "ts", "resolves", "env", "sig"}, what); err != nil {
		return SignedRecord{}, err
	}
	var r SignedRecord
	if r.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return SignedRecord{}, err
	}
	if r.ItemID, err = asID(obj["item_id"], what+".item_id"); err != nil {
		return SignedRecord{}, err
	}
	if r.BaseRevision, err = asUint(obj["base_revision"], what+".base_revision"); err != nil {
		return SignedRecord{}, err
	}
	if r.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return SignedRecord{}, err
	}
	if r.Tombstone, err = asBool(obj["tombstone"], what+".tombstone"); err != nil {
		return SignedRecord{}, err
	}
	if r.Author, err = asID(obj["author"], what+".author"); err != nil {
		return SignedRecord{}, err
	}
	if r.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return SignedRecord{}, err
	}
	if r.Resolves, err = asIDList(obj["resolves"], what+".resolves", MaxResolves); err != nil {
		return SignedRecord{}, err
	}
	if r.Env, err = parseEnvelopeAs(obj["env"], what+".env"); err != nil {
		return SignedRecord{}, err
	}
	if r.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return SignedRecord{}, err
	}
	tag, err := EpochTag(r.KeyEpoch)
	if err != nil {
		return SignedRecord{}, err
	}
	if r.Env.Kid != tag {
		return SignedRecord{}, badRequest("%s.env.kid must be the epoch tag", what)
	}
	return r, nil
}

// VerifyRecordSignature parses a record and verifies it against an explicit
// b64 signing key (e.g. a historical author).
func VerifyRecordSignature(v any, signPub string) (SignedRecord, error) {
	r, err := ParseRecord(v)
	if err != nil {
		return SignedRecord{}, err
	}
	if err := VerifyObject(ContextRecord, r, signPub); err != nil {
		return SignedRecord{}, err
	}
	return r, nil
}

// VerifyRecord parses and verifies a record against verified membership: same
// vault (bad_request), author is a current device (forbidden), valid
// signature (invalid_signature).
func VerifyRecord(v any, state MembershipState) (SignedRecord, error) {
	r, err := ParseRecord(v)
	if err != nil {
		return SignedRecord{}, err
	}
	if r.VaultID != state.VaultID {
		return SignedRecord{}, badRequest("record belongs to another vault")
	}
	d, ok := state.FindDevice(r.Author)
	if !ok {
		return SignedRecord{}, newErr(CodeForbidden, "record author is not a current device")
	}
	if err := VerifyObject(ContextRecord, r, d.SignPub); err != nil {
		return SignedRecord{}, err
	}
	return r, nil
}

// AuthorizeRecordWrite is the write-side authorization shared by server and
// clients: the author must be a human owner/editor device (forbidden), the
// vault must not be rekey_required (rekey_required), and key_epoch must equal
// the current key epoch (bad_request).
func AuthorizeRecordWrite(state MembershipState, r SignedRecord) error {
	d, ok := state.FindDevice(r.Author)
	if !ok {
		return newErr(CodeForbidden, "record author is not a current device")
	}
	if d.Kind != KindHuman || (d.Role != RoleOwner && d.Role != RoleEditor) {
		return newErr(CodeForbidden, "author may not write")
	}
	if state.RekeyRequired {
		return newErr(CodeRekeyRequired, "writes are refused until rekey")
	}
	if r.KeyEpoch != state.KeyEpoch {
		return badRequest("record key_epoch is not the current key epoch")
	}
	return nil
}
