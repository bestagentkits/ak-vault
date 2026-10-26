package akv1

// Write intents (spec §3.8): the target of a human-entered write that an MCP
// client requested, encrypted to seal_pub[e] so the Worker never stores the
// secret name. An enrolled browser device opens it with SealSK[e] to show the
// person what they are about to write. The plaintext never carries a value.
//
//	shared = X25519(esk, seal_pub[e])            ; all-zero output refused
//	key    = HKDF(ikm=shared, salt=epk || seal_pub[e], info="akv1/write-intent", L=32)
//	aad    = {ctx:"akv1/write-intent", vault_id, request_id, key_epoch, origin, operation, ts, expires_at}
//	ct     = XC20P(key, n, cjson({name, purpose?, sensitivity?}), aad)

// AlgWriteIntent is the only write-intent algorithm.
const AlgWriteIntent = "x25519-xc20p-seal"

// Write-intent operations (closed set).
const (
	WriteIntentCreate  = "create"
	WriteIntentReplace = "replace"
)

// WriteIntentOperations lists the accepted write-intent operations.
var WriteIntentOperations = []string{WriteIntentCreate, WriteIntentReplace}

// MaxWritePurpose is the maximum UTF-16 code units of the optional purpose.
const MaxWritePurpose = 200

// maxIntentPlaintextBytes bounds an intent plaintext (name and purpose only).
const maxIntentPlaintextBytes = 16384

// WriteIntentTarget is the decrypted intent target. Purpose and Sensitivity
// "" mean absent.
type WriteIntentTarget struct {
	Name        string
	Purpose     string
	Sensitivity string
}

// JSONValue returns the plaintext object, omitting absent optional fields.
func (p WriteIntentTarget) JSONValue() any {
	m := map[string]any{"name": p.Name}
	if p.Purpose != "" {
		m["purpose"] = p.Purpose
	}
	if p.Sensitivity != "" {
		m["sensitivity"] = p.Sensitivity
	}
	return m
}

// WriteIntent is the write-intent wire object
// {"v":1,"alg":"x25519-xc20p-seal","request_id","vault_id","key_epoch","epk","n","ct","origin","operation","ts","expires_at"}.
type WriteIntent struct {
	RequestID string
	VaultID   string
	KeyEpoch  int64
	Epk       string
	N         string
	Ct        string
	Origin    SealedOrigin
	Operation string
	TS        int64 // unix ms
	ExpiresAt int64 // unix ms; the request is refused after this instant
}

// JSONValue returns the wire object.
func (w WriteIntent) JSONValue() any {
	return map[string]any{
		"v": int64(1), "alg": AlgWriteIntent, "request_id": w.RequestID, "vault_id": w.VaultID, "key_epoch": w.KeyEpoch,
		"epk": w.Epk, "n": w.N, "ct": w.Ct, "origin": w.Origin.JSONValue(), "operation": w.Operation,
		"ts": w.TS, "expires_at": w.ExpiresAt,
	}
}

func writeIntentAAD(w WriteIntent) map[string]any {
	return map[string]any{
		"ctx": "akv1/write-intent", "vault_id": w.VaultID, "request_id": w.RequestID, "key_epoch": w.KeyEpoch,
		"origin": w.Origin.JSONValue(), "operation": w.Operation, "ts": w.TS, "expires_at": w.ExpiresAt,
	}
}

func deriveWriteIntentKey(shared, epk, sealPub []byte) []byte {
	return hkdf32(shared, concatBytes(epk, sealPub), []byte("akv1/write-intent"))
}

// ParseWriteIntentTarget validates a decrypted (or to-be-sealed) intent target.
func ParseWriteIntentTarget(v any) (WriteIntentTarget, error) {
	const what = "write intent"
	obj, err := asObject(v, what)
	if err != nil {
		return WriteIntentTarget{}, err
	}
	if err := exactKeys(obj, []string{"name"}, what, "purpose", "sensitivity"); err != nil {
		return WriteIntentTarget{}, err
	}
	var p WriteIntentTarget
	if p.Name, err = asString(obj["name"], what+".name", MaxItemNameLength, 1); err != nil {
		return WriteIntentTarget{}, err
	}
	if s, ok := obj["purpose"]; ok {
		if p.Purpose, err = asString(s, what+".purpose", MaxWritePurpose, 1); err != nil {
			return WriteIntentTarget{}, err
		}
	}
	if s, ok := obj["sensitivity"]; ok {
		if p.Sensitivity, err = asEnum(s, sensitivities, what+".sensitivity"); err != nil {
			return WriteIntentTarget{}, err
		}
	}
	return p, nil
}

// ParseWriteIntent structurally validates an untrusted write intent: an
// unknown v or alg is unsupported_version; keys, lengths, origin, operation
// and expires_at not after ts are bad_request.
func ParseWriteIntent(v any) (WriteIntent, error) {
	const what = "write intent"
	obj, err := asObject(v, what)
	if err != nil {
		return WriteIntent{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return WriteIntent{}, err
	}
	if obj["alg"] != AlgWriteIntent {
		return WriteIntent{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "request_id", "vault_id", "key_epoch", "epk", "n", "ct", "origin", "operation", "ts", "expires_at"}, what); err != nil {
		return WriteIntent{}, err
	}
	var w WriteIntent
	if w.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
		return WriteIntent{}, err
	}
	if ct, _ := B64Decode(w.Ct); len(ct) < TagBytes || len(ct) > maxIntentPlaintextBytes+TagBytes {
		return WriteIntent{}, badRequest("%s.ct length out of range", what)
	}
	if w.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return WriteIntent{}, err
	}
	if w.ExpiresAt, err = asUint(obj["expires_at"], what+".expires_at"); err != nil {
		return WriteIntent{}, err
	}
	if w.ExpiresAt <= w.TS {
		return WriteIntent{}, badRequest("%s.expires_at must be after ts", what)
	}
	if w.RequestID, err = asID(obj["request_id"], what+".request_id"); err != nil {
		return WriteIntent{}, err
	}
	if w.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return WriteIntent{}, err
	}
	if w.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return WriteIntent{}, err
	}
	if w.Epk, err = asB64(obj["epk"], what+".epk", KeyBytes); err != nil {
		return WriteIntent{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return WriteIntent{}, err
	}
	if w.Origin, err = parseSealedOrigin(obj["origin"], what+".origin"); err != nil {
		return WriteIntent{}, err
	}
	if w.Operation, err = asEnum(obj["operation"], WriteIntentOperations, what+".operation"); err != nil {
		return WriteIntent{}, err
	}
	return w, nil
}

// SealWriteIntentArgs configures SealWriteIntent. RequestID is empty in
// production (a fresh random ID); test vectors inject it. The ephemeral secret
// and nonce are unexported so only this package's vector tests can fix them:
// reusing an ephemeral secret reuses the (key, nonce) pair.
type SealWriteIntentArgs struct {
	SealPub   []byte // seal_pub[KeyEpoch] from a verified seal-key document
	VaultID   string
	KeyEpoch  int64
	RequestID string
	Origin    SealedOrigin
	Operation string
	TS        int64 // unix ms
	ExpiresAt int64 // unix ms; after TS
	Target    WriteIntentTarget

	ephemeralSecret []byte
	nonce           []byte
}

// SealWriteIntent encrypts a write-intent target to seal_pub[e] after the
// same checks OpenWriteIntent applies.
func SealWriteIntent(args SealWriteIntentArgs) (WriteIntent, error) {
	if len(args.SealPub) != KeyBytes {
		return WriteIntent{}, badRequest("seal_pub must be 32 bytes")
	}
	target, err := ParseWriteIntentTarget(args.Target.JSONValue())
	if err != nil {
		return WriteIntent{}, err
	}
	ptBytes, err := CJSON(target)
	if err != nil {
		return WriteIntent{}, err
	}
	// Escaping can inflate a valid target past what ParseWriteIntent accepts;
	// refuse here rather than emit a wire no device can open.
	if len(ptBytes) > maxIntentPlaintextBytes {
		return WriteIntent{}, badRequest("write intent plaintext exceeds %d bytes", maxIntentPlaintextBytes)
	}
	requestID := args.RequestID
	if requestID == "" {
		requestID = RandomID()
	}
	esk := args.ephemeralSecret
	if esk == nil {
		esk = randomBytes(KeyBytes)
	}
	nonce := args.nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	epk, err := KxPublicKey(esk)
	if err != nil {
		return WriteIntent{}, err
	}
	// Validate the wire fields with a placeholder ciphertext before encrypting.
	w := WriteIntent{
		RequestID: requestID, VaultID: args.VaultID, KeyEpoch: args.KeyEpoch, Epk: B64Encode(epk), N: B64Encode(nonce),
		Ct: B64Encode(make([]byte, TagBytes)), Origin: args.Origin, Operation: args.Operation, TS: args.TS, ExpiresAt: args.ExpiresAt,
	}
	if w, err = ParseWriteIntent(w); err != nil {
		return WriteIntent{}, err
	}
	shared, err := X25519Shared(esk, args.SealPub)
	if err != nil {
		return WriteIntent{}, err
	}
	ct, err := XC20PSeal(deriveWriteIntentKey(shared, epk, args.SealPub), nonce, ptBytes, writeIntentAAD(w))
	if err != nil {
		return WriteIntent{}, err
	}
	w.Ct = B64Encode(ct)
	return w, nil
}

// OpenedWriteIntent is the authenticated result of OpenWriteIntent. Its fields
// are unexported so only OpenWriteIntent produces one.
type OpenedWriteIntent struct {
	wire   WriteIntent
	target WriteIntentTarget
}

// Wire returns the authenticated write intent.
func (o OpenedWriteIntent) Wire() WriteIntent { return o.wire }

// Target returns the decrypted target.
func (o OpenedWriteIntent) Target() WriteIntentTarget { return o.target }

// OpenWriteIntent parses and decrypts an untrusted write intent with
// SealSK[e], in the order of spec §3.8: wire shape (unsupported_version /
// bad_request), vault_id ≠ vaultID (bad_request), all-zero shared secret
// (bad_request), AEAD failure (decrypt_failed), target not canonical or
// invalid (bad_request).
func OpenWriteIntent(sealSecret []byte, wire any, vaultID string) (OpenedWriteIntent, error) {
	w, err := ParseWriteIntent(wire)
	if err != nil {
		return OpenedWriteIntent{}, err
	}
	if w.VaultID != vaultID {
		return OpenedWriteIntent{}, badRequest("write intent belongs to another vault")
	}
	sealPub, err := KxPublicKey(sealSecret)
	if err != nil {
		return OpenedWriteIntent{}, err
	}
	epk, _ := B64Decode(w.Epk)
	shared, err := X25519Shared(sealSecret, epk)
	if err != nil {
		return OpenedWriteIntent{}, err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	ptBytes, err := XC20POpen(deriveWriteIntentKey(shared, epk, sealPub), nonce, ct, writeIntentAAD(w))
	if err != nil {
		return OpenedWriteIntent{}, err
	}
	v, err := CJSONParse(ptBytes)
	if err != nil {
		return OpenedWriteIntent{}, err
	}
	target, err := ParseWriteIntentTarget(v)
	if err != nil {
		return OpenedWriteIntent{}, err
	}
	return OpenedWriteIntent{wire: w, target: target}, nil
}
