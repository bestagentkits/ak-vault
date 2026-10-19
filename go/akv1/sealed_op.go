package akv1

// Sealed operations (spec §3.6): a remote MCP write the Worker encrypts to
// seal_pub[e] while no device is online. An opted-in device opens it with
// SealSK[e] and writes a normal signed record.

// AlgSealedOp is the only sealed-operation algorithm.
const AlgSealedOp = "x25519-xc20p-seal"

// Sealed-operation plaintext ops (closed set) and the origin kind.
const (
	SealedOpSet    = "set"
	SealedOpDelete = "delete"

	SealedOriginMCP = "mcp"
)

// Item payload limits in UTF-16 code units (spec §3.6, the limits
// ParseItemPayload enforces).
const (
	MaxItemNameLength  = 4096
	MaxItemValueLength = 65536
)

const (
	maxClientIDBytes = 256
	maxGrantIDBytes  = 64
)

// SealedOrigin says who asked the Worker for the operation. A device cannot
// verify it beyond its binding into the AAD.
type SealedOrigin struct {
	Kind     string // SealedOriginMCP
	Account  string // the MCP token's sub
	ClientID string
	GrantID  string
}

// JSONValue returns the wire object.
func (o SealedOrigin) JSONValue() any {
	return map[string]any{"kind": o.Kind, "account": o.Account, "client_id": o.ClientID, "grant_id": o.GrantID}
}

// SealedOp is the sealed-operation wire object
// {"v":1,"alg":"x25519-xc20p-seal","sealed_id","vault_id","key_epoch","epk","n","ct","origin","ts"}.
type SealedOp struct {
	SealedID string
	VaultID  string
	KeyEpoch int64
	Epk      string
	N        string
	Ct       string
	Origin   SealedOrigin
	TS       int64
}

// JSONValue returns the wire object.
func (s SealedOp) JSONValue() any {
	return map[string]any{
		"v": int64(1), "alg": AlgSealedOp, "sealed_id": s.SealedID, "vault_id": s.VaultID, "key_epoch": s.KeyEpoch,
		"epk": s.Epk, "n": s.N, "ct": s.Ct, "origin": s.Origin.JSONValue(), "ts": s.TS,
	}
}

// SealedOpPlaintext is the decrypted operation. Value and Sensitivity are
// meaningful only for SealedOpSet; Sensitivity "" means absent.
type SealedOpPlaintext struct {
	Op          string
	Name        string
	Value       string
	Sensitivity string
}

// JSONValue returns the plaintext object.
func (p SealedOpPlaintext) JSONValue() any {
	if p.Op != SealedOpSet {
		return map[string]any{"op": p.Op, "name": p.Name}
	}
	m := map[string]any{"op": p.Op, "name": p.Name, "value": p.Value}
	if p.Sensitivity != "" {
		m["sensitivity"] = p.Sensitivity
	}
	return m
}

func sealedOpAAD(s SealedOp) map[string]any {
	return map[string]any{
		"ctx": "akv1/sealed-op", "vault_id": s.VaultID, "sealed_id": s.SealedID, "key_epoch": s.KeyEpoch,
		"origin": s.Origin.JSONValue(), "ts": s.TS,
	}
}

func deriveSealKey(shared, epk, sealPub []byte) []byte {
	return hkdf32(shared, concatBytes(epk, sealPub), []byte("akv1/seal"))
}

// asPrintableASCII requires a string of minLen..maxLen bytes of 0x20–0x7E.
func asPrintableASCII(v any, what string, minLen, maxLen int) (string, error) {
	s, ok := v.(string)
	if !ok || len(s) < minLen || len(s) > maxLen || !isPrintableASCII(s) {
		return "", badRequest("%s must be %d..%d bytes of printable ASCII", what, minLen, maxLen)
	}
	return s, nil
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func parseSealedOrigin(v any, what string) (SealedOrigin, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return SealedOrigin{}, err
	}
	if err := exactKeys(obj, []string{"kind", "account", "client_id", "grant_id"}, what); err != nil {
		return SealedOrigin{}, err
	}
	var o SealedOrigin
	if o.Kind, err = asEnum(obj["kind"], []string{SealedOriginMCP}, what+".kind"); err != nil {
		return SealedOrigin{}, err
	}
	if o.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return SealedOrigin{}, err
	}
	if o.ClientID, err = asPrintableASCII(obj["client_id"], what+".client_id", 1, maxClientIDBytes); err != nil {
		return SealedOrigin{}, err
	}
	if o.GrantID, err = asPrintableASCII(obj["grant_id"], what+".grant_id", 1, maxGrantIDBytes); err != nil {
		return SealedOrigin{}, err
	}
	return o, nil
}

// ParseSealedOp structurally validates an untrusted sealed operation: an
// unknown v or alg is unsupported_version; keys, lengths and origin are
// bad_request.
func ParseSealedOp(v any) (SealedOp, error) {
	const what = "sealed op"
	obj, err := asObject(v, what)
	if err != nil {
		return SealedOp{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return SealedOp{}, err
	}
	if obj["alg"] != AlgSealedOp {
		return SealedOp{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "sealed_id", "vault_id", "key_epoch", "epk", "n", "ct", "origin", "ts"}, what); err != nil {
		return SealedOp{}, err
	}
	var s SealedOp
	if s.SealedID, err = asID(obj["sealed_id"], what+".sealed_id"); err != nil {
		return SealedOp{}, err
	}
	if s.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return SealedOp{}, err
	}
	if s.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return SealedOp{}, err
	}
	if s.Epk, err = asB64(obj["epk"], what+".epk", KeyBytes); err != nil {
		return SealedOp{}, err
	}
	if s.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return SealedOp{}, err
	}
	if s.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
		return SealedOp{}, err
	}
	if ct, _ := B64Decode(s.Ct); len(ct) < TagBytes || len(ct) > MaxPlaintextBytes+TagBytes {
		return SealedOp{}, badRequest("%s.ct length out of range", what)
	}
	if s.Origin, err = parseSealedOrigin(obj["origin"], what+".origin"); err != nil {
		return SealedOp{}, err
	}
	if s.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return SealedOp{}, err
	}
	return s, nil
}

// ParseSealedOpPlaintext validates a decrypted plaintext object.
func ParseSealedOpPlaintext(v any) (SealedOpPlaintext, error) {
	const what = "sealed op plaintext"
	obj, err := asObject(v, what)
	if err != nil {
		return SealedOpPlaintext{}, err
	}
	var p SealedOpPlaintext
	if p.Op, err = asEnum(obj["op"], []string{SealedOpSet, SealedOpDelete}, what+".op"); err != nil {
		return SealedOpPlaintext{}, err
	}
	if p.Op == SealedOpSet {
		err = exactKeys(obj, []string{"op", "name", "value"}, what, "sensitivity")
	} else {
		err = exactKeys(obj, []string{"op", "name"}, what)
	}
	if err != nil {
		return SealedOpPlaintext{}, err
	}
	if p.Name, err = asString(obj["name"], what+".name", MaxItemNameLength, 1); err != nil {
		return SealedOpPlaintext{}, err
	}
	if p.Op == SealedOpSet {
		if p.Value, err = asString(obj["value"], what+".value", MaxItemValueLength, 0); err != nil {
			return SealedOpPlaintext{}, err
		}
		if s, ok := obj["sensitivity"]; ok {
			if p.Sensitivity, err = asEnum(s, sensitivities, what+".sensitivity"); err != nil {
				return SealedOpPlaintext{}, err
			}
		}
	}
	return p, nil
}

// SealOpArgs configures SealOp. SealedID, EphemeralSecret and Nonce are
// empty/nil in production (fresh random values); tests inject them.
type SealOpArgs struct {
	SealPub         []byte // seal_pub[KeyEpoch] from a verified seal-key document
	VaultID         string
	KeyEpoch        int64
	SealedID        string
	Origin          SealedOrigin
	TS              int64
	Plaintext       SealedOpPlaintext
	EphemeralSecret []byte
	Nonce           []byte
}

// SealOp encrypts one operation to seal_pub[e] after the same checks
// OpenSealedOp applies.
func SealOp(args SealOpArgs) (SealedOp, error) {
	if len(args.SealPub) != KeyBytes {
		return SealedOp{}, badRequest("seal_pub must be 32 bytes")
	}
	sealedID := args.SealedID
	if sealedID == "" {
		sealedID = RandomID()
	}
	esk := args.EphemeralSecret
	if esk == nil {
		esk = randomBytes(KeyBytes)
	}
	nonce := args.Nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	pt, err := ParseSealedOpPlaintext(args.Plaintext.JSONValue())
	if err != nil {
		return SealedOp{}, err
	}
	ptBytes, err := CJSON(pt)
	if err != nil {
		return SealedOp{}, err
	}
	if len(ptBytes) > MaxPlaintextBytes {
		return SealedOp{}, badRequest("sealed op plaintext exceeds 65536 bytes")
	}
	epk, err := KxPublicKey(esk)
	if err != nil {
		return SealedOp{}, err
	}
	// Validate the wire fields with a placeholder ciphertext before encrypting.
	s := SealedOp{SealedID: sealedID, VaultID: args.VaultID, KeyEpoch: args.KeyEpoch, Epk: B64Encode(epk), N: B64Encode(nonce), Ct: B64Encode(make([]byte, TagBytes)), Origin: args.Origin, TS: args.TS}
	if s, err = ParseSealedOp(s); err != nil {
		return SealedOp{}, err
	}
	shared, err := X25519Shared(esk, args.SealPub)
	if err != nil {
		return SealedOp{}, err
	}
	ct, err := XC20PSeal(deriveSealKey(shared, epk, args.SealPub), nonce, ptBytes, sealedOpAAD(s))
	if err != nil {
		return SealedOp{}, err
	}
	s.Ct = B64Encode(ct)
	return s, nil
}

// OpenSealedOp parses and decrypts an untrusted sealed operation with
// SealSK[e], in the order of spec §3.6: wire shape (unsupported_version /
// bad_request), vault_id ≠ vaultID (bad_request), all-zero shared secret
// (bad_request), AEAD failure (decrypt_failed), plaintext not canonical or
// invalid (bad_request).
func OpenSealedOp(sealSecret []byte, wire any, vaultID string) (SealedOp, SealedOpPlaintext, error) {
	s, err := ParseSealedOp(wire)
	if err != nil {
		return SealedOp{}, SealedOpPlaintext{}, err
	}
	if s.VaultID != vaultID {
		return SealedOp{}, SealedOpPlaintext{}, badRequest("sealed op belongs to another vault")
	}
	sealPub, err := KxPublicKey(sealSecret)
	if err != nil {
		return SealedOp{}, SealedOpPlaintext{}, err
	}
	epk, _ := B64Decode(s.Epk)
	shared, err := X25519Shared(sealSecret, epk)
	if err != nil {
		return SealedOp{}, SealedOpPlaintext{}, err
	}
	nonce, _ := B64Decode(s.N)
	ct, _ := B64Decode(s.Ct)
	ptBytes, err := XC20POpen(deriveSealKey(shared, epk, sealPub), nonce, ct, sealedOpAAD(s))
	if err != nil {
		return SealedOp{}, SealedOpPlaintext{}, err
	}
	v, err := CJSONParse(ptBytes)
	if err != nil {
		return SealedOp{}, SealedOpPlaintext{}, err
	}
	pt, err := ParseSealedOpPlaintext(v)
	if err != nil {
		return SealedOp{}, SealedOpPlaintext{}, err
	}
	return s, pt, nil
}
