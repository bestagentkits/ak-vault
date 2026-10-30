package akv1

// Input seals (spec §3.11, ADR 0004): a secret value typed into the /input
// form, sealed to a one-time X25519 key that one online device holds in memory
// for one input request. The device rebuilds the AAD from what it recorded
// when it issued the key, so a seal moved to another request, device, account
// or name never opens.
//
//	shared = X25519(esk, input_pub)              ; all-zero output refused
//	key    = HKDF(ikm=shared, salt=epk || input_pub, info="akv1/input-seal", L=32)
//	aad    = {ctx:"akv1/input-seal", request_id, vault_id, account, device_id, name, purpose|null, operation, expires_at}
//	ct     = XC20P(key, n, cjson({value, sensitivity?}), aad)

// AlgInputSeal is the only input-seal algorithm.
const AlgInputSeal = "x25519-xc20p-input"

// InputSealContext is what the device recorded when it issued the input key;
// every field is bound by the AAD. Purpose "" means null.
type InputSealContext struct {
	RequestID string
	VaultID   string
	Account   string
	DeviceID  string
	Name      string
	Purpose   string
	Operation string
	ExpiresAt int64 // unix ms
}

// JSONValue returns the context object, with purpose null when absent.
func (c InputSealContext) JSONValue() any {
	var purpose any
	if c.Purpose != "" {
		purpose = c.Purpose
	}
	return map[string]any{
		"request_id": c.RequestID, "vault_id": c.VaultID, "account": c.Account, "device_id": c.DeviceID,
		"name": c.Name, "purpose": purpose, "operation": c.Operation, "expires_at": c.ExpiresAt,
	}
}

// InputSealPayload is the sealed plaintext. Sensitivity "" means absent; an
// empty Value is a valid value.
type InputSealPayload struct {
	Value       string
	Sensitivity string
}

// JSONValue returns the plaintext object, omitting an absent sensitivity.
func (p InputSealPayload) JSONValue() any {
	m := map[string]any{"value": p.Value}
	if p.Sensitivity != "" {
		m["sensitivity"] = p.Sensitivity
	}
	return m
}

// InputSeal is the input-seal wire object
// {"v":1,"alg":"x25519-xc20p-input","request_id","epk","n","ct"}.
type InputSeal struct {
	RequestID string
	Epk       string
	N         string
	Ct        string
}

// JSONValue returns the wire object.
func (w InputSeal) JSONValue() any {
	return map[string]any{"v": int64(1), "alg": AlgInputSeal, "request_id": w.RequestID, "epk": w.Epk, "n": w.N, "ct": w.Ct}
}

func inputSealAAD(c InputSealContext) map[string]any {
	m := c.JSONValue().(map[string]any)
	m["ctx"] = "akv1/input-seal"
	return m
}

func deriveInputSealKey(shared, epk, inputPub []byte) []byte {
	return hkdf32(shared, concatBytes(epk, inputPub), []byte("akv1/input-seal"))
}

// ParseInputSealContext validates an input-seal context: exact keys, IDs,
// account 1..256, name 1..4096, purpose null or 1..200, operation create or
// replace, expires_at an integer. Every failure is bad_request.
func ParseInputSealContext(v any) (InputSealContext, error) {
	const what = "input seal context"
	obj, err := asObject(v, what)
	if err != nil {
		return InputSealContext{}, err
	}
	if err := exactKeys(obj, []string{"request_id", "vault_id", "account", "device_id", "name", "purpose", "operation", "expires_at"}, what); err != nil {
		return InputSealContext{}, err
	}
	var c InputSealContext
	if c.RequestID, err = asID(obj["request_id"], what+".request_id"); err != nil {
		return InputSealContext{}, err
	}
	if c.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return InputSealContext{}, err
	}
	if c.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return InputSealContext{}, err
	}
	if c.DeviceID, err = asID(obj["device_id"], what+".device_id"); err != nil {
		return InputSealContext{}, err
	}
	if c.Name, err = asString(obj["name"], what+".name", MaxItemNameLength, 1); err != nil {
		return InputSealContext{}, err
	}
	if obj["purpose"] != nil {
		if c.Purpose, err = asString(obj["purpose"], what+".purpose", MaxWritePurpose, 1); err != nil {
			return InputSealContext{}, err
		}
	}
	if c.Operation, err = asEnum(obj["operation"], WriteIntentOperations, what+".operation"); err != nil {
		return InputSealContext{}, err
	}
	if c.ExpiresAt, err = asUint(obj["expires_at"], what+".expires_at"); err != nil {
		return InputSealContext{}, err
	}
	return c, nil
}

// ParseInputSealPayload validates a decrypted (or to-be-sealed) payload:
// exact keys value and optional sensitivity; value is well-formed text of at
// most 65536 UTF-16 code units, possibly empty.
func ParseInputSealPayload(v any) (InputSealPayload, error) {
	const what = "input seal payload"
	obj, err := asObject(v, what)
	if err != nil {
		return InputSealPayload{}, err
	}
	if err := exactKeys(obj, []string{"value"}, what, "sensitivity"); err != nil {
		return InputSealPayload{}, err
	}
	var p InputSealPayload
	if p.Value, err = asWellFormedString(obj["value"], what+".value", MaxItemValueLength, 0); err != nil {
		return InputSealPayload{}, err
	}
	if s, ok := obj["sensitivity"]; ok {
		if p.Sensitivity, err = asEnum(s, sensitivities, what+".sensitivity"); err != nil {
			return InputSealPayload{}, err
		}
	}
	return p, nil
}

// ParseInputSeal structurally validates an untrusted input seal: an unknown v
// or alg is unsupported_version; keys, the request ID and the epk, n and ct
// lengths are bad_request.
func ParseInputSeal(v any) (InputSeal, error) {
	const what = "input seal"
	obj, err := asObject(v, what)
	if err != nil {
		return InputSeal{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return InputSeal{}, err
	}
	if obj["alg"] != AlgInputSeal {
		return InputSeal{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "request_id", "epk", "n", "ct"}, what); err != nil {
		return InputSeal{}, err
	}
	var w InputSeal
	if w.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
		return InputSeal{}, err
	}
	if ct, _ := B64Decode(w.Ct); len(ct) < TagBytes || len(ct) > MaxPlaintextBytes+TagBytes {
		return InputSeal{}, badRequest("%s.ct length out of range", what)
	}
	if w.RequestID, err = asID(obj["request_id"], what+".request_id"); err != nil {
		return InputSeal{}, err
	}
	if w.Epk, err = asB64(obj["epk"], what+".epk", KeyBytes); err != nil {
		return InputSeal{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return InputSeal{}, err
	}
	return w, nil
}

// GenerateInputKeyPair returns a fresh X25519 key pair for one input request.
// The device keeps the secret half in memory only and drops it before writing.
func GenerateInputKeyPair() (secret, public []byte, err error) {
	secret = randomBytes(KeyBytes)
	if public, err = KxPublicKey(secret); err != nil {
		return nil, nil, err
	}
	return secret, public, nil
}

// SealInput encrypts payload to inputPub under ctx with a fresh ephemeral key
// and nonce, after the same checks OpenInput applies.
func SealInput(inputPub []byte, ctx InputSealContext, payload InputSealPayload) (InputSeal, error) {
	return sealInput(inputPub, ctx, payload, nil, nil)
}

// sealInput is SealInput with an injectable ephemeral secret and nonce; only
// this package's vector tests fix them (reuse would repeat a key and nonce).
func sealInput(inputPub []byte, ctx InputSealContext, payload InputSealPayload, esk, nonce []byte) (InputSeal, error) {
	if len(inputPub) != KeyBytes {
		return InputSeal{}, badRequest("input_pub must be 32 bytes")
	}
	c, err := ParseInputSealContext(ctx.JSONValue())
	if err != nil {
		return InputSeal{}, err
	}
	p, err := ParseInputSealPayload(payload.JSONValue())
	if err != nil {
		return InputSeal{}, err
	}
	ptBytes, err := CJSON(p)
	if err != nil {
		return InputSeal{}, err
	}
	if len(ptBytes) > MaxPlaintextBytes {
		return InputSeal{}, badRequest("input seal plaintext exceeds %d bytes", MaxPlaintextBytes)
	}
	if esk == nil {
		esk = randomBytes(KeyBytes)
	}
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	epk, err := KxPublicKey(esk)
	if err != nil {
		return InputSeal{}, err
	}
	shared, err := X25519Shared(esk, inputPub)
	if err != nil {
		return InputSeal{}, err
	}
	ct, err := XC20PSeal(deriveInputSealKey(shared, epk, inputPub), nonce, ptBytes, inputSealAAD(c))
	if err != nil {
		return InputSeal{}, err
	}
	return InputSeal{RequestID: c.RequestID, Epk: B64Encode(epk), N: B64Encode(nonce), Ct: B64Encode(ct)}, nil
}

// OpenInput parses and decrypts an untrusted input seal with the request's
// input secret under the context the device recorded, in the order of spec
// §3.11: wire shape (unsupported_version / bad_request), request_id ≠ the
// context's (bad_request), all-zero shared secret (bad_request), AEAD failure
// (decrypt_failed), payload not canonical or invalid (bad_request).
func OpenInput(inputSecret []byte, wire any, ctx InputSealContext) (InputSealPayload, error) {
	w, err := ParseInputSeal(wire)
	if err != nil {
		return InputSealPayload{}, err
	}
	c, err := ParseInputSealContext(ctx.JSONValue())
	if err != nil {
		return InputSealPayload{}, err
	}
	if w.RequestID != c.RequestID {
		return InputSealPayload{}, badRequest("input seal belongs to another request")
	}
	inputPub, err := KxPublicKey(inputSecret)
	if err != nil {
		return InputSealPayload{}, err
	}
	epk, _ := B64Decode(w.Epk)
	shared, err := X25519Shared(inputSecret, epk)
	if err != nil {
		return InputSealPayload{}, err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	ptBytes, err := XC20POpen(deriveInputSealKey(shared, epk, inputPub), nonce, ct, inputSealAAD(c))
	if err != nil {
		return InputSealPayload{}, err
	}
	v, err := CJSONParse(ptBytes)
	if err != nil {
		return InputSealPayload{}, err
	}
	return ParseInputSealPayload(v)
}
