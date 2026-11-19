package akv1

// Sandbox secret leases (spec §3.14, ADR 0007). A sandbox that is not a vault
// member asks for named secrets; a person approves on an enrolled human
// device, which seals exactly the approved values to the sandbox's one-time
// lease key. The Worker relays ciphertext only.
//
// Request (signed by the sandbox's request key; the subject sealed to seal_pub[e]):
//
//	shared = X25519(esk, seal_pub[e])                ; all-zero output refused
//	key    = HKDF(ikm=shared, salt=epk || seal_pub[e], info="akv1/lease-request", L=32)
//	aad    = {ctx:"akv1/lease-request", lease_id, vault_id, key_epoch, account, requester, lease_pub, ttl_s, ts, expires_at}
//	ct     = XC20P(key, n, cjson({secrets:[{var, ref}], purpose?}), aad)
//	sig    = Ed25519(requester_key, "akv1/lease-request", wire minus sig)
//
// The lease code is the request digest b64(SHA-256(cjson(request))); the
// approving device refuses a request whose digest is not the code the person
// entered, because nothing else ties the self-signed request to their sandbox.
//
// Grant (signed by the approving device; values sealed to lease_pub):
//
//	shared = X25519(esk, lease_pub)
//	key    = HKDF(ikm=shared, salt=epk || lease_pub, info="akv1/lease-seal", L=32)
//	aad    = {ctx:"akv1/lease-seal", lease_id, vault_id, account, requester, lease_pub, request_digest, approver, ts, expires_at}
//	ct     = XC20P(key, n, cjson({secrets:[{var, value}]}), aad)
//	sig    = Ed25519(approver_key, "akv1/lease-grant", wire minus sig)

import "regexp"

// Lease algorithms.
const (
	AlgLeaseRequest = "x25519-xc20p-lease-req"
	AlgLeaseGrant   = "x25519-xc20p-lease"
)

// Lease decisions (closed set).
const (
	LeaseAllow = "allow"
	LeaseDeny  = "deny"
)

// LeaseDecisions lists the accepted grant decisions.
var LeaseDecisions = []string{LeaseAllow, LeaseDeny}

// Lease limits (spec §3.14).
const (
	LeaseMinTTLS    = 60
	LeaseMaxTTLS    = 86400
	LeaseMaxSecrets = 32
	maxLeasePurpose = 200
	maxLeaseVar     = 128
)

// leaseVarPattern is the environment variable names a lease may set.
var leaseVarPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// LeaseRef maps an environment variable to a secret reference (item name).
type LeaseRef struct {
	Var string
	Ref string
}

// LeaseSubject is what the sandbox asks for; never a value. Purpose "" means absent.
type LeaseSubject struct {
	Secrets []LeaseRef
	Purpose string
}

// JSONValue returns the plaintext object, omitting an absent purpose.
func (s LeaseSubject) JSONValue() any {
	list := make([]any, len(s.Secrets))
	for i, e := range s.Secrets {
		list[i] = map[string]any{"var": e.Var, "ref": e.Ref}
	}
	m := map[string]any{"secrets": list}
	if s.Purpose != "" {
		m["purpose"] = s.Purpose
	}
	return m
}

// Vars returns the requested variable names in order.
func (s LeaseSubject) Vars() []string {
	out := make([]string, len(s.Secrets))
	for i, e := range s.Secrets {
		out[i] = e.Var
	}
	return out
}

// LeaseValue maps an environment variable to an approved value.
type LeaseValue struct {
	Var   string
	Value string
}

// LeasePayload is what the approving device seals: a subset of the requested vars.
type LeasePayload struct {
	Secrets []LeaseValue
}

// JSONValue returns the plaintext object.
func (p LeasePayload) JSONValue() any {
	list := make([]any, len(p.Secrets))
	for i, e := range p.Secrets {
		list[i] = map[string]any{"var": e.Var, "value": e.Value}
	}
	return map[string]any{"secrets": list}
}

// LeaseRequest is the signed request wire object.
type LeaseRequest struct {
	LeaseID      string
	VaultID      string
	KeyEpoch     int64
	Account      string
	Requester    string
	RequesterKey string
	LeasePub     string
	TTLS         int64
	TS           int64
	ExpiresAt    int64
	Epk          string
	N            string
	Ct           string
	Sig          string
}

func (w LeaseRequest) unsigned() map[string]any {
	return map[string]any{
		"v": int64(1), "alg": AlgLeaseRequest, "lease_id": w.LeaseID, "vault_id": w.VaultID, "key_epoch": w.KeyEpoch,
		"account": w.Account, "requester": w.Requester, "requester_key": w.RequesterKey, "lease_pub": w.LeasePub,
		"ttl_s": w.TTLS, "ts": w.TS, "expires_at": w.ExpiresAt, "epk": w.Epk, "n": w.N, "ct": w.Ct,
	}
}

// JSONValue returns the wire object.
func (w LeaseRequest) JSONValue() any {
	m := w.unsigned()
	m["sig"] = w.Sig
	return m
}

func leaseRequestAAD(w LeaseRequest) map[string]any {
	return map[string]any{
		"ctx": "akv1/lease-request", "lease_id": w.LeaseID, "vault_id": w.VaultID, "key_epoch": w.KeyEpoch,
		"account": w.Account, "requester": w.Requester, "lease_pub": w.LeasePub, "ttl_s": w.TTLS, "ts": w.TS,
		"expires_at": w.ExpiresAt,
	}
}

// LeaseGrant is the signed grant wire object. ExpiresAt, Epk, N and Ct are
// set for an allow only.
type LeaseGrant struct {
	LeaseID       string
	VaultID       string
	Account       string
	Requester     string
	RequestDigest string
	Decision      string
	Approver      string
	ApproverKey   string
	TS            int64
	ExpiresAt     int64
	Epk           string
	N             string
	Ct            string
	Sig           string
}

func (g LeaseGrant) unsigned() map[string]any {
	m := map[string]any{
		"v": int64(1), "alg": AlgLeaseGrant, "lease_id": g.LeaseID, "vault_id": g.VaultID, "account": g.Account,
		"requester": g.Requester, "request_digest": g.RequestDigest, "decision": g.Decision, "approver": g.Approver,
		"approver_key": g.ApproverKey, "ts": g.TS,
	}
	if g.Decision == LeaseAllow {
		m["expires_at"], m["epk"], m["n"], m["ct"] = g.ExpiresAt, g.Epk, g.N, g.Ct
	}
	return m
}

// JSONValue returns the wire object.
func (g LeaseGrant) JSONValue() any {
	m := g.unsigned()
	m["sig"] = g.Sig
	return m
}

func leaseGrantAAD(g LeaseGrant, leasePub string) map[string]any {
	return map[string]any{
		"ctx": "akv1/lease-seal", "lease_id": g.LeaseID, "vault_id": g.VaultID, "account": g.Account,
		"requester": g.Requester, "lease_pub": leasePub, "request_digest": g.RequestDigest, "approver": g.Approver,
		"ts": g.TS, "expires_at": g.ExpiresAt,
	}
}

func asLeaseVar(v any, what string) (string, error) {
	s, err := asString(v, what, maxLeaseVar, 1)
	if err != nil {
		return "", err
	}
	if !leaseVarPattern.MatchString(s) {
		return "", badRequest("%s must match %s", what, leaseVarPattern.String())
	}
	return s, nil
}

// leaseEntries validates the secrets list shared by subject and payload: 1..32
// objects with exactly var and other, unique vars.
func leaseEntries(obj map[string]any, what, other string, parseOther func(any, string) (string, error)) ([][2]string, error) {
	list, err := asArray(obj["secrets"], what+".secrets", LeaseMaxSecrets)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, badRequest("%s.secrets is empty", what)
	}
	out := make([][2]string, len(list))
	for i, entry := range list {
		ew := what + ".secrets[]"
		e, err := asObject(entry, ew)
		if err != nil {
			return nil, err
		}
		if err := exactKeys(e, []string{"var", other}, ew); err != nil {
			return nil, err
		}
		if out[i][0], err = asLeaseVar(e["var"], ew+".var"); err != nil {
			return nil, err
		}
		if out[i][1], err = parseOther(e[other], ew+"."+other); err != nil {
			return nil, err
		}
	}
	seen := make(map[string]bool, len(out))
	for _, e := range out {
		if seen[e[0]] {
			return nil, badRequest("%s.secrets repeats a var", what)
		}
		seen[e[0]] = true
	}
	return out, nil
}

// ParseLeaseSubject validates a decrypted (or to-be-sealed) lease subject.
func ParseLeaseSubject(v any) (LeaseSubject, error) {
	const what = "lease subject"
	obj, err := asObject(v, what)
	if err != nil {
		return LeaseSubject{}, err
	}
	if err := exactKeys(obj, []string{"secrets"}, what, "purpose"); err != nil {
		return LeaseSubject{}, err
	}
	entries, err := leaseEntries(obj, what, "ref", func(v any, w string) (string, error) { return asItemName(v, w) })
	if err != nil {
		return LeaseSubject{}, err
	}
	s := LeaseSubject{Secrets: make([]LeaseRef, len(entries))}
	for i, e := range entries {
		s.Secrets[i] = LeaseRef{Var: e[0], Ref: e[1]}
	}
	if p, ok := obj["purpose"]; ok {
		if s.Purpose, err = asWellFormedString(p, what+".purpose", maxLeasePurpose, 1); err != nil {
			return LeaseSubject{}, err
		}
	}
	return s, nil
}

// ParseLeasePayload validates a decrypted (or to-be-sealed) lease payload.
func ParseLeasePayload(v any) (LeasePayload, error) {
	const what = "lease payload"
	obj, err := asObject(v, what)
	if err != nil {
		return LeasePayload{}, err
	}
	if err := exactKeys(obj, []string{"secrets"}, what); err != nil {
		return LeasePayload{}, err
	}
	entries, err := leaseEntries(obj, what, "value", func(v any, w string) (string, error) {
		return asWellFormedString(v, w, MaxItemValueLength, 0)
	})
	if err != nil {
		return LeasePayload{}, err
	}
	p := LeasePayload{Secrets: make([]LeaseValue, len(entries))}
	for i, e := range entries {
		p.Secrets[i] = LeaseValue{Var: e[0], Value: e[1]}
	}
	return p, nil
}

func leaseCtLength(ct string, max int, what string) error {
	if b, _ := B64Decode(ct); len(b) < TagBytes || len(b) > max+TagBytes {
		return badRequest("%s.ct length out of range", what)
	}
	return nil
}

// ParseLeaseRequest structurally validates an untrusted request (no signature
// or AEAD check), in the reference check order.
func ParseLeaseRequest(v any) (LeaseRequest, error) {
	const what = "lease request"
	obj, err := asObject(v, what)
	if err != nil {
		return LeaseRequest{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return LeaseRequest{}, err
	}
	if obj["alg"] != AlgLeaseRequest {
		return LeaseRequest{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "lease_id", "vault_id", "key_epoch", "account", "requester", "requester_key", "lease_pub", "ttl_s", "ts", "expires_at", "epk", "n", "ct", "sig"}, what); err != nil {
		return LeaseRequest{}, err
	}
	var w LeaseRequest
	if w.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
		return LeaseRequest{}, err
	}
	if err := leaseCtLength(w.Ct, maxSubjectPlaintext, what); err != nil {
		return LeaseRequest{}, err
	}
	if w.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return LeaseRequest{}, err
	}
	if w.ExpiresAt, err = asUint(obj["expires_at"], what+".expires_at"); err != nil {
		return LeaseRequest{}, err
	}
	if w.ExpiresAt <= w.TS {
		return LeaseRequest{}, badRequest("%s.expires_at must be after ts", what)
	}
	if w.RequesterKey, err = asB64(obj["requester_key"], what+".requester_key", KeyBytes); err != nil {
		return LeaseRequest{}, err
	}
	if w.Requester, err = asID(obj["requester"], what+".requester"); err != nil {
		return LeaseRequest{}, err
	}
	if kid, _ := DeviceIDFromSignPubB64(w.RequesterKey); kid != w.Requester {
		return LeaseRequest{}, badRequest("%s.requester is not kid(requester_key)", what)
	}
	if w.LeaseID, err = asID(obj["lease_id"], what+".lease_id"); err != nil {
		return LeaseRequest{}, err
	}
	if w.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return LeaseRequest{}, err
	}
	if w.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return LeaseRequest{}, err
	}
	if w.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return LeaseRequest{}, err
	}
	if w.LeasePub, err = asB64(obj["lease_pub"], what+".lease_pub", KeyBytes); err != nil {
		return LeaseRequest{}, err
	}
	if w.TTLS, err = asInt(obj["ttl_s"], what+".ttl_s", LeaseMinTTLS, LeaseMaxTTLS); err != nil {
		return LeaseRequest{}, err
	}
	if w.Epk, err = asB64(obj["epk"], what+".epk", KeyBytes); err != nil {
		return LeaseRequest{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return LeaseRequest{}, err
	}
	if w.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return LeaseRequest{}, err
	}
	return w, nil
}

// LeaseRequestDigest is b64(SHA-256(cjson(request wire, sig included))): the lease code.
func LeaseRequestDigest(wire any) (string, error) {
	w, err := ParseLeaseRequest(wire)
	if err != nil {
		return "", err
	}
	b, err := CJSON(w)
	if err != nil {
		return "", err
	}
	return SHA256B64(b), nil
}

// GenerateLeaseKeys returns a fresh X25519 lease key pair and Ed25519 request
// seed for one lease; the sandbox keeps both in memory only.
func GenerateLeaseKeys() (leaseSecret, leasePub, requestSeed, requestPub []byte, err error) {
	leaseSecret, requestSeed = randomBytes(KeyBytes), randomBytes(KeyBytes)
	if leasePub, err = KxPublicKey(leaseSecret); err != nil {
		return nil, nil, nil, nil, err
	}
	if requestPub, err = SignPublicKey(requestSeed); err != nil {
		return nil, nil, nil, nil, err
	}
	return leaseSecret, leasePub, requestSeed, requestPub, nil
}

// SealLeaseRequestArgs configures SealLeaseRequest.
type SealLeaseRequestArgs struct {
	VaultID   string
	KeyEpoch  int64
	Account   string
	SealPub   []byte // the epoch's seal public key, from the seal-key document
	LeasePub  []byte
	TTLS      int64
	TS        int64 // unix ms
	ExpiresAt int64 // unix ms; after TS
	Subject   LeaseSubject
}

// leaseVectorValues fixes random inputs; only this package's vector tests set
// them (reuse would repeat a key and nonce).
type leaseVectorValues struct {
	leaseID string
	esk     []byte
	nonce   []byte
}

// SealLeaseRequest seals the subject to the epoch's seal key and signs the
// request with the sandbox's request seed.
func SealLeaseRequest(requestSeed []byte, args SealLeaseRequestArgs) (LeaseRequest, error) {
	return sealLeaseRequestWithVectorValues(requestSeed, args, leaseVectorValues{})
}

func sealLeaseRequestWithVectorValues(requestSeed []byte, args SealLeaseRequestArgs, fixed leaseVectorValues) (LeaseRequest, error) {
	subject, err := ParseLeaseSubject(args.Subject.JSONValue())
	if err != nil {
		return LeaseRequest{}, err
	}
	if len(args.SealPub) != KeyBytes {
		return LeaseRequest{}, badRequest("seal_pub must be 32 bytes")
	}
	if len(args.LeasePub) != KeyBytes {
		return LeaseRequest{}, badRequest("lease_pub must be 32 bytes")
	}
	requesterKey, err := SignPublicKey(requestSeed)
	if err != nil {
		return LeaseRequest{}, err
	}
	pt, err := CJSON(subject)
	if err != nil {
		return LeaseRequest{}, err
	}
	if len(pt) > maxSubjectPlaintext {
		return LeaseRequest{}, badRequest("lease subject too large")
	}
	leaseID := fixed.leaseID
	if leaseID == "" {
		leaseID = RandomID()
	}
	esk, nonce := fixed.esk, fixed.nonce
	if esk == nil {
		esk = randomBytes(KeyBytes)
	}
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	epk, err := KxPublicKey(esk)
	if err != nil {
		return LeaseRequest{}, err
	}
	w := LeaseRequest{
		LeaseID: leaseID, VaultID: args.VaultID, KeyEpoch: args.KeyEpoch, Account: args.Account,
		Requester: Kid(requesterKey), RequesterKey: B64Encode(requesterKey), LeasePub: B64Encode(args.LeasePub),
		TTLS: args.TTLS, TS: args.TS, ExpiresAt: args.ExpiresAt, Epk: B64Encode(epk), N: B64Encode(nonce),
		Ct: B64Encode(make([]byte, TagBytes)), Sig: B64Encode(make([]byte, 64)),
	}
	if w, err = ParseLeaseRequest(w); err != nil {
		return LeaseRequest{}, err
	}
	shared, err := X25519Shared(esk, args.SealPub)
	if err != nil {
		return LeaseRequest{}, err
	}
	key := hkdf32(shared, concatBytes(epk, args.SealPub), []byte("akv1/lease-request"))
	ct, err := XC20PSeal(key, nonce, pt, leaseRequestAAD(w))
	if err != nil {
		return LeaseRequest{}, err
	}
	w.Ct = B64Encode(ct)
	if w.Sig, err = SignDetached(ContextLeaseRequest, w.unsigned(), requestSeed); err != nil {
		return LeaseRequest{}, err
	}
	return w, nil
}

// VerifyLeaseRequestSignature parses a request and checks its signature under
// requester_key (what the Worker runs on POST …/leases).
func VerifyLeaseRequestSignature(wire any) (LeaseRequest, error) {
	w, err := ParseLeaseRequest(wire)
	if err != nil {
		return LeaseRequest{}, err
	}
	if err := VerifyObject(ContextLeaseRequest, w.JSONValue(), w.RequesterKey); err != nil {
		return LeaseRequest{}, err
	}
	return w, nil
}

// OpenLeaseRequest is the approver side, in the order of spec §3.14: parse;
// vault_id or account other than expected (bad_request); signature
// (invalid_signature); digest ≠ leaseCode (forbidden); all-zero shared secret
// (bad_request); AEAD (decrypt_failed); subject not canonical or invalid
// (bad_request). The caller passes SealSK[key_epoch] and checks expiry.
func OpenLeaseRequest(sealSecret []byte, wire any, vaultID, account, leaseCode string) (LeaseRequest, LeaseSubject, string, error) {
	w, err := verifyLeaseRequestFor(wire, vaultID, account)
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	digest, err := LeaseRequestDigest(w)
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	if digest != leaseCode {
		return LeaseRequest{}, LeaseSubject{}, "", newErr(CodeForbidden, "lease request does not match the lease code")
	}
	sealPub, err := KxPublicKey(sealSecret)
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	epk, _ := B64Decode(w.Epk)
	shared, err := X25519Shared(sealSecret, epk)
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	pt, err := XC20POpen(hkdf32(shared, concatBytes(epk, sealPub), []byte("akv1/lease-request")), nonce, ct, leaseRequestAAD(w))
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	v, err := CJSONParse(pt)
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	s, err := ParseLeaseSubject(v)
	if err != nil {
		return LeaseRequest{}, LeaseSubject{}, "", err
	}
	return w, s, digest, nil
}

// verifyLeaseRequestFor parses a request, refuses one for another
// vault or account (bad_request), then checks its signature.
func verifyLeaseRequestFor(wire any, vaultID, account string) (LeaseRequest, error) {
	w, err := ParseLeaseRequest(wire)
	if err != nil {
		return LeaseRequest{}, err
	}
	if w.VaultID != vaultID {
		return LeaseRequest{}, badRequest("lease request belongs to another vault")
	}
	if w.Account != account {
		return LeaseRequest{}, badRequest("lease request belongs to another account")
	}
	return VerifyLeaseRequestSignature(w)
}

// ParseLeaseGrant structurally validates an untrusted grant (no signature,
// binding or AEAD check), in the reference check order.
func ParseLeaseGrant(v any) (LeaseGrant, error) {
	const what = "lease grant"
	obj, err := asObject(v, what)
	if err != nil {
		return LeaseGrant{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return LeaseGrant{}, err
	}
	if obj["alg"] != AlgLeaseGrant {
		return LeaseGrant{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	var g LeaseGrant
	if g.Decision, err = asEnum(obj["decision"], LeaseDecisions, what+".decision"); err != nil {
		return LeaseGrant{}, err
	}
	keys := []string{"v", "alg", "lease_id", "vault_id", "account", "requester", "request_digest", "decision", "approver", "approver_key", "ts", "sig"}
	if g.Decision == LeaseAllow {
		keys = append(keys, "expires_at", "epk", "n", "ct")
	}
	if err := exactKeys(obj, keys, what); err != nil {
		return LeaseGrant{}, err
	}
	if g.ApproverKey, err = asB64(obj["approver_key"], what+".approver_key", KeyBytes); err != nil {
		return LeaseGrant{}, err
	}
	if g.Approver, err = asID(obj["approver"], what+".approver"); err != nil {
		return LeaseGrant{}, err
	}
	if kid, _ := DeviceIDFromSignPubB64(g.ApproverKey); kid != g.Approver {
		return LeaseGrant{}, badRequest("%s.approver is not kid(approver_key)", what)
	}
	if g.LeaseID, err = asID(obj["lease_id"], what+".lease_id"); err != nil {
		return LeaseGrant{}, err
	}
	if g.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return LeaseGrant{}, err
	}
	if g.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return LeaseGrant{}, err
	}
	if g.Requester, err = asID(obj["requester"], what+".requester"); err != nil {
		return LeaseGrant{}, err
	}
	if g.RequestDigest, err = asB64(obj["request_digest"], what+".request_digest", 32); err != nil {
		return LeaseGrant{}, err
	}
	if g.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return LeaseGrant{}, err
	}
	if g.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return LeaseGrant{}, err
	}
	if g.Decision == LeaseAllow {
		if g.ExpiresAt, err = asUint(obj["expires_at"], what+".expires_at"); err != nil {
			return LeaseGrant{}, err
		}
		if g.ExpiresAt <= g.TS {
			return LeaseGrant{}, badRequest("%s.expires_at must be after ts", what)
		}
		if g.Epk, err = asB64(obj["epk"], what+".epk", KeyBytes); err != nil {
			return LeaseGrant{}, err
		}
		if g.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
			return LeaseGrant{}, err
		}
		if g.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
			return LeaseGrant{}, err
		}
		if err := leaseCtLength(g.Ct, MaxPlaintextBytes, what); err != nil {
			return LeaseGrant{}, err
		}
	}
	return g, nil
}

// SignLeaseGrantArgs configures SignLeaseGrant.
type SignLeaseGrantArgs struct {
	Request       any    // the opened request (the approving device checked the lease code)
	Decision      string // LeaseAllow or LeaseDeny
	Payload       *LeasePayload
	ApproverKey   []byte // the approving device's Ed25519 public key
	TS            int64  // unix ms, in [request.ts, request.expires_at)
	ExpiresAt     int64  // allow only; 0 means ts + ttl_s*1000
	RequestedVars []string
}

func checkLeasePayloadVars(p LeasePayload, requested []string) error {
	for _, s := range p.Secrets {
		if !contains(requested, s.Var) {
			return newErr(CodeForbidden, "lease payload names a var the request did not ask for")
		}
	}
	return nil
}

// SignLeaseGrant builds and signs a grant with the approving device's seed.
func SignLeaseGrant(signSecret []byte, args SignLeaseGrantArgs) (LeaseGrant, error) {
	return signLeaseGrantWithVectorValues(signSecret, args, leaseVectorValues{})
}

func signLeaseGrantWithVectorValues(signSecret []byte, args SignLeaseGrantArgs, fixed leaseVectorValues) (LeaseGrant, error) {
	own, err := SignPublicKey(signSecret)
	if err != nil {
		return LeaseGrant{}, err
	}
	if len(args.ApproverKey) != KeyBytes {
		return LeaseGrant{}, badRequest("approver_key must be 32 bytes")
	}
	if B64Encode(own) != B64Encode(args.ApproverKey) {
		return LeaseGrant{}, badRequest("approver_key is not the signing key")
	}
	r, err := ParseLeaseRequest(args.Request)
	if err != nil {
		return LeaseGrant{}, err
	}
	decision, err := asEnum(args.Decision, LeaseDecisions, "decision")
	if err != nil {
		return LeaseGrant{}, err
	}
	if args.TS < r.TS || args.TS >= r.ExpiresAt {
		return LeaseGrant{}, badRequest("grant is outside the request lifetime")
	}
	digest, err := LeaseRequestDigest(r)
	if err != nil {
		return LeaseGrant{}, err
	}
	g := LeaseGrant{
		LeaseID: r.LeaseID, VaultID: r.VaultID, Account: r.Account, Requester: r.Requester, RequestDigest: digest,
		Decision: decision, Approver: Kid(args.ApproverKey), ApproverKey: B64Encode(args.ApproverKey), TS: args.TS,
	}
	if g.Approver == r.Requester {
		return LeaseGrant{}, newErr(CodeForbidden, "a lease cannot be granted by its requester")
	}
	if decision == LeaseDeny {
		if args.Payload != nil || args.ExpiresAt != 0 {
			return LeaseGrant{}, badRequest("a deny carries no values or expiry")
		}
	} else if err := sealLeaseGrant(&g, r, args, fixed); err != nil {
		return LeaseGrant{}, err
	}
	g.Sig = B64Encode(make([]byte, 64))
	if g, err = ParseLeaseGrant(g); err != nil {
		return LeaseGrant{}, err
	}
	if g.Sig, err = SignDetached(ContextLeaseGrant, g.unsigned(), signSecret); err != nil {
		return LeaseGrant{}, err
	}
	return g, nil
}

// sealLeaseGrant fills an allow grant's expiry and sealed payload.
func sealLeaseGrant(g *LeaseGrant, r LeaseRequest, args SignLeaseGrantArgs, fixed leaseVectorValues) error {
	if args.Payload == nil {
		return badRequest("an allow carries the approved values")
	}
	p, err := ParseLeasePayload(args.Payload.JSONValue())
	if err != nil {
		return err
	}
	if err := checkLeasePayloadVars(p, args.RequestedVars); err != nil {
		return err
	}
	maxExpiry := g.TS + r.TTLS*1000
	g.ExpiresAt = args.ExpiresAt
	if g.ExpiresAt == 0 {
		g.ExpiresAt = maxExpiry
	}
	if g.ExpiresAt <= g.TS || g.ExpiresAt > maxExpiry {
		return badRequest("grant expiry outside (ts, ts + ttl_s]")
	}
	pt, err := CJSON(p)
	if err != nil {
		return err
	}
	if len(pt) > MaxPlaintextBytes {
		return badRequest("lease payload too large")
	}
	esk, nonce := fixed.esk, fixed.nonce
	if esk == nil {
		esk = randomBytes(KeyBytes)
	}
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	epk, err := KxPublicKey(esk)
	if err != nil {
		return err
	}
	leasePub, _ := B64Decode(r.LeasePub)
	shared, err := X25519Shared(esk, leasePub)
	if err != nil {
		return err
	}
	ct, err := XC20PSeal(hkdf32(shared, concatBytes(epk, leasePub), []byte("akv1/lease-seal")), nonce, pt, leaseGrantAAD(*g, r.LeasePub))
	if err != nil {
		return err
	}
	g.Epk, g.N, g.Ct = B64Encode(epk), B64Encode(nonce), B64Encode(ct)
	return nil
}

// VerifyLeaseGrant runs the binding and signature checks shared by the Worker
// and the sandbox, in the order of spec §3.14: parse; lease_id, vault_id,
// account, requester or request_digest other than the request's (bad_request);
// ts outside [request.ts, request.expires_at) or an allow expiry beyond
// ts + ttl_s (bad_request); approver = requester (forbidden); signature
// (invalid_signature).
func VerifyLeaseGrant(grant, request any) (LeaseGrant, error) {
	g, err := ParseLeaseGrant(grant)
	if err != nil {
		return LeaseGrant{}, err
	}
	r, err := ParseLeaseRequest(request)
	if err != nil {
		return LeaseGrant{}, err
	}
	if g.LeaseID != r.LeaseID || g.VaultID != r.VaultID || g.Account != r.Account || g.Requester != r.Requester {
		return LeaseGrant{}, badRequest("lease grant answers another request")
	}
	digest, err := LeaseRequestDigest(r)
	if err != nil {
		return LeaseGrant{}, err
	}
	if g.RequestDigest != digest {
		return LeaseGrant{}, badRequest("lease grant binds another request body")
	}
	if g.TS < r.TS || g.TS >= r.ExpiresAt {
		return LeaseGrant{}, badRequest("lease grant is outside the request lifetime")
	}
	if g.Decision == LeaseAllow && g.ExpiresAt > g.TS+r.TTLS*1000 {
		return LeaseGrant{}, badRequest("lease grant outlives the requested ttl_s")
	}
	if g.Approver == r.Requester {
		return LeaseGrant{}, newErr(CodeForbidden, "a lease cannot be granted by its requester")
	}
	if err := VerifyObject(ContextLeaseGrant, g.JSONValue(), g.ApproverKey); err != nil {
		return LeaseGrant{}, err
	}
	return g, nil
}

// OpenLeaseGrant is the sandbox side, in the order of spec §3.14:
// VerifyLeaseGrant; approver outside a non-nil approvers pin (forbidden); a
// deny returns with a zero payload; now >= expires_at (bad_request); lease
// secret not the request's, or AEAD failure (decrypt_failed); payload not
// canonical or invalid (bad_request); a var not requested (forbidden).
func OpenLeaseGrant(leaseSecret []byte, grant, request any, now int64, requestedVars, approvers []string) (LeaseGrant, LeasePayload, error) {
	g, err := VerifyLeaseGrant(grant, request)
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	r, err := ParseLeaseRequest(request)
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	if approvers != nil && !contains(approvers, g.Approver) {
		return LeaseGrant{}, LeasePayload{}, newErr(CodeForbidden, "lease grant from an approver outside the pinned set")
	}
	if g.Decision == LeaseDeny {
		return g, LeasePayload{}, nil
	}
	if now >= g.ExpiresAt {
		return LeaseGrant{}, LeasePayload{}, badRequest("lease expired")
	}
	leasePub, err := KxPublicKey(leaseSecret)
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	if B64Encode(leasePub) != r.LeasePub {
		return LeaseGrant{}, LeasePayload{}, newErr(CodeDecryptFailed, "lease secret does not match the request")
	}
	epk, _ := B64Decode(g.Epk)
	shared, err := X25519Shared(leaseSecret, epk)
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	nonce, _ := B64Decode(g.N)
	ct, _ := B64Decode(g.Ct)
	pt, err := XC20POpen(hkdf32(shared, concatBytes(epk, leasePub), []byte("akv1/lease-seal")), nonce, ct, leaseGrantAAD(g, r.LeasePub))
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	v, err := CJSONParse(pt)
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	p, err := ParseLeasePayload(v)
	if err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	if err := checkLeasePayloadVars(p, requestedVars); err != nil {
		return LeaseGrant{}, LeasePayload{}, err
	}
	return g, p, nil
}
