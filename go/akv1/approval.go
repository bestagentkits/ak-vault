package akv1

// Access approvals (spec §3.13): a device whose local resolve found no grant
// publishes an approval request, and the person answers it from another
// enrolled device of the same account. The server stores ciphertext and
// signatures only; only an enrolled device key signs a decision, and the
// requesting device verifies it before writing a local grant.
//
//	key = HKDF(ikm=VK[e], salt=b64decode(request_id), info="akv1/approval-request", L=32)
//	aad = {ctx:"akv1/approval-request", vault_id, request_id, key_epoch, requester, ts, expires_at}
//	ct  = XC20P(key, n, cjson(subject), aad)
//	sig = Ed25519(requester, "akv1/approval-request", wire minus sig)
//
// A decision is signed under "akv1/approval-decision" and binds the request by
// its digest. The subject never carries a secret value.

import "regexp"

// AlgApproval is the only approval-request algorithm.
const AlgApproval = "xc20p"

// Signing contexts of approval requests and decisions.
const (
	ContextApprovalRequest  = "akv1/approval-request"
	ContextApprovalDecision = "akv1/approval-decision"
)

// Approval decisions (closed set).
const (
	ApprovalDeny      = "deny"
	ApprovalAllowOnce = "allow_once"
	ApprovalAllowTTL  = "allow_ttl"
)

// ApprovalDecisions lists the accepted decisions.
var ApprovalDecisions = []string{ApprovalDeny, ApprovalAllowOnce, ApprovalAllowTTL}

// Approval limits (spec §3.13).
const (
	ApprovalMinTTLS      = 60
	ApprovalMaxTTLS      = 2592000
	maxApprovalAgent     = 128
	maxApprovalProject   = 1024
	maxApprovalPurpose   = 200
	maxApprovalReason    = 500
	maxSubjectPlaintext  = 16384
	approvalFingerprintN = 71
)

var approvalFingerprint = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ApprovalSubject is the decrypted subject. Project, Purpose and Reason "" mean absent.
type ApprovalSubject struct {
	Secret      string
	Agent       string
	Fingerprint string
	Project     string
	Purpose     string
	Reason      string
	MaxTTLS     int64
}

// JSONValue returns the plaintext object, omitting absent optional fields.
func (s ApprovalSubject) JSONValue() any {
	m := map[string]any{"secret": s.Secret, "agent": s.Agent, "fingerprint": s.Fingerprint, "max_ttl_s": s.MaxTTLS}
	if s.Project != "" {
		m["project"] = s.Project
	}
	if s.Purpose != "" {
		m["purpose"] = s.Purpose
	}
	if s.Reason != "" {
		m["reason"] = s.Reason
	}
	return m
}

// ApprovalRequest is the signed request wire object.
type ApprovalRequest struct {
	RequestID string
	VaultID   string
	KeyEpoch  int64
	Requester string
	N         string
	Ct        string
	TS        int64
	ExpiresAt int64
	Sig       string
}

func (w ApprovalRequest) unsigned() map[string]any {
	return map[string]any{
		"v": int64(1), "alg": AlgApproval, "request_id": w.RequestID, "vault_id": w.VaultID, "key_epoch": w.KeyEpoch,
		"requester": w.Requester, "n": w.N, "ct": w.Ct, "ts": w.TS, "expires_at": w.ExpiresAt,
	}
}

// JSONValue returns the wire object.
func (w ApprovalRequest) JSONValue() any {
	m := w.unsigned()
	m["sig"] = w.Sig
	return m
}

func approvalAAD(w ApprovalRequest) map[string]any {
	return map[string]any{
		"ctx": "akv1/approval-request", "vault_id": w.VaultID, "request_id": w.RequestID, "key_epoch": w.KeyEpoch,
		"requester": w.Requester, "ts": w.TS, "expires_at": w.ExpiresAt,
	}
}

func approvalSubjectKey(vk []byte, requestID string) ([]byte, error) {
	if len(vk) != KeyBytes {
		return nil, badRequest("vault key must be 32 bytes")
	}
	salt, _ := B64Decode(requestID)
	return hkdf32(vk, salt, []byte("akv1/approval-request")), nil
}

func optionalApprovalText(obj map[string]any, key string, max int, what string) (string, error) {
	v, ok := obj[key]
	if !ok {
		return "", nil
	}
	return asString(v, what+"."+key, max, 1)
}

// ParseApprovalSubject validates a decrypted (or to-be-sealed) subject.
func ParseApprovalSubject(v any) (ApprovalSubject, error) {
	const what = "approval subject"
	obj, err := asObject(v, what)
	if err != nil {
		return ApprovalSubject{}, err
	}
	if err := exactKeys(obj, []string{"secret", "agent", "fingerprint", "max_ttl_s"}, what, "project", "purpose", "reason"); err != nil {
		return ApprovalSubject{}, err
	}
	var s ApprovalSubject
	if s.Fingerprint, err = asPrintableASCII(obj["fingerprint"], what+".fingerprint", approvalFingerprintN, approvalFingerprintN); err != nil {
		return ApprovalSubject{}, err
	}
	if !approvalFingerprint.MatchString(s.Fingerprint) {
		return ApprovalSubject{}, badRequest("%s.fingerprint must be sha256:<64 hex>", what)
	}
	if s.Secret, err = asString(obj["secret"], what+".secret", MaxItemNameLength, 1); err != nil {
		return ApprovalSubject{}, err
	}
	if s.Agent, err = asPrintableASCII(obj["agent"], what+".agent", 1, maxApprovalAgent); err != nil {
		return ApprovalSubject{}, err
	}
	if s.MaxTTLS, err = asInt(obj["max_ttl_s"], what+".max_ttl_s", ApprovalMinTTLS, ApprovalMaxTTLS); err != nil {
		return ApprovalSubject{}, err
	}
	if s.Project, err = optionalApprovalText(obj, "project", maxApprovalProject, what); err != nil {
		return ApprovalSubject{}, err
	}
	if s.Purpose, err = optionalApprovalText(obj, "purpose", maxApprovalPurpose, what); err != nil {
		return ApprovalSubject{}, err
	}
	if s.Reason, err = optionalApprovalText(obj, "reason", maxApprovalReason, what); err != nil {
		return ApprovalSubject{}, err
	}
	return s, nil
}

// ParseApprovalRequest structurally validates an untrusted request (no
// signature or AEAD check).
func ParseApprovalRequest(v any) (ApprovalRequest, error) {
	const what = "approval request"
	obj, err := asObject(v, what)
	if err != nil {
		return ApprovalRequest{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return ApprovalRequest{}, err
	}
	if obj["alg"] != AlgApproval {
		return ApprovalRequest{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "request_id", "vault_id", "key_epoch", "requester", "n", "ct", "ts", "expires_at", "sig"}, what); err != nil {
		return ApprovalRequest{}, err
	}
	var w ApprovalRequest
	if w.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
		return ApprovalRequest{}, err
	}
	if ct, _ := B64Decode(w.Ct); len(ct) < TagBytes || len(ct) > maxSubjectPlaintext+TagBytes {
		return ApprovalRequest{}, badRequest("%s.ct length out of range", what)
	}
	if w.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return ApprovalRequest{}, err
	}
	if w.ExpiresAt, err = asUint(obj["expires_at"], what+".expires_at"); err != nil {
		return ApprovalRequest{}, err
	}
	if w.ExpiresAt <= w.TS {
		return ApprovalRequest{}, badRequest("%s.expires_at must be after ts", what)
	}
	if w.RequestID, err = asID(obj["request_id"], what+".request_id"); err != nil {
		return ApprovalRequest{}, err
	}
	if w.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return ApprovalRequest{}, err
	}
	if w.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return ApprovalRequest{}, err
	}
	if w.Requester, err = asID(obj["requester"], what+".requester"); err != nil {
		return ApprovalRequest{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return ApprovalRequest{}, err
	}
	if w.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return ApprovalRequest{}, err
	}
	return w, nil
}

// SealApprovalRequestArgs configures SealApprovalRequest. RequestID is empty
// in production; the nonce is unexported so only vector tests can fix it.
type SealApprovalRequestArgs struct {
	VK         []byte // VK[KeyEpoch]
	SignSecret []byte // the requester's Ed25519 seed
	VaultID    string
	KeyEpoch   int64
	Requester  string
	RequestID  string
	TS         int64
	ExpiresAt  int64
	Subject    ApprovalSubject

	nonce []byte
}

// SealApprovalRequest encrypts the subject under VK[e] and signs the request.
func SealApprovalRequest(args SealApprovalRequestArgs) (ApprovalRequest, error) {
	subject, err := ParseApprovalSubject(args.Subject.JSONValue())
	if err != nil {
		return ApprovalRequest{}, err
	}
	pt, err := CJSON(subject)
	if err != nil {
		return ApprovalRequest{}, err
	}
	if len(pt) > maxSubjectPlaintext {
		return ApprovalRequest{}, badRequest("approval subject exceeds %d bytes", maxSubjectPlaintext)
	}
	requestID := args.RequestID
	if requestID == "" {
		requestID = RandomID()
	}
	nonce := args.nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	w := ApprovalRequest{
		RequestID: requestID, VaultID: args.VaultID, KeyEpoch: args.KeyEpoch, Requester: args.Requester, N: B64Encode(nonce),
		Ct: B64Encode(make([]byte, TagBytes)), TS: args.TS, ExpiresAt: args.ExpiresAt, Sig: B64Encode(make([]byte, 64)),
	}
	if w, err = ParseApprovalRequest(w); err != nil {
		return ApprovalRequest{}, err
	}
	key, err := approvalSubjectKey(args.VK, w.RequestID)
	if err != nil {
		return ApprovalRequest{}, err
	}
	ct, err := XC20PSeal(key, nonce, pt, approvalAAD(w))
	if err != nil {
		return ApprovalRequest{}, err
	}
	w.Ct = B64Encode(ct)
	if w.Sig, err = SignDetached(ContextApprovalRequest, w.unsigned(), args.SignSecret); err != nil {
		return ApprovalRequest{}, err
	}
	return w, nil
}

// OpenApprovalRequest verifies and opens an untrusted request in the order of
// spec §3.13: shape, vault_id, requester signature (invalid_signature), AEAD
// (decrypt_failed), subject (bad_request).
func OpenApprovalRequest(vk []byte, wire any, vaultID, requesterSignPub string) (ApprovalRequest, ApprovalSubject, error) {
	w, err := ParseApprovalRequest(wire)
	if err != nil {
		return ApprovalRequest{}, ApprovalSubject{}, err
	}
	if w.VaultID != vaultID {
		return ApprovalRequest{}, ApprovalSubject{}, badRequest("approval request belongs to another vault")
	}
	if err := VerifyObject(ContextApprovalRequest, w.JSONValue(), requesterSignPub); err != nil {
		return ApprovalRequest{}, ApprovalSubject{}, err
	}
	key, err := approvalSubjectKey(vk, w.RequestID)
	if err != nil {
		return ApprovalRequest{}, ApprovalSubject{}, err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	pt, err := XC20POpen(key, nonce, ct, approvalAAD(w))
	if err != nil {
		return ApprovalRequest{}, ApprovalSubject{}, err
	}
	v, err := CJSONParse(pt)
	if err != nil {
		return ApprovalRequest{}, ApprovalSubject{}, err
	}
	s, err := ParseApprovalSubject(v)
	if err != nil {
		return ApprovalRequest{}, ApprovalSubject{}, err
	}
	return w, s, nil
}

// ApprovalRequestDigest is b64(SHA-256(cjson(request wire, sig included))).
func ApprovalRequestDigest(wire any) (string, error) {
	w, err := ParseApprovalRequest(wire)
	if err != nil {
		return "", err
	}
	b, err := CJSON(w)
	if err != nil {
		return "", err
	}
	return SHA256B64(b), nil
}

// ApprovalDecision is the signed decision wire object. TTLS is 0 unless the
// decision is allow_ttl.
type ApprovalDecision struct {
	RequestID     string
	VaultID       string
	Requester     string
	RequestDigest string
	Decision      string
	TTLS          int64
	Approver      string
	TS            int64
	Sig           string
}

func (d ApprovalDecision) unsigned() map[string]any {
	m := map[string]any{
		"v": int64(1), "request_id": d.RequestID, "vault_id": d.VaultID, "requester": d.Requester,
		"request_digest": d.RequestDigest, "decision": d.Decision, "approver": d.Approver, "ts": d.TS,
	}
	if d.Decision == ApprovalAllowTTL {
		m["ttl_s"] = d.TTLS
	}
	return m
}

// JSONValue returns the wire object.
func (d ApprovalDecision) JSONValue() any {
	m := d.unsigned()
	m["sig"] = d.Sig
	return m
}

// ParseApprovalDecision structurally validates an untrusted decision.
func ParseApprovalDecision(v any) (ApprovalDecision, error) {
	const what = "approval decision"
	obj, err := asObject(v, what)
	if err != nil {
		return ApprovalDecision{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return ApprovalDecision{}, err
	}
	var d ApprovalDecision
	if d.Decision, err = asEnum(obj["decision"], ApprovalDecisions, what+".decision"); err != nil {
		return ApprovalDecision{}, err
	}
	keys := []string{"v", "request_id", "vault_id", "requester", "request_digest", "decision", "approver", "ts", "sig"}
	if d.Decision == ApprovalAllowTTL {
		keys = append(keys, "ttl_s")
	}
	if err := exactKeys(obj, keys, what); err != nil {
		return ApprovalDecision{}, err
	}
	if d.RequestID, err = asID(obj["request_id"], what+".request_id"); err != nil {
		return ApprovalDecision{}, err
	}
	if d.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return ApprovalDecision{}, err
	}
	if d.Requester, err = asID(obj["requester"], what+".requester"); err != nil {
		return ApprovalDecision{}, err
	}
	if d.RequestDigest, err = asB64(obj["request_digest"], what+".request_digest", 32); err != nil {
		return ApprovalDecision{}, err
	}
	if d.Approver, err = asID(obj["approver"], what+".approver"); err != nil {
		return ApprovalDecision{}, err
	}
	if d.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return ApprovalDecision{}, err
	}
	if d.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return ApprovalDecision{}, err
	}
	if d.Decision == ApprovalAllowTTL {
		if d.TTLS, err = asInt(obj["ttl_s"], what+".ttl_s", ApprovalMinTTLS, ApprovalMaxTTLS); err != nil {
			return ApprovalDecision{}, err
		}
	}
	return d, nil
}

// SignApprovalDecision answers request with the approving device's seed.
// ttlS is required for allow_ttl and must be 0 otherwise.
func SignApprovalDecision(signSecret []byte, request any, decision string, ttlS int64, approver string, ts int64) (ApprovalDecision, error) {
	r, err := ParseApprovalRequest(request)
	if err != nil {
		return ApprovalDecision{}, err
	}
	if (decision == ApprovalAllowTTL) != (ttlS != 0) {
		return ApprovalDecision{}, badRequest("ttl_s is required for allow_ttl and refused otherwise")
	}
	digest, err := ApprovalRequestDigest(r)
	if err != nil {
		return ApprovalDecision{}, err
	}
	d := ApprovalDecision{RequestID: r.RequestID, VaultID: r.VaultID, Requester: r.Requester, RequestDigest: digest, Decision: decision, TTLS: ttlS, Approver: approver, TS: ts, Sig: B64Encode(make([]byte, 64))}
	if d, err = ParseApprovalDecision(d); err != nil {
		return ApprovalDecision{}, err
	}
	if d.Sig, err = SignDetached(ContextApprovalDecision, d.unsigned(), signSecret); err != nil {
		return ApprovalDecision{}, err
	}
	return d, nil
}

// VerifyApprovalDecision checks a decision against the request it answers in
// the order of spec §3.13. maxTTLS 0 skips the max_ttl_s check (a verifier that
// did not open the request); the requesting device always passes it.
func VerifyApprovalDecision(decision, request any, approverSignPub string, maxTTLS int64) (ApprovalDecision, error) {
	d, err := ParseApprovalDecision(decision)
	if err != nil {
		return ApprovalDecision{}, err
	}
	r, err := ParseApprovalRequest(request)
	if err != nil {
		return ApprovalDecision{}, err
	}
	if d.RequestID != r.RequestID || d.VaultID != r.VaultID || d.Requester != r.Requester {
		return ApprovalDecision{}, badRequest("approval decision answers another request")
	}
	digest, err := ApprovalRequestDigest(r)
	if err != nil {
		return ApprovalDecision{}, err
	}
	if d.RequestDigest != digest {
		return ApprovalDecision{}, badRequest("approval decision binds another request body")
	}
	if d.TS < r.TS || d.TS >= r.ExpiresAt {
		return ApprovalDecision{}, badRequest("approval decision is outside the request lifetime")
	}
	if maxTTLS != 0 && d.TTLS > maxTTLS {
		return ApprovalDecision{}, badRequest("approval decision exceeds the requested max_ttl_s")
	}
	if err := VerifyObject(ContextApprovalDecision, d.JSONValue(), approverSignPub); err != nil {
		return ApprovalDecision{}, err
	}
	return d, nil
}
