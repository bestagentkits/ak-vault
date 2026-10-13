package akv1

import (
	"errors"
	"regexp"
	"strings"
)

// Transport proof limits (spec §9.2).
const (
	ProofMaxSkewMs = 60000
	ProofJTITTLMs  = 120000
	maxProofHeader = 4096
)

var htmPattern = regexp.MustCompile(`^[A-Z]{1,16}$`)

// TransportProof is {"htm","htu","ts","jti","ath","bh"}; ath/bh are b64
// sha256 of the bearer token / request body, ts is unix milliseconds.
type TransportProof struct {
	HTM string
	HTU string
	TS  int64
	JTI string
	ATH string
	BH  string
}

// JSONValue returns the proof object.
func (p TransportProof) JSONValue() any {
	return map[string]any{"htm": p.HTM, "htu": p.HTU, "ts": p.TS, "jti": p.JTI, "ath": p.ATH, "bh": p.BH}
}

// BuildProofArgs configures BuildProof. JTI is "" in production (16 random
// bytes); tests inject a fixed value.
type BuildProofArgs struct {
	HTM       string
	HTU       string
	TS        int64
	Token     string
	Body      []byte
	SecretKey []byte // Ed25519 seed of the device named by the token "did"
	JTI       string
}

func parseProofObject(v any) (TransportProof, error) {
	obj, err := asObject(v, "proof")
	if err != nil {
		return TransportProof{}, err
	}
	if err := exactKeys(obj, []string{"htm", "htu", "ts", "jti", "ath", "bh"}, "proof"); err != nil {
		return TransportProof{}, err
	}
	var p TransportProof
	if p.HTM, err = asString(obj["htm"], "proof.htm", 16, 1); err != nil {
		return TransportProof{}, err
	}
	if !htmPattern.MatchString(p.HTM) {
		return TransportProof{}, badRequest("proof.htm must be an uppercase method")
	}
	if p.HTU, err = asString(obj["htu"], "proof.htu", 2048, 1); err != nil {
		return TransportProof{}, err
	}
	if p.TS, err = asUint(obj["ts"], "proof.ts"); err != nil {
		return TransportProof{}, err
	}
	if p.JTI, err = asID(obj["jti"], "proof.jti"); err != nil {
		return TransportProof{}, err
	}
	if p.ATH, err = asB64(obj["ath"], "proof.ath", 32); err != nil {
		return TransportProof{}, err
	}
	if p.BH, err = asB64(obj["bh"], "proof.bh", 32); err != nil {
		return TransportProof{}, err
	}
	return p, nil
}

// BuildProof returns the AKV-Proof header value `b64(cjson(proof)) "." b64(sig)`.
func BuildProof(a BuildProofArgs) (string, error) {
	jti := a.JTI
	if jti == "" {
		jti = RandomID()
	}
	proof := TransportProof{HTM: a.HTM, HTU: a.HTU, TS: a.TS, JTI: jti, ATH: SHA256B64([]byte(a.Token)), BH: SHA256B64(a.Body)}
	if _, err := parseProofObject(proof); err != nil {
		return "", err
	}
	blob, err := CJSON(proof)
	if err != nil {
		return "", err
	}
	sig, err := SignDetached(ContextProof, proof, a.SecretKey)
	if err != nil {
		return "", err
	}
	return B64Encode(blob) + "." + sig, nil
}

// DecodeProof decodes a header without verifying it. Any malformed input
// (including a non-canonical proof blob) is CodeUnauthorized.
func DecodeProof(header string) (TransportProof, string, error) {
	p, sig, err := decodeProof(header)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return TransportProof{}, "", newErr(CodeUnauthorized, "malformed proof")
		}
		return TransportProof{}, "", err
	}
	return p, sig, nil
}

func decodeProof(header string) (TransportProof, string, error) {
	if utf16Len(header) > maxProofHeader {
		return TransportProof{}, "", badRequest("proof header too long")
	}
	parts := strings.Split(header, ".")
	if len(parts) != 2 {
		return TransportProof{}, "", badRequest("proof header must have two parts")
	}
	blob, err := B64Decode(parts[0])
	if err != nil {
		return TransportProof{}, "", err
	}
	v, err := CJSONParse(blob)
	if err != nil {
		return TransportProof{}, "", err
	}
	p, err := parseProofObject(v)
	if err != nil {
		return TransportProof{}, "", err
	}
	sig, err := asB64(parts[1], "proof sig", 64)
	if err != nil {
		return TransportProof{}, "", err
	}
	return p, sig, nil
}

// VerifyProofOptions configures VerifyProof.
type VerifyProofOptions struct {
	HTM     string
	HTU     string
	Token   string
	Body    []byte
	NowMs   int64  // current time, unix ms
	SignPub []byte // Ed25519 public key of the device named by the token "did"
	// MaxSkewMs defaults to ProofMaxSkewMs when zero.
	MaxSkewMs int64
	// IsReplay reports whether the jti was already used by the device within
	// its TTL. Nil means no replay cache (callers MUST provide one in servers).
	IsReplay func(jti string) bool
}

// VerifyProof verifies an AKV-Proof header. A bad signature is
// CodeInvalidSignature; everything else (malformed, wrong htm/htu, outside the
// time window, wrong ath/bh, replayed jti) is CodeUnauthorized.
func VerifyProof(header string, o VerifyProofOptions) (TransportProof, error) {
	p, sig, err := DecodeProof(header)
	if err != nil {
		return TransportProof{}, err
	}
	if !VerifyDetached(ContextProof, p, sig, o.SignPub) {
		return TransportProof{}, newErr(CodeInvalidSignature, "proof signature verification failed")
	}
	if p.HTM != o.HTM {
		return TransportProof{}, newErr(CodeUnauthorized, "proof htm mismatch")
	}
	if p.HTU != o.HTU {
		return TransportProof{}, newErr(CodeUnauthorized, "proof htu mismatch")
	}
	skew := o.MaxSkewMs
	if skew == 0 {
		skew = ProofMaxSkewMs
	}
	diff := o.NowMs - p.TS
	if diff < 0 {
		diff = -diff
	}
	if diff > skew {
		return TransportProof{}, newErr(CodeUnauthorized, "proof outside the time window")
	}
	if p.ATH != SHA256B64([]byte(o.Token)) {
		return TransportProof{}, newErr(CodeUnauthorized, "proof is not bound to this token")
	}
	if p.BH != SHA256B64(o.Body) {
		return TransportProof{}, newErr(CodeUnauthorized, "proof is not bound to this body")
	}
	if o.IsReplay != nil && o.IsReplay(p.JTI) {
		return TransportProof{}, newErr(CodeUnauthorized, "proof jti replayed")
	}
	return p, nil
}
