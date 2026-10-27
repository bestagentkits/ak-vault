package akv1

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// Committed device enrollment (spec §3.9). The joiner commits to nonce_j in
// its join code, the owner device answers with an offer that reveals nonce_i,
// and only then the joiner reveals nonce_j. A party that substitutes the join
// must fix its key and nonce before it knows nonce_i, so a six-digit SAS
// cannot be ground offline. The SAS also covers the vault origin and the
// trust anchor.

// Code prefixes and contexts of the committed enrollment.
const (
	Join2CodePrefix   = "akj2-"
	Offer2CodePrefix  = "ako2-"
	Reveal2CodePrefix = "akr2-"

	Join2CodeContext   = "akv1/enroll-join"
	Offer2CodeContext  = "akv1/enroll-offer"
	Reveal2CodeContext = "akv1/enroll-reveal"

	// NonceJCommitContext domain-separates the nonce_j commitment.
	NonceJCommitContext = "akv1/enroll-nonce-j"
	// SAS2Context domain-separates the committed-enrollment SAS transcript.
	SAS2Context = "akv1/sas2"
)

var (
	join2CodeKeys   = []string{"v", "ctx", "account", "device", "nonce_j_commit", "label"}
	offer2CodeKeys  = []string{"v", "ctx", "vault_origin", "vault_id", "initiator", "joiner", "nonce_i", "nonce_j_commit", "trust_anchor", "checkpoint"}
	reveal2CodeKeys = []string{"v", "ctx", "vault_id", "joiner", "nonce_j"}
)

// Join2Code is the content of a committed join code.
type Join2Code struct {
	Account      string
	Device       DeviceRecord
	NonceJCommit string // b64 sha256, see NonceJCommit
	Label        string
}

// JSONValue returns the code object.
func (j Join2Code) JSONValue() any {
	return map[string]any{
		"v": int64(1), "ctx": Join2CodeContext, "account": j.Account, "device": j.Device.JSONValue(),
		"nonce_j_commit": j.NonceJCommit, "label": j.Label,
	}
}

// Offer2Code is the content of a committed offer code.
type Offer2Code struct {
	VaultOrigin  string
	VaultID      string
	Initiator    string
	Joiner       string
	NonceI       string
	NonceJCommit string
	TrustAnchor  string
	Checkpoint   Checkpoint
}

// JSONValue returns the code object.
func (o Offer2Code) JSONValue() any {
	return map[string]any{
		"v": int64(1), "ctx": Offer2CodeContext, "vault_origin": o.VaultOrigin, "vault_id": o.VaultID,
		"initiator": o.Initiator, "joiner": o.Joiner, "nonce_i": o.NonceI, "nonce_j_commit": o.NonceJCommit,
		"trust_anchor": o.TrustAnchor, "checkpoint": o.Checkpoint.JSONValue(),
	}
}

// Reveal2Code is the content of a reveal code.
type Reveal2Code struct {
	VaultID string
	Joiner  string
	NonceJ  string
}

// JSONValue returns the code object.
func (r Reveal2Code) JSONValue() any {
	return map[string]any{"v": int64(1), "ctx": Reveal2CodeContext, "vault_id": r.VaultID, "joiner": r.Joiner, "nonce_j": r.NonceJ}
}

// NonceJCommit returns b64(sha256(cjson({ctx:"akv1/enroll-nonce-j", nonce_j}))).
func NonceJCommit(nonceJ string) (string, error) {
	if _, err := asB64(nonceJ, "nonce_j", sasNonceBytes); err != nil {
		return "", err
	}
	body, err := CJSON(map[string]any{"ctx": NonceJCommitContext, "nonce_j": nonceJ})
	if err != nil {
		return "", err
	}
	return SHA256B64(body), nil
}

// VerifyNonceJReveal checks a revealed nonce_j against its commitment. A
// mismatch is forbidden and the initiator must not compute a SAS from it.
func VerifyNonceJReveal(commit, nonceJ string) error {
	if _, err := asB64(commit, "nonce_j_commit", KeyBytes); err != nil {
		return err
	}
	want, err := NonceJCommit(nonceJ)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(commit), []byte(want)) != 1 {
		return newErr(CodeForbidden, "nonce_j does not match its commitment")
	}
	return nil
}

// SAS2Input is the committed-enrollment SAS input (spec §3.9).
type SAS2Input struct {
	VaultID     string
	VaultOrigin string
	TrustAnchor string // b64 32-byte Ed25519 sign_pub of the genesis author
	Initiator   string
	Joiner      any // full device record of the joining device
	NonceI      string
	NonceJ      string
}

// SAS2Transcript returns the committed-enrollment SAS transcript.
func SAS2Transcript(in SAS2Input) ([]byte, error) {
	if err := ValidateVaultOrigin(in.VaultOrigin); err != nil {
		return nil, err
	}
	if _, err := asID(in.VaultID, "vault_id"); err != nil {
		return nil, err
	}
	if _, err := asB64(in.TrustAnchor, "trust_anchor", KeyBytes); err != nil {
		return nil, err
	}
	if _, err := asID(in.Initiator, "initiator"); err != nil {
		return nil, err
	}
	joiner, err := parseDeviceAs(in.Joiner, "joiner")
	if err != nil {
		return nil, err
	}
	if _, err := asB64(in.NonceI, "nonce_i", sasNonceBytes); err != nil {
		return nil, err
	}
	if _, err := asB64(in.NonceJ, "nonce_j", sasNonceBytes); err != nil {
		return nil, err
	}
	return CJSON(map[string]any{
		"ctx": SAS2Context, "vault_id": in.VaultID, "vault_origin": in.VaultOrigin, "trust_anchor": in.TrustAnchor,
		"initiator": in.Initiator, "joiner": joiner, "nonce_i": in.NonceI, "nonce_j": in.NonceJ,
	})
}

// SAS2Code returns the six-digit code both devices display.
func SAS2Code(in SAS2Input) (string, error) {
	t, err := SAS2Transcript(in)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(SHA256(t)[:4])%1_000_000), nil
}

// SAS2Digest returns b64(sha256(transcript)), the value of device_add.body.sas.
func SAS2Digest(in SAS2Input) (string, error) {
	t, err := SAS2Transcript(in)
	if err != nil {
		return "", err
	}
	return SHA256B64(t), nil
}

// EncodeJoin2Code applies the ParseJoin2Code checks and returns the code.
func EncodeJoin2Code(j Join2Code) (string, error) {
	return encodeEnrollCode(Join2CodePrefix, j, func(obj map[string]any) error {
		_, err := parseJoin2Object(obj)
		return err
	})
}

// EncodeOffer2Code applies the ParseOffer2Code checks and returns the code.
func EncodeOffer2Code(o Offer2Code) (string, error) {
	return encodeEnrollCode(Offer2CodePrefix, o, func(obj map[string]any) error {
		_, err := parseOffer2Object(obj)
		return err
	})
}

// EncodeReveal2Code applies the ParseReveal2Code checks and returns the code.
func EncodeReveal2Code(r Reveal2Code) (string, error) {
	return encodeEnrollCode(Reveal2CodePrefix, r, func(obj map[string]any) error {
		_, err := parseReveal2Object(obj)
		return err
	})
}

// ParseJoin2Code parses a committed join code (spec §3.9, rules of §3.8).
func ParseJoin2Code(code string) (Join2Code, error) {
	obj, err := decodeEnrollCode(code, Join2CodePrefix, join2CodeKeys, Join2CodeContext)
	if err != nil {
		return Join2Code{}, err
	}
	return parseJoin2Object(obj)
}

// ParseOffer2Code parses a committed offer code (spec §3.9, rules of §3.8).
func ParseOffer2Code(code string) (Offer2Code, error) {
	obj, err := decodeEnrollCode(code, Offer2CodePrefix, offer2CodeKeys, Offer2CodeContext)
	if err != nil {
		return Offer2Code{}, err
	}
	return parseOffer2Object(obj)
}

// ParseReveal2Code parses a reveal code (spec §3.9, rules of §3.8).
func ParseReveal2Code(code string) (Reveal2Code, error) {
	obj, err := decodeEnrollCode(code, Reveal2CodePrefix, reveal2CodeKeys, Reveal2CodeContext)
	if err != nil {
		return Reveal2Code{}, err
	}
	return parseReveal2Object(obj)
}

func parseJoin2Object(obj map[string]any) (Join2Code, error) {
	const what = "join code"
	if err := exactKeys(obj, join2CodeKeys, what); err != nil {
		return Join2Code{}, err
	}
	if err := checkCodeHeader(obj, Join2CodeContext); err != nil {
		return Join2Code{}, err
	}
	var j Join2Code
	var err error
	if j.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return Join2Code{}, err
	}
	if j.Device, err = parseDeviceAs(obj["device"], what+".device"); err != nil {
		return Join2Code{}, err
	}
	if j.Device.Account != j.Account || j.Device.Role != RoleOwner || j.Device.Kind != KindHuman {
		return Join2Code{}, badRequest("%s.device must be a human owner device of the account", what)
	}
	if j.NonceJCommit, err = asB64(obj["nonce_j_commit"], what+".nonce_j_commit", KeyBytes); err != nil {
		return Join2Code{}, err
	}
	if j.Label, err = asPrintableASCII(obj["label"], what+".label", 0, MaxDeviceLabelBytes); err != nil {
		return Join2Code{}, err
	}
	return j, nil
}

func parseOffer2Object(obj map[string]any) (Offer2Code, error) {
	const what = "offer code"
	if err := exactKeys(obj, offer2CodeKeys, what); err != nil {
		return Offer2Code{}, err
	}
	if err := checkCodeHeader(obj, Offer2CodeContext); err != nil {
		return Offer2Code{}, err
	}
	var o Offer2Code
	var err error
	origin, ok := obj["vault_origin"].(string)
	if !ok || ValidateVaultOrigin(origin) != nil {
		return Offer2Code{}, badRequest("%s.vault_origin is not a canonical origin", what)
	}
	o.VaultOrigin = origin
	if o.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return Offer2Code{}, err
	}
	if o.Initiator, err = asID(obj["initiator"], what+".initiator"); err != nil {
		return Offer2Code{}, err
	}
	if o.Joiner, err = asID(obj["joiner"], what+".joiner"); err != nil {
		return Offer2Code{}, err
	}
	if o.NonceI, err = asB64(obj["nonce_i"], what+".nonce_i", sasNonceBytes); err != nil {
		return Offer2Code{}, err
	}
	if o.NonceJCommit, err = asB64(obj["nonce_j_commit"], what+".nonce_j_commit", KeyBytes); err != nil {
		return Offer2Code{}, err
	}
	if o.TrustAnchor, err = asB64(obj["trust_anchor"], what+".trust_anchor", KeyBytes); err != nil {
		return Offer2Code{}, err
	}
	if o.Checkpoint, err = ParseCheckpoint(obj["checkpoint"]); err != nil {
		if CodeOf(err) == CodeUnsupportedVersion {
			return Offer2Code{}, badRequest("%s.checkpoint does not parse", what)
		}
		return Offer2Code{}, err
	}
	if o.Checkpoint.VaultID != o.VaultID {
		return Offer2Code{}, badRequest("%s.checkpoint names another vault", what)
	}
	return o, nil
}

func parseReveal2Object(obj map[string]any) (Reveal2Code, error) {
	const what = "reveal code"
	if err := exactKeys(obj, reveal2CodeKeys, what); err != nil {
		return Reveal2Code{}, err
	}
	if err := checkCodeHeader(obj, Reveal2CodeContext); err != nil {
		return Reveal2Code{}, err
	}
	var r Reveal2Code
	var err error
	if r.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return Reveal2Code{}, err
	}
	if r.Joiner, err = asID(obj["joiner"], what+".joiner"); err != nil {
		return Reveal2Code{}, err
	}
	if r.NonceJ, err = asB64(obj["nonce_j"], what+".nonce_j", sasNonceBytes); err != nil {
		return Reveal2Code{}, err
	}
	return r, nil
}
