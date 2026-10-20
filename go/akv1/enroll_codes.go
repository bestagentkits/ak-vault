package akv1

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Enrollment codes (spec §3.8): the join code a new device prints and the
// offer code the approving owner device answers with. Each is a prefix
// followed by b64(cjson(obj)). They carry only public keys, nonces, IDs and a
// signed checkpoint; the six-digit SAS authenticates the exchange.

// Code prefixes and contexts. The contexts keep their agentkit/ prefix
// because shipped CLIs already produce and accept these codes.
const (
	JoinCodePrefix  = "akj1-"
	OfferCodePrefix = "ako1-"

	JoinCodeContext  = "agentkit/akv1-join"
	OfferCodeContext = "agentkit/akv1-offer"

	// MaxEnrollCodeBytes bounds a code after whitespace removal.
	MaxEnrollCodeBytes = 8192
	// MaxDeviceLabelBytes bounds a join code label (printable ASCII).
	MaxDeviceLabelBytes = 64
)

const sasNonceBytes = 16

var (
	joinCodeKeys  = []string{"v", "ctx", "account", "device", "nonce_j", "label"}
	offerCodeKeys = []string{"v", "ctx", "vault_origin", "vault_id", "initiator", "joiner", "nonce_i", "nonce_j", "trust_anchor", "checkpoint"}
)

// JoinCode is the content of a join code.
type JoinCode struct {
	Account string
	Device  DeviceRecord
	NonceJ  string // b64 16 bytes
	Label   string // display text chosen by the joiner
}

// JSONValue returns the code object.
func (j JoinCode) JSONValue() any {
	return map[string]any{
		"v": int64(1), "ctx": JoinCodeContext, "account": j.Account, "device": j.Device.JSONValue(),
		"nonce_j": j.NonceJ, "label": j.Label,
	}
}

// OfferCode is the content of an offer code.
type OfferCode struct {
	VaultOrigin string
	VaultID     string
	Initiator   string
	Joiner      string
	NonceI      string
	NonceJ      string
	TrustAnchor string // b64 Ed25519 sign_pub of the genesis author
	Checkpoint  Checkpoint
}

// JSONValue returns the code object.
func (o OfferCode) JSONValue() any {
	return map[string]any{
		"v": int64(1), "ctx": OfferCodeContext, "vault_origin": o.VaultOrigin, "vault_id": o.VaultID,
		"initiator": o.Initiator, "joiner": o.Joiner, "nonce_i": o.NonceI, "nonce_j": o.NonceJ,
		"trust_anchor": o.TrustAnchor, "checkpoint": o.Checkpoint.JSONValue(),
	}
}

// EncodeJoinCode applies the ParseJoinCode checks and returns the code.
func EncodeJoinCode(j JoinCode) (string, error) {
	return encodeEnrollCode(JoinCodePrefix, j, func(obj map[string]any) error {
		_, err := parseJoinObject(obj)
		return err
	})
}

// EncodeOfferCode applies the ParseOfferCode checks and returns the code.
func EncodeOfferCode(o OfferCode) (string, error) {
	return encodeEnrollCode(OfferCodePrefix, o, func(obj map[string]any) error {
		_, err := parseOfferObject(obj)
		return err
	})
}

func encodeEnrollCode(prefix string, v Valuer, check func(map[string]any) error) (string, error) {
	obj := v.JSONValue().(map[string]any)
	if err := check(obj); err != nil {
		return "", err
	}
	body, err := CJSON(obj)
	if err != nil {
		return "", err
	}
	code := prefix + B64Encode(body)
	if len(code) > MaxEnrollCodeBytes {
		return "", badRequest("enrollment code exceeds %d bytes", MaxEnrollCodeBytes)
	}
	return code, nil
}

// ParseJoinCode parses a join code (spec §3.8). Every failure is bad_request
// except a v other than 1 (unsupported_version). No signature is checked.
func ParseJoinCode(code string) (JoinCode, error) {
	obj, err := decodeEnrollCode(code, JoinCodePrefix, joinCodeKeys, JoinCodeContext)
	if err != nil {
		return JoinCode{}, err
	}
	return parseJoinObject(obj)
}

// ParseOfferCode parses an offer code (spec §3.8). Every failure is
// bad_request except a v other than 1 (unsupported_version). Parsing checks
// no signature: the joiner then verifies the chain from trust_anchor, the
// checkpoint and the SAS digest of its device_add.
func ParseOfferCode(code string) (OfferCode, error) {
	obj, err := decodeEnrollCode(code, OfferCodePrefix, offerCodeKeys, OfferCodeContext)
	if err != nil {
		return OfferCode{}, err
	}
	return parseOfferObject(obj)
}

// decodeEnrollCode runs steps 1–4: remove White_Space, size and prefix,
// canonical object with exactly keys, v, ctx.
func decodeEnrollCode(code, prefix string, keys []string, ctx string) (map[string]any, error) {
	code = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.White_Space, r) {
			return -1
		}
		return r
	}, code)
	if len(code) > MaxEnrollCodeBytes || !strings.HasPrefix(code, prefix) {
		return nil, badRequest("enrollment code is malformed")
	}
	raw, err := B64Decode(code[len(prefix):])
	if err != nil {
		return nil, badRequest("enrollment code is malformed")
	}
	v, err := CJSONParse(raw)
	if err != nil {
		return nil, badRequest("enrollment code is malformed")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, badRequest("enrollment code is malformed")
	}
	if err := exactKeys(obj, keys, "enrollment code"); err != nil {
		return nil, err
	}
	return obj, nil
}

// checkCodeHeader checks v (unsupported_version) and ctx (bad_request).
func checkCodeHeader(obj map[string]any, ctx string) error {
	if err := checkVersion(obj, "enrollment code"); err != nil {
		return err
	}
	if obj["ctx"] != ctx {
		return badRequest("enrollment code has the wrong context")
	}
	return nil
}

func parseJoinObject(obj map[string]any) (JoinCode, error) {
	const what = "join code"
	if err := exactKeys(obj, joinCodeKeys, what); err != nil {
		return JoinCode{}, err
	}
	if err := checkCodeHeader(obj, JoinCodeContext); err != nil {
		return JoinCode{}, err
	}
	var j JoinCode
	var err error
	if j.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return JoinCode{}, err
	}
	if j.Device, err = parseDeviceAs(obj["device"], what+".device"); err != nil {
		return JoinCode{}, err
	}
	if j.Device.Account != j.Account || j.Device.Role != RoleOwner || j.Device.Kind != KindHuman {
		return JoinCode{}, badRequest("%s.device must be a human owner device of the account", what)
	}
	if j.NonceJ, err = asB64(obj["nonce_j"], what+".nonce_j", sasNonceBytes); err != nil {
		return JoinCode{}, err
	}
	if j.Label, err = asPrintableASCII(obj["label"], what+".label", 0, MaxDeviceLabelBytes); err != nil {
		return JoinCode{}, err
	}
	return j, nil
}

func parseOfferObject(obj map[string]any) (OfferCode, error) {
	const what = "offer code"
	if err := exactKeys(obj, offerCodeKeys, what); err != nil {
		return OfferCode{}, err
	}
	if err := checkCodeHeader(obj, OfferCodeContext); err != nil {
		return OfferCode{}, err
	}
	var o OfferCode
	var err error
	origin, ok := obj["vault_origin"].(string)
	if !ok || ValidateVaultOrigin(origin) != nil {
		return OfferCode{}, badRequest("%s.vault_origin is not a canonical origin", what)
	}
	o.VaultOrigin = origin
	if o.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return OfferCode{}, err
	}
	if o.Initiator, err = asID(obj["initiator"], what+".initiator"); err != nil {
		return OfferCode{}, err
	}
	if o.Joiner, err = asID(obj["joiner"], what+".joiner"); err != nil {
		return OfferCode{}, err
	}
	if o.NonceI, err = asB64(obj["nonce_i"], what+".nonce_i", sasNonceBytes); err != nil {
		return OfferCode{}, err
	}
	if o.NonceJ, err = asB64(obj["nonce_j"], what+".nonce_j", sasNonceBytes); err != nil {
		return OfferCode{}, err
	}
	if o.TrustAnchor, err = asB64(obj["trust_anchor"], what+".trust_anchor", KeyBytes); err != nil {
		return OfferCode{}, err
	}
	if o.Checkpoint, err = ParseCheckpoint(obj["checkpoint"]); err != nil {
		if CodeOf(err) == CodeUnsupportedVersion {
			return OfferCode{}, badRequest("%s.checkpoint does not parse", what)
		}
		return OfferCode{}, err
	}
	if o.Checkpoint.VaultID != o.VaultID {
		return OfferCode{}, badRequest("%s.checkpoint names another vault", what)
	}
	return o, nil
}

var (
	originPattern     = regexp.MustCompile(`^(https|http)://(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::([1-9][0-9]{0,4}))?$`)
	loopbackV4Pattern = regexp.MustCompile(`^127\.` + ipv4Octet + `\.` + ipv4Octet + `\.` + ipv4Octet + `$`)
)

const ipv4Octet = `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`

// ValidateVaultOrigin accepts only a canonical origin: https://host[:port]
// with a lowercase scheme and host of [a-z0-9.-] (or a bracketed IPv6
// literal), no empty label, trailing dot, default port, path, query,
// fragment or userinfo; http:// only for localhost, 127.0.0.0/8 or [::1].
// Anything else is bad_request.
func ValidateVaultOrigin(origin string) error {
	invalid := badRequest("vault origin is not canonical")
	if len(origin) > 2048 {
		return invalid
	}
	m := originPattern.FindStringSubmatch(origin)
	if m == nil || strings.Contains(m[2], "..") {
		return invalid
	}
	scheme, host, port := m[1], m[2], m[3]
	if port != "" {
		n, _ := strconv.Atoi(port)
		if n > 65535 || (scheme == "https" && n == 443) || (scheme == "http" && n == 80) {
			return invalid
		}
	}
	if scheme == "http" && host != "localhost" && host != "[::1]" && !loopbackV4Pattern.MatchString(host) {
		return invalid
	}
	return nil
}
