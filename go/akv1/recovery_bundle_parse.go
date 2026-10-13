package akv1

import (
	"regexp"
	"strconv"
)

// Recovery bundle wire types and untrusted-input parsers (spec §3.4, §11 "Recovery bundle").
//
//	wire      = {v:1, vault_id, bundle_seq, pw, rk, env (kid "bk")}
//	pw        = {v:1, alg:"argon2id-xc20p", s, t, m, p, n, ct}   wraps the 32-byte bundle key BK
//	rk        = {v:1, alg:"rk-xc20p", n, ct}
//	plaintext = cjson({v:1, vault_id, bundle_seq, vk:{"<epoch>":b64}, owner_sign_pub, recovery_sign_sk, checkpoint})

// BundleEnvelopeKid is the envelope kid of the recovery bundle ciphertext.
const BundleEnvelopeKid = "bk"

// MaxBundleEpochs bounds the vault keys carried in a bundle.
const MaxBundleEpochs = 10000

var epochKeyPattern = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)

// BundlePasswordWrap wraps BK under KEK_pw (no key_epoch field).
type BundlePasswordWrap struct {
	S      string
	Params ArgonParams
	N      string
	Ct     string
}

// JSONValue returns the wire object.
func (w BundlePasswordWrap) JSONValue() any {
	return map[string]any{"v": int64(1), "alg": "argon2id-xc20p", "s": w.S, "t": w.Params.T, "m": w.Params.M, "p": w.Params.P, "n": w.N, "ct": w.Ct}
}

// BundleRecoveryWrap wraps BK under KEK_rk.
type BundleRecoveryWrap struct {
	N  string
	Ct string
}

// JSONValue returns the wire object.
func (w BundleRecoveryWrap) JSONValue() any {
	return map[string]any{"v": int64(1), "alg": "rk-xc20p", "n": w.N, "ct": w.Ct}
}

// RecoveryBundle is the opaque bundle stored by the server.
type RecoveryBundle struct {
	VaultID   string
	BundleSeq int64
	PW        BundlePasswordWrap
	RK        BundleRecoveryWrap
	Env       Envelope
}

// JSONValue returns the wire object.
func (b RecoveryBundle) JSONValue() any {
	return map[string]any{"v": int64(1), "vault_id": b.VaultID, "bundle_seq": b.BundleSeq, "pw": b.PW.JSONValue(), "rk": b.RK.JSONValue(), "env": b.Env.JSONValue()}
}

// recoveryBundlePlaintext is the decrypted bundle content (vk values are b64).
type recoveryBundlePlaintext struct {
	VaultID        string
	BundleSeq      int64
	VK             map[string]string
	OwnerSignPub   string
	RecoverySignSK string
	Checkpoint     Checkpoint
}

func (p recoveryBundlePlaintext) JSONValue() any {
	vk := make(map[string]any, len(p.VK))
	for k, v := range p.VK {
		vk[k] = v
	}
	return map[string]any{
		"v": int64(1), "vault_id": p.VaultID, "bundle_seq": p.BundleSeq, "vk": vk,
		"owner_sign_pub": p.OwnerSignPub, "recovery_sign_sk": p.RecoverySignSK, "checkpoint": p.Checkpoint.JSONValue(),
	}
}

func parseBundlePW(v any, what string) (BundlePasswordWrap, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return BundlePasswordWrap{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return BundlePasswordWrap{}, err
	}
	if obj["alg"] != "argon2id-xc20p" {
		return BundlePasswordWrap{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "s", "t", "m", "p", "n", "ct"}, what); err != nil {
		return BundlePasswordWrap{}, err
	}
	if err := validateArgonValues(obj["t"], obj["m"], obj["p"]); err != nil {
		return BundlePasswordWrap{}, err
	}
	var w BundlePasswordWrap
	w.Params.T, _ = toInt(obj["t"])
	w.Params.M, _ = toInt(obj["m"])
	w.Params.P, _ = toInt(obj["p"])
	if w.S, err = asB64(obj["s"], what+".s", SaltBytes); err != nil {
		return BundlePasswordWrap{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return BundlePasswordWrap{}, err
	}
	if w.Ct, err = asB64(obj["ct"], what+".ct", wrappedKeyCtBytes); err != nil {
		return BundlePasswordWrap{}, err
	}
	return w, nil
}

func parseBundleRK(v any, what string) (BundleRecoveryWrap, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return BundleRecoveryWrap{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return BundleRecoveryWrap{}, err
	}
	if obj["alg"] != "rk-xc20p" {
		return BundleRecoveryWrap{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "n", "ct"}, what); err != nil {
		return BundleRecoveryWrap{}, err
	}
	var w BundleRecoveryWrap
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return BundleRecoveryWrap{}, err
	}
	if w.Ct, err = asB64(obj["ct"], what+".ct", wrappedKeyCtBytes); err != nil {
		return BundleRecoveryWrap{}, err
	}
	return w, nil
}

// ParseRecoveryBundle validates an untrusted bundle wire object (including
// the Argon2id bounds) before any KDF work.
func ParseRecoveryBundle(v any) (RecoveryBundle, error) {
	const what = "recovery bundle"
	obj, err := asObject(v, what)
	if err != nil {
		return RecoveryBundle{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return RecoveryBundle{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "bundle_seq", "pw", "rk", "env"}, what); err != nil {
		return RecoveryBundle{}, err
	}
	var b RecoveryBundle
	if b.Env, err = parseEnvelopeAs(obj["env"], what+".env"); err != nil {
		return RecoveryBundle{}, err
	}
	if b.Env.Kid != BundleEnvelopeKid {
		return RecoveryBundle{}, badRequest(`%s.env.kid must be "bk"`, what)
	}
	if b.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return RecoveryBundle{}, err
	}
	if b.BundleSeq, err = asInt(obj["bundle_seq"], what+".bundle_seq", 1, MaxSafeInteger); err != nil {
		return RecoveryBundle{}, err
	}
	if b.PW, err = parseBundlePW(obj["pw"], what+".pw"); err != nil {
		return RecoveryBundle{}, err
	}
	if b.RK, err = parseBundleRK(obj["rk"], what+".rk"); err != nil {
		return RecoveryBundle{}, err
	}
	return b, nil
}

// parseVKMap validates 1..MaxBundleEpochs entries with decimal epoch keys >= 1
// (no leading zeros, at most 2^53-1) and 32-byte b64 values.
func parseVKMap(v any, what string) (map[string]string, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return nil, err
	}
	if len(obj) == 0 || len(obj) > MaxBundleEpochs {
		return nil, badRequest("%s must hold 1..%d epochs", what, MaxBundleEpochs)
	}
	out := make(map[string]string, len(obj))
	for k, val := range obj {
		n, convErr := strconv.ParseInt(k, 10, 64)
		if !epochKeyPattern.MatchString(k) || convErr != nil || n > MaxSafeInteger {
			return nil, badRequest("%s has an invalid epoch key", what)
		}
		if out[k], err = asB64(val, what+".epoch", KeyBytes); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func parseRecoveryBundlePlaintext(v any) (recoveryBundlePlaintext, error) {
	const what = "recovery bundle plaintext"
	obj, err := asObject(v, what)
	if err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "bundle_seq", "vk", "owner_sign_pub", "recovery_sign_sk", "checkpoint"}, what); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	var p recoveryBundlePlaintext
	if p.VK, err = parseVKMap(obj["vk"], what+".vk"); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if p.Checkpoint, err = ParseCheckpoint(obj["checkpoint"]); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if _, ok := p.VK[strconv.FormatInt(p.Checkpoint.KeyEpoch, 10)]; !ok {
		return recoveryBundlePlaintext{}, badRequest("%s.vk lacks the checkpoint key_epoch", what)
	}
	if p.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if p.BundleSeq, err = asInt(obj["bundle_seq"], what+".bundle_seq", 1, MaxSafeInteger); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if p.OwnerSignPub, err = asB64(obj["owner_sign_pub"], what+".owner_sign_pub", KeyBytes); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	if p.RecoverySignSK, err = asB64(obj["recovery_sign_sk"], what+".recovery_sign_sk", KeyBytes); err != nil {
		return recoveryBundlePlaintext{}, err
	}
	return p, nil
}
