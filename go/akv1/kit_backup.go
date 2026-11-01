package akv1

import (
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Recovery kit backup `argon2id-xc20p-kit` (spec §3.12, ADR 0005): the recovery
// kit encrypted under a separate backup passphrase so the file can sit in a
// mailbox. The TypeScript reference in packages/protocol/src/kit-backup.ts is
// the documented twin; every vector must pass in both.
const (
	KitBackupAlg                           = "argon2id-xc20p-kit"
	KitBackupMaxFileBytes                  = 4096
	KitBackupMinPassphraseCodePoints       = 12
	KitBackupMaxPassphraseBytes            = 1024
	KitBackupMaxOrigin                     = 256
	kitBackupCiphertextMax                 = 1280
	generatedPassphraseBytes               = 20
	kitBackupAADContext                    = "akv1/kit-backup"
	kitBackupKeyInfo                       = "akv1/kit-backup-key"
	kitBackupKeySalt                       = "akv1"
	kitBackupDefaultKiB              int64 = 262144
)

// Argon2id parameters accepted for a kit backup, checked before any KDF work.
var (
	KitBackupArgonDefaults = ArgonParams{T: 3, M: kitBackupDefaultKiB, P: 1}
	KitBackupArgonMin      = ArgonParams{T: 3, M: 65536, P: 1}
	KitBackupArgonMax      = ArgonParams{T: 10, M: 524288, P: 4}
)

// KitBackupKit is the recovery kit; RecoveryKey is the raw 32-byte key as base64url.
type KitBackupKit struct {
	VaultID     string
	Account     string
	VaultOrigin string
	RecoveryKey string
}

// JSONValue returns the kit fields (without the payload version).
func (k KitBackupKit) JSONValue() any {
	return map[string]any{"vault_id": k.VaultID, "account": k.Account, "vault_origin": k.VaultOrigin, "recovery_key": k.RecoveryKey}
}

// KitBackupFile is the attachment: {"v":1,"alg","vault_id","account","recovery_sign_pub","s","t","m","p","n","ct"}.
type KitBackupFile struct {
	VaultID         string
	Account         string
	RecoverySignPub string
	S               string
	Params          ArgonParams
	N               string
	Ct              string
}

// JSONValue returns the wire object.
func (f KitBackupFile) JSONValue() any {
	return map[string]any{
		"v": int64(1), "alg": KitBackupAlg, "vault_id": f.VaultID, "account": f.Account, "recovery_sign_pub": f.RecoverySignPub,
		"s": f.S, "t": f.Params.T, "m": f.Params.M, "p": f.Params.P, "n": f.N, "ct": f.Ct,
	}
}

// KitBackupExpected is what the opener already knows. Account is required;
// an empty VaultID or RecoverySignPub means "not known".
type KitBackupExpected struct {
	Account         string
	VaultID         string
	RecoverySignPub string
}

// KitBackupSealArgs configures SealKitBackup. A zero Params means
// KitBackupArgonDefaults. Salt and Nonce are nil in production (random).
type KitBackupSealArgs struct {
	Kit             KitBackupKit
	RecoverySignPub string
	Passphrase      string
	Params          ArgonParams
	Salt            []byte
	Nonce           []byte
}

// ValidateKitBackupParams returns CodeBadRequest outside the kit-backup Argon2id bounds.
func ValidateKitBackupParams(p ArgonParams) error {
	return validateKitBackupValues(p.T, p.M, p.P)
}

func validateKitBackupValues(t, m, p any) error {
	if _, err := asInt(t, "argon2 t", KitBackupArgonMin.T, KitBackupArgonMax.T); err != nil {
		return err
	}
	if _, err := asInt(m, "argon2 m", KitBackupArgonMin.M, KitBackupArgonMax.M); err != nil {
		return err
	}
	_, err := asInt(p, "argon2 p", KitBackupArgonMin.P, KitBackupArgonMax.P)
	return err
}

// GenerateBackupPassphrase returns 160 bits as 32 Crockford base32 symbols in 8
// groups of 4 joined by "-". It must be entered exactly as shown.
func GenerateBackupPassphrase() string {
	raw := randomBytes(generatedPassphraseBytes)
	symbols := make([]byte, 0, 32)
	var acc uint32
	bits := 0
	for _, b := range raw {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			symbols = append(symbols, crockford[(acc>>(bits-5))&31])
			bits -= 5
		}
		acc &= 1<<bits - 1
	}
	out := make([]byte, 0, 39)
	for i := 0; i < len(symbols); i += 4 {
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, symbols[i:i+4]...)
	}
	return string(out)
}

func normalizeKitPassphrase(passphrase string, seal bool) ([]byte, error) {
	if passphrase == "" || !utf8.ValidString(passphrase) {
		return nil, badRequest("backup passphrase must be a non-empty UTF-8 string")
	}
	if len(passphrase) > 3*KitBackupMaxPassphraseBytes {
		return nil, badRequest("backup passphrase is too long")
	}
	nfc := norm.NFC.String(passphrase)
	if len(nfc) > KitBackupMaxPassphraseBytes {
		return nil, badRequest("backup passphrase is too long")
	}
	if seal && utf8.RuneCountInString(nfc) < KitBackupMinPassphraseCodePoints {
		return nil, badRequest("backup passphrase is too short")
	}
	return []byte(nfc), nil
}

func deriveKitBackupKey(passphrase, salt []byte, p ArgonParams) []byte {
	raw := argon2.IDKey(passphrase, salt, uint32(p.T), uint32(p.M), uint8(p.P), 32)
	return hkdf32(raw, []byte(kitBackupKeySalt), []byte(kitBackupKeyInfo))
}

func kitBackupAAD(vaultID, account, signPub string, p ArgonParams) map[string]any {
	return map[string]any{"ctx": kitBackupAADContext, "vault_id": vaultID, "account": account, "recovery_sign_pub": signPub, "t": p.T, "m": p.M, "p": p.P}
}

// ParseKitBackupKit validates the kit fields (exact keys; the recovery key is 32 bytes).
func ParseKitBackupKit(v any) (KitBackupKit, error) {
	const what = "kit"
	obj, err := asObject(v, what)
	if err != nil {
		return KitBackupKit{}, err
	}
	if err := exactKeys(obj, []string{"vault_id", "account", "vault_origin", "recovery_key"}, what); err != nil {
		return KitBackupKit{}, err
	}
	var k KitBackupKit
	if k.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return KitBackupKit{}, err
	}
	if k.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return KitBackupKit{}, err
	}
	if k.VaultOrigin, err = asPrintableASCII(obj["vault_origin"], what+".vault_origin", 1, KitBackupMaxOrigin); err != nil {
		return KitBackupKit{}, err
	}
	if k.RecoveryKey, err = asB64(obj["recovery_key"], what+".recovery_key", RecoveryKeyBytes); err != nil {
		return KitBackupKit{}, err
	}
	return k, nil
}

// ParseKitBackupFile validates an untrusted backup file object, including the
// Argon2id bounds, before any KDF work.
func ParseKitBackupFile(v any) (KitBackupFile, error) {
	const what = "kit backup"
	obj, err := asObject(v, what)
	if err != nil {
		return KitBackupFile{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return KitBackupFile{}, err
	}
	if obj["alg"] != KitBackupAlg {
		return KitBackupFile{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "vault_id", "account", "recovery_sign_pub", "s", "t", "m", "p", "n", "ct"}, what); err != nil {
		return KitBackupFile{}, err
	}
	if err := validateKitBackupValues(obj["t"], obj["m"], obj["p"]); err != nil {
		return KitBackupFile{}, err
	}
	var f KitBackupFile
	f.Params.T, _ = toInt(obj["t"])
	f.Params.M, _ = toInt(obj["m"])
	f.Params.P, _ = toInt(obj["p"])
	if f.Ct, err = asB64(obj["ct"], what+".ct", -1); err != nil {
		return KitBackupFile{}, err
	}
	if ct, _ := B64Decode(f.Ct); len(ct) < TagBytes || len(ct) > kitBackupCiphertextMax {
		return KitBackupFile{}, badRequest("%s.ct length out of range", what)
	}
	if f.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return KitBackupFile{}, err
	}
	if f.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return KitBackupFile{}, err
	}
	if f.RecoverySignPub, err = asB64(obj["recovery_sign_pub"], what+".recovery_sign_pub", 32); err != nil {
		return KitBackupFile{}, err
	}
	if f.S, err = asB64(obj["s"], what+".s", SaltBytes); err != nil {
		return KitBackupFile{}, err
	}
	if f.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return KitBackupFile{}, err
	}
	return f, nil
}

// SealKitBackup encrypts the kit into the backup file.
func SealKitBackup(args KitBackupSealArgs) (KitBackupFile, error) {
	kit, err := ParseKitBackupKit(args.Kit.JSONValue())
	if err != nil {
		return KitBackupFile{}, err
	}
	signPub, err := asB64(args.RecoverySignPub, "recovery_sign_pub", 32)
	if err != nil {
		return KitBackupFile{}, err
	}
	params := args.Params
	if params == (ArgonParams{}) {
		params = KitBackupArgonDefaults
	}
	if err := ValidateKitBackupParams(params); err != nil {
		return KitBackupFile{}, err
	}
	pass, err := normalizeKitPassphrase(args.Passphrase, true)
	if err != nil {
		return KitBackupFile{}, err
	}
	salt := args.Salt
	if salt == nil {
		salt = randomBytes(SaltBytes)
	}
	if len(salt) != SaltBytes {
		return KitBackupFile{}, badRequest("salt must be 16 bytes")
	}
	nonce := args.Nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	payload, err := CJSON(map[string]any{"v": int64(1), "vault_id": kit.VaultID, "account": kit.Account, "vault_origin": kit.VaultOrigin, "recovery_key": kit.RecoveryKey})
	if err != nil {
		return KitBackupFile{}, err
	}
	ct, err := XC20PSeal(deriveKitBackupKey(pass, salt, params), nonce, []byte(payload), kitBackupAAD(kit.VaultID, kit.Account, signPub, params))
	if err != nil {
		return KitBackupFile{}, err
	}
	return KitBackupFile{VaultID: kit.VaultID, Account: kit.Account, RecoverySignPub: signPub, S: B64Encode(salt), Params: params, N: B64Encode(nonce), Ct: B64Encode(ct)}, nil
}

// KitBackupFileBytes returns the exact bytes to attach or save: canonical JSON.
func KitBackupFileBytes(f KitBackupFile) ([]byte, error) {
	if _, err := ParseKitBackupFile(f.JSONValue()); err != nil {
		return nil, err
	}
	text, err := CJSON(f.JSONValue())
	if err != nil {
		return nil, err
	}
	if len(text) > KitBackupMaxFileBytes {
		return nil, badRequest("kit backup file too large")
	}
	return []byte(text), nil
}

// OpenKitBackup opens a backup file given as []byte or string (JSON text) or as
// a parsed object. Order (spec §3.12): size cap and strict JSON parse; structure,
// version, algorithm and Argon2id bounds before any KDF work; header ≠ expected
// (bad_request, before any KDF work); AEAD failure is CodeDecryptFailed; inner
// payload not canonical, invalid or disagreeing with the header is bad_request.
func OpenKitBackup(input any, passphrase string, expected KitBackupExpected) (KitBackupKit, error) {
	value := input
	switch in := input.(type) {
	case []byte:
		if len(in) > KitBackupMaxFileBytes {
			return KitBackupKit{}, badRequest("kit backup file too large")
		}
		parsed, err := ParseJSON(in)
		if err != nil {
			return KitBackupKit{}, err
		}
		value = parsed
	case string:
		if len(in) > KitBackupMaxFileBytes {
			return KitBackupKit{}, badRequest("kit backup file too large")
		}
		parsed, err := ParseJSON([]byte(in))
		if err != nil {
			return KitBackupKit{}, err
		}
		value = parsed
	}
	f, err := ParseKitBackupFile(value)
	if err != nil {
		return KitBackupKit{}, err
	}
	if _, err := asString(expected.Account, "expected.account", MaxAccountLength, 1); err != nil {
		return KitBackupKit{}, err
	}
	if f.Account != expected.Account {
		return KitBackupKit{}, badRequest("kit backup belongs to another account")
	}
	if expected.VaultID != "" {
		if _, err := asID(expected.VaultID, "expected.vault_id"); err != nil {
			return KitBackupKit{}, err
		}
		if f.VaultID != expected.VaultID {
			return KitBackupKit{}, badRequest("kit backup belongs to another vault")
		}
	}
	if expected.RecoverySignPub != "" {
		if _, err := asB64(expected.RecoverySignPub, "expected.recovery_sign_pub", 32); err != nil {
			return KitBackupKit{}, err
		}
		if f.RecoverySignPub != expected.RecoverySignPub {
			return KitBackupKit{}, badRequest("kit backup is not for the current recovery key")
		}
	}
	pass, err := normalizeKitPassphrase(passphrase, false)
	if err != nil {
		return KitBackupKit{}, err
	}
	salt, _ := B64Decode(f.S)
	nonce, _ := B64Decode(f.N)
	ct, _ := B64Decode(f.Ct)
	pt, err := XC20POpen(deriveKitBackupKey(pass, salt, f.Params), nonce, ct, kitBackupAAD(f.VaultID, f.Account, f.RecoverySignPub, f.Params))
	if err != nil {
		return KitBackupKit{}, err
	}
	parsed, err := CJSONParse(pt)
	if err != nil {
		return KitBackupKit{}, err
	}
	obj, err := asObject(parsed, "kit backup payload")
	if err != nil {
		return KitBackupKit{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "account", "vault_origin", "recovery_key"}, "kit backup payload"); err != nil {
		return KitBackupKit{}, err
	}
	if err := checkVersion(obj, "kit backup payload"); err != nil {
		return KitBackupKit{}, err
	}
	fields := map[string]any{}
	for k, val := range obj {
		if k != "v" {
			fields[k] = val
		}
	}
	kit, err := ParseKitBackupKit(fields)
	if err != nil {
		return KitBackupKit{}, err
	}
	if kit.VaultID != f.VaultID || kit.Account != f.Account {
		return KitBackupKit{}, badRequest("kit backup payload disagrees with its header")
	}
	return kit, nil
}
