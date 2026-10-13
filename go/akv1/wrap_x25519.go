package akv1

import (
	"crypto/ecdh"
)

// X25519Wrap is the device key wrap
// {"v":1,"alg":"x25519-xc20p","rcpt","key_epoch","epk","n","ct"} (spec §3.3).
type X25519Wrap struct {
	Rcpt     string
	KeyEpoch int64
	Epk      string
	N        string
	Ct       string
}

// JSONValue returns the wire object.
func (w X25519Wrap) JSONValue() any {
	return map[string]any{"v": int64(1), "alg": "x25519-xc20p", "rcpt": w.Rcpt, "key_epoch": w.KeyEpoch, "epk": w.Epk, "n": w.N, "ct": w.Ct}
}

// wrappedKeyCtBytes is the ciphertext size of a wrapped 32-byte key (key || tag).
const wrappedKeyCtBytes = KeyBytes + TagBytes

func wrapAAD(vaultID string, keyEpoch int64, recipient string) map[string]any {
	return map[string]any{"ctx": "akv1/wrap", "vault_id": vaultID, "key_epoch": keyEpoch, "recipient": recipient}
}

// X25519Shared computes X25519(secret, publicKey) and fails closed
// (CodeBadRequest) on an all-zero output from a low-order point.
func X25519Shared(secret, publicKey []byte) ([]byte, error) {
	if len(secret) != KeyBytes || len(publicKey) != KeyBytes {
		return nil, badRequest("X25519 keys must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		return nil, badRequest("invalid X25519 secret")
	}
	pub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, badRequest("invalid X25519 public key")
	}
	shared, err := priv.ECDH(pub)
	if err != nil || isAllZero(shared) {
		return nil, badRequest("X25519 produced an all-zero shared secret")
	}
	return shared, nil
}

func deriveWrapKey(shared, epk, rcptKxPub []byte) []byte {
	return hkdf32(shared, concatBytes(epk, rcptKxPub), []byte("akv1/wrap/x25519"))
}

// ParseX25519Wrap validates an untrusted device wrap.
func ParseX25519Wrap(v any) (X25519Wrap, error) { return parseX25519WrapAs(v, "wrap") }

func parseX25519WrapAs(v any, what string) (X25519Wrap, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return X25519Wrap{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return X25519Wrap{}, err
	}
	if obj["alg"] != "x25519-xc20p" {
		return X25519Wrap{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "rcpt", "key_epoch", "epk", "n", "ct"}, what); err != nil {
		return X25519Wrap{}, err
	}
	var w X25519Wrap
	if w.Rcpt, err = asID(obj["rcpt"], what+".rcpt"); err != nil {
		return X25519Wrap{}, err
	}
	if w.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return X25519Wrap{}, err
	}
	if w.Epk, err = asB64(obj["epk"], what+".epk", KeyBytes); err != nil {
		return X25519Wrap{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return X25519Wrap{}, err
	}
	if w.Ct, err = asB64(obj["ct"], what+".ct", wrappedKeyCtBytes); err != nil {
		return X25519Wrap{}, err
	}
	return w, nil
}

// WrapToDeviceArgs configures WrapToDevice. EphemeralSecret and Nonce are nil
// in production (fresh random values); tests inject them to reproduce vectors.
type WrapToDeviceArgs struct {
	VK              []byte
	VaultID         string
	KeyEpoch        int64
	RecipientID     string // recipient device_id
	RecipientKxPub  []byte // recipient X25519 public key (32 bytes)
	EphemeralSecret []byte
	Nonce           []byte
}

// WrapToDevice wraps VK[e] to a recipient device (x25519-xc20p).
func WrapToDevice(args WrapToDeviceArgs) (X25519Wrap, error) {
	if len(args.VK) != KeyBytes {
		return X25519Wrap{}, badRequest("vault key must be 32 bytes")
	}
	if _, err := asID(args.RecipientID, "recipient.device_id"); err != nil {
		return X25519Wrap{}, err
	}
	if _, err := asInt(args.KeyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return X25519Wrap{}, err
	}
	if _, err := asID(args.VaultID, "vault_id"); err != nil {
		return X25519Wrap{}, err
	}
	if len(args.RecipientKxPub) != KeyBytes {
		return X25519Wrap{}, badRequest("kx_pub must be 32 bytes")
	}
	esk := args.EphemeralSecret
	if esk == nil {
		esk = randomBytes(KeyBytes)
	}
	epk, err := KxPublicKey(esk)
	if err != nil {
		return X25519Wrap{}, err
	}
	shared, err := X25519Shared(esk, args.RecipientKxPub)
	if err != nil {
		return X25519Wrap{}, err
	}
	nonce := args.Nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	wrapKey := deriveWrapKey(shared, epk, args.RecipientKxPub)
	ct, err := XC20PSeal(wrapKey, nonce, args.VK, wrapAAD(args.VaultID, args.KeyEpoch, args.RecipientID))
	if err != nil {
		return X25519Wrap{}, err
	}
	return X25519Wrap{Rcpt: args.RecipientID, KeyEpoch: args.KeyEpoch, Epk: B64Encode(epk), N: B64Encode(nonce), Ct: B64Encode(ct)}, nil
}

// UnwrapFromDevice recovers VK[e] from an untrusted wrap. The wrap's rcpt must
// equal deviceID (CodeForbidden); a wrong key or tampering is CodeDecryptFailed.
func UnwrapFromDevice(wrap any, vaultID, deviceID string, kxSecret []byte) ([]byte, error) {
	w, err := ParseX25519Wrap(wrap)
	if err != nil {
		return nil, err
	}
	if w.Rcpt != deviceID {
		return nil, newErr(CodeForbidden, "wrap is addressed to a different device")
	}
	ownPub, err := KxPublicKey(kxSecret)
	if err != nil {
		return nil, err
	}
	epk, _ := B64Decode(w.Epk)
	shared, err := X25519Shared(kxSecret, epk)
	if err != nil {
		return nil, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return nil, err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	return XC20POpen(deriveWrapKey(shared, epk, ownPub), nonce, ct, wrapAAD(vaultID, w.KeyEpoch, w.Rcpt))
}
