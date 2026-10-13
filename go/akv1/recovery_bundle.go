package akv1

import (
	"sort"
	"strconv"
)

// Recovery bundle (spec §3.4, §11): an opaque blob stored by the server that
// gives a fresh device the vault keys, the owner trust anchor, the owner
// recovery signing key and the newest owner-witnessed checkpoint.
//
//	BK  = 32 random bytes
//	env = XC20P(BK, n, cjson(plaintext), aad={ctx:"akv1/recovery-bundle", vault_id, bundle_seq}), kid "bk"
//	pw  = XC20P(Argon2id(NFC(password), s, t, m, p), n, BK, aad={ctx:"akv1/bundle-pw-wrap", vault_id, bundle_seq, t, m, p})
//	rk  = XC20P(KEK_rk(rk), n, BK, aad={ctx:"akv1/bundle-rk-wrap", vault_id, bundle_seq})

func bundleAAD(vaultID string, seq int64) map[string]any {
	return map[string]any{"ctx": "akv1/recovery-bundle", "vault_id": vaultID, "bundle_seq": seq}
}

func bundlePwAAD(vaultID string, seq int64, p ArgonParams) map[string]any {
	return map[string]any{"ctx": "akv1/bundle-pw-wrap", "vault_id": vaultID, "bundle_seq": seq, "t": p.T, "m": p.M, "p": p.P}
}

func bundleRkAAD(vaultID string, seq int64) map[string]any {
	return map[string]any{"ctx": "akv1/bundle-rk-wrap", "vault_id": vaultID, "bundle_seq": seq}
}

// checkBundleCheckpoint: same vault (bad_request), author is kid(owner_sign_pub)
// (forbidden), and the signature verifies against owner_sign_pub (invalid_signature).
func checkBundleCheckpoint(cp Checkpoint, vaultID, ownerSignPub string) error {
	if cp.VaultID != vaultID {
		return badRequest("bundle checkpoint belongs to another vault")
	}
	owner, err := DeviceIDFromSignPubB64(ownerSignPub)
	if err != nil {
		return err
	}
	if cp.Author != owner {
		return newErr(CodeForbidden, "bundle checkpoint is not signed by the owner anchor")
	}
	return VerifyObject(ContextCheckpoint, cp, ownerSignPub)
}

// SealRecoveryBundleArgs configures SealRecoveryBundle. A zero Params means
// ArgonDefaults. BundleKey, Salt and the nonces are nil in production
// (random); tests inject them to reproduce vectors.
type SealRecoveryBundleArgs struct {
	VaultID        string
	BundleSeq      int64 // >= 1; every replacement bundle MUST increase it
	VK             map[int64][]byte
	OwnerSignPub   string // b64
	RecoverySignSK []byte // 32-byte Ed25519 seed
	Checkpoint     Checkpoint
	Password       string // raw user input; NFC-normalized by DerivePasswordKEK
	RK             []byte
	Params         ArgonParams
	BundleKey      []byte
	Salt           []byte
	NonceEnv       []byte
	NoncePW        []byte
	NonceRK        []byte
}

// SealRecoveryBundle builds the bundle, applying the same plaintext checks as opening.
func SealRecoveryBundle(a SealRecoveryBundleArgs) (RecoveryBundle, error) {
	if _, err := asID(a.VaultID, "vault_id"); err != nil {
		return RecoveryBundle{}, err
	}
	if _, err := asInt(a.BundleSeq, "bundle_seq", 1, MaxSafeInteger); err != nil {
		return RecoveryBundle{}, err
	}
	params := a.Params
	if params == (ArgonParams{}) {
		params = ArgonDefaults
	}
	if err := ValidateArgonParams(params); err != nil {
		return RecoveryBundle{}, err
	}
	vk := make(map[string]any, len(a.VK))
	for epoch, key := range a.VK {
		vk[strconv.FormatInt(epoch, 10)] = B64Encode(key)
	}
	pt, err := parseRecoveryBundlePlaintext(map[string]any{
		"v": int64(1), "vault_id": a.VaultID, "bundle_seq": a.BundleSeq, "vk": vk,
		"owner_sign_pub": a.OwnerSignPub, "recovery_sign_sk": B64Encode(a.RecoverySignSK), "checkpoint": a.Checkpoint.JSONValue(),
	})
	if err != nil {
		return RecoveryBundle{}, err
	}
	if err := checkBundleCheckpoint(pt.Checkpoint, a.VaultID, pt.OwnerSignPub); err != nil {
		return RecoveryBundle{}, err
	}
	bk := a.BundleKey
	if bk == nil {
		bk = randomBytes(KeyBytes)
	}
	if len(bk) != KeyBytes {
		return RecoveryBundle{}, badRequest("bundle key must be 32 bytes")
	}
	salt := a.Salt
	if salt == nil {
		salt = randomBytes(SaltBytes)
	}
	nEnv, nPW, nRK := a.NonceEnv, a.NoncePW, a.NonceRK
	if nEnv == nil {
		nEnv = randomBytes(NonceBytes)
	}
	if nPW == nil {
		nPW = randomBytes(NonceBytes)
	}
	if nRK == nil {
		nRK = randomBytes(NonceBytes)
	}
	plaintext, err := CJSON(pt)
	if err != nil {
		return RecoveryBundle{}, err
	}
	env, err := SealEnvelope(bk, plaintext, bundleAAD(a.VaultID, a.BundleSeq), SealOptions{Kid: BundleEnvelopeKid, Nonce: nEnv})
	if err != nil {
		return RecoveryBundle{}, err
	}
	kekPW, err := DerivePasswordKEK(a.Password, salt, params)
	if err != nil {
		return RecoveryBundle{}, err
	}
	pwCt, err := XC20PSeal(kekPW, nPW, bk, bundlePwAAD(a.VaultID, a.BundleSeq, params))
	if err != nil {
		return RecoveryBundle{}, err
	}
	kekRK, err := DeriveRecoveryKEK(a.RK)
	if err != nil {
		return RecoveryBundle{}, err
	}
	rkCt, err := XC20PSeal(kekRK, nRK, bk, bundleRkAAD(a.VaultID, a.BundleSeq))
	if err != nil {
		return RecoveryBundle{}, err
	}
	return RecoveryBundle{
		VaultID: a.VaultID, BundleSeq: a.BundleSeq,
		PW:  BundlePasswordWrap{S: B64Encode(salt), Params: params, N: B64Encode(nPW), Ct: B64Encode(pwCt)},
		RK:  BundleRecoveryWrap{N: B64Encode(nRK), Ct: B64Encode(rkCt)},
		Env: env,
	}, nil
}

// OpenRecoveryBundleArgs configures OpenRecoveryBundle. Exactly one of
// Password (non-empty) or RK (non-nil) must be given. KnownBundleSeq is the
// highest bundle_seq this client has seen (0 = none).
type OpenRecoveryBundleArgs struct {
	Bundle         any
	VaultID        string
	Password       string
	RK             []byte
	KnownBundleSeq int64
}

// OpenedRecoveryBundle is the verified bundle content.
type OpenedRecoveryBundle struct {
	BundleSeq       int64
	VK              map[int64][]byte // vault key per key epoch
	OwnerSignPub    string
	RecoverySignSK  []byte
	RecoverySignPub string
	Checkpoint      Checkpoint
	// NeedsUpgrade: opened with a password under params weaker than the
	// defaults; re-seal the bundle after unlock.
	NeedsUpgrade bool
}

// JSONValue returns the summary shape used by the vectors (vk as b64 by decimal epoch).
func (o OpenedRecoveryBundle) JSONValue() any {
	epochs := make([]int64, 0, len(o.VK))
	for e := range o.VK {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	vk := make(map[string]any, len(epochs))
	for _, e := range epochs {
		vk[strconv.FormatInt(e, 10)] = B64Encode(o.VK[e])
	}
	return map[string]any{
		"bundle_seq": o.BundleSeq, "vk": vk, "owner_sign_pub": o.OwnerSignPub,
		"recovery_sign_sk": B64Encode(o.RecoverySignSK), "recovery_sign_pub": o.RecoverySignPub,
		"checkpoint": o.Checkpoint.JSONValue(), "needs_upgrade": o.NeedsUpgrade,
	}
}

// OpenRecoveryBundle opens an untrusted bundle. Order: parse the wire
// (unsupported_version / bad_request), vault match (bad_request), bundle_seq
// below KnownBundleSeq (rollback, before any KDF), exactly one secret
// (bad_request), unwrap BK (decrypt_failed), open env (decrypt_failed),
// plaintext must be canonical and repeat the wire vault_id/bundle_seq
// (bad_request), checkpoint author must be kid(owner_sign_pub) (forbidden)
// with a valid signature (invalid_signature).
func OpenRecoveryBundle(a OpenRecoveryBundleArgs) (OpenedRecoveryBundle, error) {
	w, err := ParseRecoveryBundle(a.Bundle)
	if err != nil {
		return OpenedRecoveryBundle{}, err
	}
	if _, err := asID(a.VaultID, "vault_id"); err != nil {
		return OpenedRecoveryBundle{}, err
	}
	if w.VaultID != a.VaultID {
		return OpenedRecoveryBundle{}, badRequest("recovery bundle belongs to another vault")
	}
	if a.KnownBundleSeq < 0 {
		return OpenedRecoveryBundle{}, badRequest("known bundle_seq must be non-negative")
	}
	if w.BundleSeq < a.KnownBundleSeq {
		return OpenedRecoveryBundle{}, newErr(CodeRollback, "recovery bundle is older than a known one")
	}
	usePassword := a.Password != ""
	if usePassword == (a.RK != nil) {
		return OpenedRecoveryBundle{}, badRequest("provide exactly one of password or rk")
	}
	bk, err := unwrapBundleKey(w, a)
	if err != nil {
		return OpenedRecoveryBundle{}, err
	}
	plain, err := openParsedEnvelope(bk, w.Env, bundleAAD(w.VaultID, w.BundleSeq))
	if err != nil {
		return OpenedRecoveryBundle{}, err
	}
	v, err := CJSONParse(plain)
	if err != nil {
		return OpenedRecoveryBundle{}, err
	}
	pt, err := parseRecoveryBundlePlaintext(v)
	if err != nil {
		return OpenedRecoveryBundle{}, err
	}
	if pt.VaultID != w.VaultID || pt.BundleSeq != w.BundleSeq {
		return OpenedRecoveryBundle{}, badRequest("recovery bundle plaintext does not match its wire header")
	}
	if err := checkBundleCheckpoint(pt.Checkpoint, w.VaultID, pt.OwnerSignPub); err != nil {
		return OpenedRecoveryBundle{}, err
	}
	sk, _ := B64Decode(pt.RecoverySignSK)
	pub, err := SignPublicKey(sk)
	if err != nil {
		return OpenedRecoveryBundle{}, err
	}
	vk := make(map[int64][]byte, len(pt.VK))
	for k, val := range pt.VK {
		e, _ := strconv.ParseInt(k, 10, 64) // validated by parseVKMap
		vk[e], _ = B64Decode(val)
	}
	return OpenedRecoveryBundle{
		BundleSeq: w.BundleSeq, VK: vk, OwnerSignPub: pt.OwnerSignPub, RecoverySignSK: sk,
		RecoverySignPub: B64Encode(pub), Checkpoint: pt.Checkpoint,
		NeedsUpgrade: usePassword && ArgonNeedsUpgrade(w.PW.Params),
	}, nil
}

func unwrapBundleKey(w RecoveryBundle, a OpenRecoveryBundleArgs) ([]byte, error) {
	if a.Password != "" {
		salt, _ := B64Decode(w.PW.S)
		kek, err := DerivePasswordKEK(a.Password, salt, w.PW.Params)
		if err != nil {
			return nil, err
		}
		n, _ := B64Decode(w.PW.N)
		ct, _ := B64Decode(w.PW.Ct)
		return XC20POpen(kek, n, ct, bundlePwAAD(w.VaultID, w.BundleSeq, w.PW.Params))
	}
	kek, err := DeriveRecoveryKEK(a.RK)
	if err != nil {
		return nil, err
	}
	n, _ := B64Decode(w.RK.N)
	ct, _ := B64Decode(w.RK.Ct)
	return XC20POpen(kek, n, ct, bundleRkAAD(w.VaultID, w.BundleSeq))
}
