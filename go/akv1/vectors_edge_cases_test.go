package akv1

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func checkEdgeCases(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("recovery_key_display_valid") {
		eqStr(t, c.path, B64Encode(mustOK(DecodeRecoveryKey(c.str("input")))(t, c.path)), c.str("rk"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("recovery_key_display_invalid") {
		_, err := DecodeRecoveryKey(c.str("display"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("x25519_public_key_invalid") {
		_, err := KxPublicKey(c.b64("secret"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("x25519_shared_invalid") {
		_, err := X25519Shared(c.b64("secret"), c.b64("public_key"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("unwrap_from_device_invalid") {
		_, err := UnwrapFromDevice(c.raw("wrap"), c.str("vault_id"), c.str("device_id"), c.b64("kx_secret"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("wrap_to_device_invalid") {
		r := c.obj("recipient")
		_, err := WrapToDevice(WrapToDeviceArgs{
			VK: c.b64("vk"), VaultID: c.str("vault_id"), KeyEpoch: c.i64("key_epoch"),
			RecipientID: r.str("device_id"), RecipientKxPub: r.b64("kx_pub"),
			EphemeralSecret: c.b64("ephemeral_secret"), Nonce: c.b64("nonce"),
		})
		r.done()
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("ed25519_valid") {
		if err := VerifyObject(c.str("context"), c.raw("object"), c.str("public_key")); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("ed25519_invalid") {
		expectCode(t, c, VerifyObject(c.str("context"), c.raw("object"), c.str("public_key")))
		c.done()
		n.add(1)
	}
}

// TestStrictEd25519ClosesStdlibGaps documents why verifyEd25519Strict exists:
// crypto/ed25519 alone accepts the small-order and non-canonical public key
// vectors (signatures forged without any secret key). The strict wrapper
// must reject every invalid vector.
func TestStrictEd25519ClosesStdlibGaps(t *testing.T) {
	v := loadVectorJSON(t, filepath.Join(vectorsDir(t), "edge-cases.json"))
	stdlibAccepted := 0
	for _, raw := range v["ed25519_invalid"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		obj := c["object"].(map[string]any)
		msg, err := SigningInput(c["context"].(string), obj)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := B64Decode(c["public_key"].(string))
		sig, _ := B64Decode(obj["sig"].(string))
		if ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			stdlibAccepted++
			t.Logf("crypto/ed25519 alone accepts %s", name)
		}
		if verifyEd25519Strict(pub, msg, sig) {
			t.Errorf("%s: strict verification accepted an invalid signature", name)
		}
	}
	if stdlibAccepted == 0 {
		t.Error("expected crypto/ed25519 to accept some lenient-only vectors; the strict checks would be untested")
	}
}

func TestCanonicalPointEncoding(t *testing.T) {
	cases := map[string]bool{
		"0100000000000000000000000000000000000000000000000000000000000000": true,  // identity
		"0100000000000000000000000000000000000000000000000000000000000080": false, // identity, negative zero
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,  // y = p-1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": false, // y = p-1, negative zero
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": false, // y = p
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": false, // y = p+1
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": false, // y = 2^255-1
		"0000000000000000000000000000000000000000000000000000000000000080": true,  // y = 0, x odd
	}
	for h, want := range cases {
		if got := canonicalPointEncoding(mustHex(h)); got != want {
			t.Errorf("%s: got %v want %v", h, got, want)
		}
	}
	// S must be strictly below L.
	if lessLE(ed25519L, ed25519L) || !lessLE(mustHex("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), ed25519L) {
		t.Error("lessLE boundary is wrong")
	}
}
