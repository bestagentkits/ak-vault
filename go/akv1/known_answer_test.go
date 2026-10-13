package akv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8032 §7.1 TEST 1 (empty message).
func TestEd25519RFC8032Test1(t *testing.T) {
	seed := unhex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantPub := unhex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	wantSig := unhex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	pub, err := SignPublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, wantPub) {
		t.Fatalf("public key mismatch: %x", pub)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), nil)
	if !bytes.Equal(sig, wantSig) {
		t.Fatalf("signature mismatch: %x", sig)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), nil, sig) {
		t.Fatal("signature does not verify")
	}
}

// RFC 7748 §6.1 Diffie-Hellman test vector.
func TestX25519RFC7748(t *testing.T) {
	alicePriv := unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := unhex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := unhex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := unhex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shared := unhex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	for _, c := range []struct{ priv, pub []byte }{{alicePriv, alicePub}, {bobPriv, bobPub}} {
		got, err := KxPublicKey(c.priv)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, c.pub) {
			t.Fatalf("public key mismatch: %x", got)
		}
	}
	ab, err := X25519Shared(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := X25519Shared(bobPriv, alicePub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, shared) || !bytes.Equal(ba, shared) {
		t.Fatalf("shared secret mismatch: %x / %x", ab, ba)
	}
	// A low-order public key yields an all-zero shared secret and must be refused.
	if _, err := X25519Shared(alicePriv, make([]byte, 32)); CodeOf(err) != CodeBadRequest {
		t.Fatalf("all-zero shared secret: got %v", err)
	}
}

func TestBase64urlStrict(t *testing.T) {
	for _, ok := range []string{"", "AA", "AAA", "AAAA", "-_8"} {
		if _, err := B64Decode(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"A", "AA==", "AB", "AAB", "A+A", "A/A", "AA A", "AAAAA"} {
		if _, err := B64Decode(bad); CodeOf(err) != CodeBadRequest {
			t.Errorf("%q: expected bad_request, got %v", bad, err)
		}
	}
}
