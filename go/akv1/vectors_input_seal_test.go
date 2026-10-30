package akv1

import (
	"strings"
	"testing"
)

func init() { vectorHandlers["input-seal.json"] = checkInputSeal }

func checkInputSeal(t *testing.T, f *rec, n *counter) {
	secret := f.b64("input_secret")
	pub := f.b64("input_pub")
	eqStr(t, "input_pub", B64Encode(mustOK(KxPublicKey(secret))(t, "input_pub")), B64Encode(pub))
	n.add(1)

	for _, c := range f.recs("cases") {
		ctx := mustOK(ParseInputSealContext(c.raw("context")))(t, c.path+".context")
		raw := c.raw("payload")
		payload := mustOK(ParseInputSealPayload(raw))(t, c.path+".payload")
		wire := mustOK(ParseInputSeal(c.raw("wire")))(t, c.path+".wire")
		got := mustOK(sealInput(pub, ctx, payload, c.b64("ephemeral_secret"), mustOK(B64Decode(wire.N))(t, c.path+".n")))(t, c.path)
		eqJSON(t, c.path+" wire", got, c.raw("wire"))
		eqStr(t, c.path+" plaintext", string(mustOK(CJSON(raw))(t, c.path)), c.str("plaintext"))
		opened := mustOK(OpenInput(secret, c.raw("wire"), ctx))(t, c.path+" open")
		eqJSON(t, c.path+" opened payload", opened, raw)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		ctx := mustOK(ParseInputSealContext(c.raw("context")))(t, c.path+".context")
		wire := c.raw("wire")
		if c.has("ct_zero_bytes") {
			m := map[string]any{}
			for k, v := range wire.(map[string]any) {
				m[k] = v
			}
			m["ct"] = B64Encode(make([]byte, c.i64("ct_zero_bytes")))
			wire = m
		}
		_, err := OpenInput(c.b64("input_secret"), wire, ctx)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("seal_invalid") {
		rawPayload := c.raw("payload").(map[string]any)
		if c.has("value_fill") {
			m := map[string]any{"value": strings.Repeat(c.str("value_fill"), int(c.i64("value_length")))}
			for k, v := range rawPayload {
				m[k] = v
			}
			rawPayload = m
		}
		// Sealing validates the context and payload first, so a context or payload
		// the structs cannot express is checked through the parsers.
		ctx, err := ParseInputSealContext(c.raw("context"))
		if err == nil {
			var payload InputSealPayload
			if payload, err = ParseInputSealPayload(rawPayload); err == nil {
				_, err = SealInput(pub, ctx, payload)
			}
		}
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func TestInputSealFreshKeysAndSealsDiffer(t *testing.T) {
	sa, pa := mustOK3(GenerateInputKeyPair())(t, "key a")
	sb, pb := mustOK3(GenerateInputKeyPair())(t, "key b")
	if B64Encode(pa) == B64Encode(pb) || B64Encode(sa) == B64Encode(sb) {
		t.Fatal("fresh input key pairs repeat")
	}
	ctx := InputSealContext{RequestID: RandomID(), VaultID: RandomID(), Account: "acct_test", DeviceID: RandomID(), Name: "A", Operation: WriteIntentCreate, ExpiresAt: 2}
	a := mustOK(SealInput(pa, ctx, InputSealPayload{Value: "x"}))(t, "seal a")
	b := mustOK(SealInput(pa, ctx, InputSealPayload{Value: "x"}))(t, "seal b")
	if a.Epk == b.Epk || a.N == b.N {
		t.Fatal("fresh seals reuse an ephemeral key or nonce")
	}
	if got := mustOK(OpenInput(sa, a.JSONValue(), ctx))(t, "open a"); got != (InputSealPayload{Value: "x"}) {
		t.Fatalf("opened payload mismatch")
	}
	if _, err := OpenInput(sb, a.JSONValue(), ctx); CodeOf(err) != CodeDecryptFailed {
		t.Fatalf("other key: want decrypt_failed, got %v", err)
	}
}

func TestInputSealRefusals(t *testing.T) {
	_, pub := mustOK3(GenerateInputKeyPair())(t, "key")
	base := InputSealContext{RequestID: RandomID(), VaultID: RandomID(), Account: "acct_test", DeviceID: RandomID(), Name: "A", Operation: WriteIntentReplace, ExpiresAt: 20}
	cases := map[string]func(p *[]byte, c *InputSealContext, v *InputSealPayload){
		"short input_pub":     func(p *[]byte, _ *InputSealContext, _ *InputSealPayload) { *p = (*p)[:31] },
		"empty account":       func(_ *[]byte, c *InputSealContext, _ *InputSealPayload) { c.Account = "" },
		"unknown operation":   func(_ *[]byte, c *InputSealContext, _ *InputSealPayload) { c.Operation = "delete" },
		"bad request id":      func(_ *[]byte, c *InputSealContext, _ *InputSealPayload) { c.RequestID = "req_1" },
		"unknown sensitivity": func(_ *[]byte, _ *InputSealContext, v *InputSealPayload) { v.Sensitivity = "low" },
		"ill-formed value":    func(_ *[]byte, _ *InputSealContext, v *InputSealPayload) { v.Value = "\xff" },
		"plaintext over limit": func(_ *[]byte, _ *InputSealContext, v *InputSealPayload) {
			v.Value = strings.Repeat("v", MaxItemValueLength)
		},
	}
	for name, mutate := range cases {
		p, c, v := append([]byte{}, pub...), base, InputSealPayload{Value: "x"}
		mutate(&p, &c, &v)
		if _, err := SealInput(p, c, v); CodeOf(err) != CodeBadRequest {
			t.Errorf("%s: want bad_request, got %v", name, err)
		}
	}
}

// mustOK3 is mustOK for a (value, value, error) triple.
func mustOK3[A, B any](a A, b B, err error) func(t *testing.T, what string) (A, B) {
	return func(t *testing.T, what string) (A, B) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", what, err)
		}
		return a, b
	}
}
