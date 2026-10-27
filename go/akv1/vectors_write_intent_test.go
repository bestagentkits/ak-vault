package akv1

import (
	"strings"
	"testing"
)

func init() { vectorHandlers["write-intent.json"] = checkWriteIntent }

// targetOf builds a WriteIntentTarget from a vector target object. It reports
// false when the object has a key or value type the struct cannot carry, so
// the caller checks it through ParseWriteIntentTarget instead of dropping it.
func targetOf(obj map[string]any) (WriteIntentTarget, bool) {
	var p WriteIntentTarget
	for k, v := range obj {
		s, ok := v.(string)
		if !ok {
			return WriteIntentTarget{}, false
		}
		switch k {
		case "name":
			p.Name = s
		case "purpose":
			if s == "" {
				return WriteIntentTarget{}, false
			}
			p.Purpose = s
		case "sensitivity":
			if s == "" {
				return WriteIntentTarget{}, false
			}
			p.Sensitivity = s
		default:
			return WriteIntentTarget{}, false
		}
	}
	return p, true
}

func checkWriteIntent(t *testing.T, f *rec, n *counter) {
	keys := sealKeys(t)
	origin := parseOrigin(t, "origin", f.raw("origin"))
	var vaultID string

	for _, c := range f.recs("cases") {
		epoch := c.i64("key_epoch")
		wire := mustOK(ParseWriteIntent(c.raw("wire")))(t, c.path+".wire")
		if vaultID == "" {
			vaultID = wire.VaultID
		}
		eqStr(t, c.path+" operation", wire.Operation, c.str("operation"))
		raw := c.raw("target").(map[string]any)
		target, ok := targetOf(raw)
		if !ok {
			t.Fatalf("%s: target is not representable", c.path)
		}
		got := mustOK(SealWriteIntent(SealWriteIntentArgs{
			SealPub: keys[epoch].public, VaultID: wire.VaultID, KeyEpoch: epoch, RequestID: wire.RequestID,
			Origin: wire.Origin, Operation: c.str("operation"), TS: wire.TS, ExpiresAt: wire.ExpiresAt, Target: target,
			ephemeralSecret: c.b64("ephemeral_secret"), nonce: mustOK(B64Decode(wire.N))(t, c.path+".n"),
		}))(t, c.path)
		eqJSON(t, c.path+" wire", got, c.raw("wire"))
		eqStr(t, c.path+" plaintext", string(mustOK(CJSON(raw))(t, c.path)), c.str("plaintext"))
		opened := mustOK(OpenWriteIntent(keys[epoch].secret, c.raw("wire"), wire.VaultID))(t, c.path+" open")
		eqJSON(t, c.path+" opened target", opened.Target(), raw)
		eqJSON(t, c.path+" opened wire", opened.Wire(), c.raw("wire"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := OpenWriteIntent(keys[c.i64("open_with_epoch")].secret, c.raw("wire"), c.str("vault_id"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("seal_invalid") {
		raw := c.raw("target").(map[string]any)
		// Sealing validates the target with ParseWriteIntentTarget first, so a
		// target the struct cannot express is checked there.
		target, ok := targetOf(raw)
		var err error
		if ok {
			_, err = SealWriteIntent(SealWriteIntentArgs{
				SealPub: keys[3].public, VaultID: vaultID, KeyEpoch: 3, Origin: origin,
				Operation: WriteIntentCreate, TS: 1, ExpiresAt: 2, Target: target,
			})
		} else {
			_, err = ParseWriteIntentTarget(raw)
		}
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func TestWriteIntentFreshSealsDifferAndOpen(t *testing.T) {
	keys := sealKeys(t)
	origin := SealedOrigin{Kind: SealedOriginMCP, Account: "acct_test", ClientID: "client-test", GrantID: "grant_test"}
	vaultID := RandomID()
	args := SealWriteIntentArgs{SealPub: keys[3].public, VaultID: vaultID, KeyEpoch: 3, Origin: origin, Operation: WriteIntentCreate, TS: 1, ExpiresAt: 2, Target: WriteIntentTarget{Name: "A"}}
	a := mustOK(SealWriteIntent(args))(t, "seal a")
	b := mustOK(SealWriteIntent(args))(t, "seal b")
	if a.Epk == b.Epk || a.RequestID == b.RequestID || a.N == b.N {
		t.Fatal("fresh seals reuse an ephemeral key, request ID or nonce")
	}
	opened := mustOK(OpenWriteIntent(keys[3].secret, a.JSONValue(), vaultID))(t, "open a")
	if opened.Target() != args.Target {
		t.Fatalf("opened target mismatch")
	}
}

func TestWriteIntentSealRefusals(t *testing.T) {
	keys := sealKeys(t)
	base := SealWriteIntentArgs{
		SealPub: keys[3].public, VaultID: RandomID(), KeyEpoch: 3,
		Origin:    SealedOrigin{Kind: SealedOriginMCP, Account: "acct_test", ClientID: "client-test", GrantID: "grant_test"},
		Operation: WriteIntentReplace, TS: 10, ExpiresAt: 20, Target: WriteIntentTarget{Name: "A"},
	}
	cases := map[string]func(a *SealWriteIntentArgs){
		"short seal_pub":      func(a *SealWriteIntentArgs) { a.SealPub = a.SealPub[:31] },
		"expires_at == ts":    func(a *SealWriteIntentArgs) { a.ExpiresAt = a.TS },
		"unknown operation":   func(a *SealWriteIntentArgs) { a.Operation = "delete" },
		"key_epoch zero":      func(a *SealWriteIntentArgs) { a.KeyEpoch = 0 },
		"unknown sensitivity": func(a *SealWriteIntentArgs) { a.Target.Sensitivity = "secret" },
		"escaped plaintext too large": func(a *SealWriteIntentArgs) {
			a.Target.Name = strings.Repeat("\x01", MaxItemNameLength)
		},
	}
	for name, mutate := range cases {
		a := base
		mutate(&a)
		_, err := SealWriteIntent(a)
		if CodeOf(err) != CodeBadRequest {
			t.Errorf("%s: want bad_request, got %v", name, err)
		}
	}
}
