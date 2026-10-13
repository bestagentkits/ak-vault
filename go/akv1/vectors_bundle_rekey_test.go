package akv1

import (
	"path/filepath"
	"strconv"
	"testing"
)

func checkRecoveryBundle(t *testing.T, f *rec, n *counter) {
	s := f.obj("seal")
	vaultID := s.str("vault_id")
	bundleSeq := s.i64("bundle_seq")
	vkRec := s.obj("vk")
	vk := map[int64][]byte{}
	for k := range vkRec.m {
		e, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			t.Fatalf("%s: bad epoch key %q", vkRec.path, k)
		}
		vk[e] = vkRec.b64(k)
	}
	vkRec.done()
	cp := mustOK(ParseCheckpoint(s.raw("checkpoint")))(t, s.path)
	bundleKey := s.b64("bundle_key")
	bundle := mustOK(SealRecoveryBundle(SealRecoveryBundleArgs{
		VaultID: vaultID, BundleSeq: bundleSeq, VK: vk, OwnerSignPub: s.str("owner_sign_pub"),
		RecoverySignSK: s.b64("recovery_sign_sk"), Checkpoint: cp, Password: s.str("password"), RK: s.b64("rk"),
		Params:    ArgonParams{T: s.i64("t"), M: s.i64("m"), P: s.i64("p")},
		BundleKey: bundleKey, Salt: s.b64("salt"), NonceEnv: s.b64("nonce_env"), NoncePW: s.b64("nonce_pw"), NonceRK: s.b64("nonce_rk"),
	}))(t, s.path)
	eqJSON(t, s.path+" bundle", bundle, s.raw("bundle"))
	env := s.obj("bundle").raw("env")
	pt := mustOK(OpenEnvelope(bundleKey, env, bundleAAD(vaultID, bundleSeq), BundleEnvelopeKid))(t, s.path)
	eqStr(t, s.path+" plaintext_cjson", string(pt), s.str("plaintext_cjson"))
	s.done()
	n.add(1)

	openArgs := func(c *rec) OpenRecoveryBundleArgs {
		o := c.obj("open")
		a := OpenRecoveryBundleArgs{Bundle: c.raw("bundle"), VaultID: vaultID}
		if o.has("vault_id") {
			a.VaultID = o.str("vault_id")
		}
		if o.has("password") {
			a.Password = o.str("password")
		}
		if o.has("rk") {
			a.RK = o.b64("rk")
		}
		if o.has("known_bundle_seq") {
			a.KnownBundleSeq = o.i64("known_bundle_seq")
		}
		if o.has("recovery_sign_pub") {
			a.RecoverySignPub = o.str("recovery_sign_pub")
		}
		o.done()
		return a
	}
	for _, c := range f.recs("cases") {
		opened := mustOK(OpenRecoveryBundle(openArgs(c)))(t, c.path)
		eqJSON(t, c.path+" expected", opened, c.raw("expected"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := OpenRecoveryBundle(openArgs(c))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkRekeyWraps(t *testing.T, f *rec, n *counter) {
	events := f.list("events")
	membership := loadVectorJSON(t, filepath.Join(vectorsDir(t), "membership.json"))
	chain0 := membership["chains"].([]any)[0].(map[string]any)["events"]
	eqJSON(t, "events equal membership.json chains[0].events", events, chain0)
	n.add(1)

	run := func(c *rec) ([]X25519Wrap, error) {
		seq := c.i64("event_seq")
		if seq >= int64(len(events)) {
			t.Fatalf("%s: event_seq out of range", c.path)
		}
		var state *MembershipState
		if c.raw("state_seq") != nil {
			ss := c.i64("state_seq")
			if ss >= int64(len(events)) {
				t.Fatalf("%s: state_seq out of range", c.path)
			}
			st := mustOK(VerifyMembershipChain(events[:ss+1], VerifyChainOptions{}))(t, c.path)
			state = &st
		}
		return VerifyRekeyWraps(events[seq], c.list("wraps"), state)
	}
	for _, c := range f.recs("cases") {
		wraps := mustOK(run(c))(t, c.path)
		if len(wraps) != len(c.list("wraps")) {
			t.Errorf("%s: got %d wraps, want %d", c.path, len(wraps), len(c.list("wraps")))
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := run(c)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}
