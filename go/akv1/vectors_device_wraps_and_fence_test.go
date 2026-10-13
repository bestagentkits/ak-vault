package akv1

import (
	"path/filepath"
	"testing"
)

// membershipChains returns the event lists of membership.json chains[0] and chains[1].
func membershipChains(t *testing.T) (shared, personal any, devices map[string][]byte) {
	t.Helper()
	m := loadVectorJSON(t, filepath.Join(vectorsDir(t), "membership.json"))
	chains := m["chains"].([]any)
	devices = map[string][]byte{}
	for _, d := range m["devices"].([]any) {
		dm := d.(map[string]any)
		kx, err := B64Decode(dm["kx_secret"].(string))
		if err != nil {
			t.Fatalf("membership.json kx_secret: %v", err)
		}
		devices[dm["record"].(map[string]any)["device_id"].(string)] = kx
	}
	return chains[0].(map[string]any)["events"], chains[1].(map[string]any)["events"], devices
}

func checkDeviceAddWraps(t *testing.T, f *rec, n *counter) {
	shared, personal, kxSecrets := membershipChains(t)
	cr := f.obj("chains")
	chains := map[string][]any{}
	for name := range cr.m {
		chains[name] = cr.list(name)
		mustOK(VerifyMembershipChain(chains[name], VerifyChainOptions{}))(t, cr.path+"."+name)
	}
	cr.done()
	eqJSON(t, "chains.shared equals membership.json chains[0]", chains["shared"], shared)
	eqJSON(t, "chains.personal equals membership.json chains[1]", chains["personal"], personal)
	n.add(1)
	vkr := f.obj("vault_keys")
	vaultKeys := map[string]*rec{}
	for name := range vkr.m {
		vaultKeys[name] = vkr.obj(name)
	}
	event := func(c *rec) any {
		events, ok := chains[c.str("chain")]
		seq := c.i64("event_seq")
		if !ok || seq >= int64(len(events)) {
			t.Fatalf("%s: unknown chain or event_seq", c.path)
		}
		return events[seq]
	}
	for _, c := range f.recs("cases") {
		ev := event(c)
		wraps := mustOK(VerifyDeviceWraps(ev, c.list("wraps")))(t, c.path)
		if len(wraps) != len(c.list("wraps")) {
			t.Errorf("%s: got %d wraps, want %d", c.path, len(wraps), len(c.list("wraps")))
		}
		vaultID := ev.(map[string]any)["vault_id"].(string)
		keys := vaultKeys[c.str("chain")]
		for _, w := range wraps {
			vk := mustOK(UnwrapFromDevice(w.JSONValue(), vaultID, w.Rcpt, kxSecrets[w.Rcpt]))(t, c.path)
			eqStr(t, c.path+" unwrapped vault key", B64Encode(vk), keys.str(mustOK(EpochTag(w.KeyEpoch))(t, c.path)[1:]))
		}
		c.done()
		n.add(1)
	}
	for _, keys := range vaultKeys {
		for k := range keys.m {
			keys.str(k)
		}
		keys.done()
	}
	vkr.done()
	for _, c := range f.recs("invalid") {
		_, err := VerifyDeviceWraps(event(c), c.list("wraps"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkRemovalFence(t *testing.T, f *rec, n *counter) {
	shared, personal, _ := membershipChains(t)
	cr := f.obj("chains")
	eqJSON(t, "chains.shared equals membership.json chains[0]", cr.raw("shared"), shared)
	eqJSON(t, "chains.personal equals membership.json chains[1]", cr.raw("personal"), personal)
	states := map[string]MembershipState{}
	for name := range cr.m {
		states[name] = mustOK(VerifyMembershipChain(cr.list(name), VerifyChainOptions{}))(t, cr.path+"."+name)
	}
	cr.done()
	rr := f.obj("removals")
	for name, st := range states {
		removals := make([]any, len(st.Removals))
		for i, r := range st.Removals {
			removals[i] = r.JSONValue()
		}
		eqJSON(t, rr.path+"."+name, removals, rr.raw(name))
	}
	rr.done()
	n.add(1)
	state := func(c *rec) MembershipState {
		st, ok := states[c.str("chain")]
		if !ok {
			t.Fatalf("%s: unknown chain", c.path)
		}
		return st
	}
	for _, c := range f.recs("cases") {
		got := mustOK(VerifyLoggedRecord(c.raw("record"), state(c), c.i64("log_seq")))(t, c.path)
		eqJSON(t, c.path+" record", got, c.raw("record"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := VerifyLoggedRecord(c.raw("record"), state(c), c.i64("log_seq"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}
