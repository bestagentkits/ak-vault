package akv1

import (
	"path/filepath"
	"strconv"
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
	checkLoggedRecords(t, f, n)
}

// checkRoleHistory reproduces role-history.json: the same layout as
// removal-fence.json, over its own chain and change log.
func checkRoleHistory(t *testing.T, f *rec, n *counter) { checkLoggedRecords(t, f, n) }

// checkLoggedRecords reproduces the chains' removals and role changes, the
// VerifyLoggedRecord cases and the change logs of a fenced-log vector file.
func checkLoggedRecords(t *testing.T, f *rec, n *counter) {
	cr := f.obj("chains")
	states := map[string]MembershipState{}
	for name := range cr.m {
		states[name] = mustOK(VerifyMembershipChain(cr.list(name), VerifyChainOptions{}))(t, cr.path+"."+name)
	}
	cr.done()
	rr := f.obj("removals")
	rc := f.obj("role_changes")
	for name, st := range states {
		removals := make([]any, len(st.Removals))
		for i, r := range st.Removals {
			removals[i] = r.JSONValue()
		}
		eqJSON(t, rr.path+"."+name, removals, rr.raw(name))
		changes := make([]any, len(st.RoleChanges))
		for i, c := range st.RoleChanges {
			changes[i] = c.JSONValue()
		}
		eqJSON(t, rc.path+"."+name, changes, rc.raw(name))
	}
	rr.done()
	rc.done()
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
	checkChangeLogs(t, f, n, states)
}

// checkChangeLogs reproduces the change-log head chains and the log replay
// cases of removal-fence.json and role-history.json.
func checkChangeLogs(t *testing.T, f *rec, n *counter, states map[string]MembershipState) {
	cl := f.obj("change_logs")
	for name := range cl.m {
		log := cl.obj(name)
		entries := log.list("entries")
		heads := log.list("heads")
		if len(heads) != len(entries)+1 || heads[0] != "" {
			t.Fatalf("%s: heads must be \"\" followed by one head per entry", log.path)
		}
		for i, raw := range entries {
			e := newRec(t, log.path+".entries["+strconv.Itoa(i)+"]", raw)
			if e.i64("log_seq") != int64(i+1) {
				t.Errorf("%s: log_seq is not its position", e.path)
			}
			conflictID := ""
			if cid := e.raw("conflict_id"); cid != nil {
				conflictID = cid.(string)
			}
			r := mustOK(ParseRecord(e.raw("record")))(t, e.path)
			digest := mustOK(RecordDigest(r))(t, e.path)
			got := mustOK(NextLogHead(heads[i].(string), int64(i+1), conflictID, digest))(t, e.path)
			eqStr(t, e.path+" head", got, heads[i+1].(string))
			e.done()
		}
		st := states[name]
		for _, sf := range SignedFences(st) {
			eqStr(t, log.path+" fence log_head", sf.LogHead, heads[sf.LogFence].(string))
		}
		got := mustOK(VerifyChangeLog(entries, st, VerifyChangeLogOptions{Complete: true}))(t, log.path)
		eqJSON(t, log.path+" head", got.Head, ChangeLogCursor{LogSeq: int64(len(entries)), LogHead: heads[len(entries)].(string)})
		log.done()
		n.add(1)
	}
	cl.done()
	run := func(c *rec) (VerifiedChangeLog, error) {
		st, ok := states[c.str("chain")]
		if !ok {
			t.Fatalf("%s: unknown chain", c.path)
		}
		from := c.obj("from")
		cursor := ChangeLogCursor{LogSeq: from.i64("log_seq"), LogHead: from.str("log_head")}
		from.done()
		kept := map[int64]string{}
		kr := c.obj("kept_heads")
		for k := range kr.m {
			pos, err := strconv.ParseInt(k, 10, 64)
			if err != nil {
				t.Fatalf("%s: kept_heads key %q is not a position", kr.path, k)
			}
			kept[pos] = kr.str(k)
		}
		kr.done()
		return VerifyChangeLog(c.list("entries"), st, VerifyChangeLogOptions{From: cursor, Complete: c.boolean("complete"), KeptHeads: kept})
	}
	for _, c := range f.recs("log_cases") {
		got := mustOK(run(c))(t, c.path)
		eqJSON(t, c.path+" head", got.Head, c.raw("head"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("log_invalid") {
		_, err := run(c)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}
