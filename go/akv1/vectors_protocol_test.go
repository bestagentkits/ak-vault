package akv1

import (
	"strconv"
	"testing"
)

// chainOptions maps a vector "options" object onto VerifyChainOptions.
func chainOptions(o *rec) VerifyChainOptions {
	var out VerifyChainOptions
	if o.has("trusted_anchor") {
		out.TrustedAnchor = o.str("trusted_anchor")
	}
	if o.has("witnessed_checkpoint") {
		w := o.obj("witnessed_checkpoint")
		out.Witnessed = &WitnessedMembership{MembershipSeq: w.i64("membership_seq"), MembershipHead: w.str("membership_head")}
		w.done()
	}
	o.done()
	return out
}

func checkMembership(t *testing.T, f *rec, n *counter) {
	for _, d := range f.recs("devices") {
		dr := d.obj("record")
		pub := mustOK(SignPublicKey(d.b64("sign_seed")))(t, d.path)
		eqStr(t, d.path+" sign_pub", B64Encode(pub), dr.str("sign_pub"))
		eqStr(t, d.path+" device_id", mustOK(DeviceIDFromSignPub(pub))(t, d.path), dr.str("device_id"))
		kx := mustOK(KxPublicKey(d.b64("kx_secret")))(t, d.path)
		eqStr(t, d.path+" kx_pub", B64Encode(kx), dr.str("kx_pub"))
		parsed := mustOK(ParseDevice(dr.m))(t, d.path)
		eqJSON(t, d.path+" record", parsed, dr.m)
		dr.str("account")
		dr.str("role")
		dr.str("kind")
		dr.done()
		d.done()
		n.add(1)
	}
	rv := f.obj("recovery")
	pub := mustOK(SignPublicKey(rv.b64("sign_seed")))(t, rv.path)
	eqStr(t, rv.path+" sign_pub", B64Encode(pub), rv.str("sign_pub"))
	eqStr(t, rv.path+" author", mustOK(DeviceIDFromSignPubB64(rv.str("sign_pub")))(t, rv.path), rv.str("author"))
	rv.done()
	n.add(1)

	chains := map[string][]any{}
	var firstChain []any
	for _, c := range f.recs("chains") {
		events := c.list("events")
		chains[c.str("name")] = events
		if firstChain == nil {
			firstChain = events
		}
		state := mustOK(VerifyMembershipChain(events, chainOptions(c.obj("options"))))(t, c.path)
		eqJSON(t, c.path+" state", state, c.raw("expected_state"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := VerifyMembershipChain(c.list("events"), chainOptions(c.obj("options")))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	var firstDigest string
	for i, c := range f.recs("wrap_checks") {
		events, ok := chains[c.str("chain")]
		if !ok {
			t.Fatalf("%s: unknown chain", c.path)
		}
		state := mustOK(VerifyMembershipChain(events, VerifyChainOptions{}))(t, c.path)
		o := c.obj("options")
		var opts ValidateWrapsOptions
		if o.raw("key_epoch") != nil {
			opts.KeyEpoch = o.i64("key_epoch")
		}
		opts.RequireAll = o.boolean("require_all")
		o.done()
		wraps, err := ValidateWrapRecipients(state, c.list("wraps"), opts)
		if c.has("expect_error") {
			expectCode(t, c, err)
		} else {
			if err != nil {
				t.Fatalf("%s: %v", c.path, err)
			}
			digest := mustOK(WrapsDigest(wraps))(t, c.path)
			eqStr(t, c.path+" wraps_digest", digest, c.str("wraps_digest"))
			if i == 0 {
				firstDigest = digest
			}
		}
		c.done()
		n.add(1)
	}
	// The rekey event in the first chain publishes the first wrap set's digest.
	rekey := newRec(t, "chains[0].events[8]", firstChain[8])
	body := rekey.obj("body")
	eqStr(t, "rekey body wraps_digest", body.str("wraps_digest"), firstDigest)
	n.add(1)

	for _, s := range f.recs("sas") {
		in := s.obj("input")
		sas := SASInput{VaultID: in.str("vault_id"), Initiator: in.str("initiator"), Joiner: in.raw("joiner"), NonceI: in.str("nonce_i"), NonceJ: in.str("nonce_j")}
		in.done()
		eqStr(t, s.path+" transcript", string(mustOK(SASTranscript(sas))(t, s.path)), s.str("transcript"))
		eqStr(t, s.path+" code", mustOK(SASCode(sas))(t, s.path), s.str("code"))
		eqStr(t, s.path+" digest", mustOK(SASDigest(sas))(t, s.path), s.str("digest"))
		s.done()
		n.add(1)
	}
}

func checkRecords(t *testing.T, f *rec, n *counter) {
	memberships := f.obj("memberships")
	keys := f.obj("vault_keys")
	vaultKeys := map[string][]byte{}
	for k := range keys.m {
		vaultKeys[k] = keys.b64(k)
	}
	keys.done()
	usedMemberships := map[string]bool{}
	for _, s := range f.recs("sequences") {
		mname := s.str("membership")
		usedMemberships[mname] = true
		events, ok := memberships.m[mname].([]any)
		if !ok {
			t.Fatalf("%s: unknown membership %q", s.path, mname)
		}
		state := mustOK(VerifyMembershipChain(events, VerifyChainOptions{}))(t, s.path)
		items := map[string]*ItemState{}
		var order []string
		for _, step := range s.recs("steps") {
			var conflictID string
			if cid := step.raw("conflict_id"); cid != nil {
				conflictID = step.str("conflict_id")
			}
			r, err := VerifyRecord(step.raw("record"), state)
			if err == nil {
				err = AuthorizeRecordWrite(state, r)
			}
			var next ItemState
			var outcome ApplyOutcome
			if err == nil {
				next, outcome, err = ApplyRecord(items[r.ItemID], r, conflictID)
			}
			if step.has("expect_error") {
				expectCode(t, step, err)
				step.done()
				n.add(1)
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", step.path, err)
			}
			eqJSON(t, step.path+" outcome", outcome, step.raw("outcome"))
			if _, seen := items[r.ItemID]; !seen {
				order = append(order, r.ItemID)
			}
			items[r.ItemID] = &next
			vk, ok := vaultKeys[strconv.FormatInt(r.KeyEpoch, 10)]
			if !ok {
				t.Fatalf("%s: no vault key for epoch %d", step.path, r.KeyEpoch)
			}
			payload := mustOK(OpenItem(vk, r.ItemContext(), r.Env))(t, step.path)
			eqJSON(t, step.path+" payload", payload, step.raw("payload"))
			step.done()
			n.add(1)
		}
		summary := make([]any, 0, len(order))
		list := make([]ItemState, 0, len(order))
		for _, id := range order {
			it := items[id]
			conflicts := make([]any, len(it.Conflicts))
			for i, c := range it.Conflicts {
				conflicts[i] = c.ConflictID
			}
			summary = append(summary, map[string]any{
				"item_id": it.ItemID, "revision": it.Revision, "tombstone": it.Tombstone,
				"tombstone_revision": it.TombstoneRevision, "head": it.Head, "conflicts": conflicts,
			})
			list = append(list, *it)
		}
		eqJSON(t, s.path+" final_items", summary, s.raw("final_items"))
		eqStr(t, s.path+" state_digest", mustOK(ComputeStateDigest(StateRows(list)))(t, s.path), s.str("state_digest"))
		s.done()
	}
	for k := range memberships.m {
		if !usedMemberships[k] {
			t.Errorf("records.json: membership %q is never exercised", k)
		}
		memberships.used[k] = true
	}
	memberships.done()
}

func checkpointView(r *rec) CheckpointView {
	v := CheckpointView{
		VaultID: r.str("vault_id"), MembershipSeq: r.i64("membership_seq"), MembershipHead: r.str("membership_head"),
		LogSeq: r.i64("log_seq"), StateDigest: r.str("state_digest"), KeyEpoch: r.i64("key_epoch"),
	}
	r.done()
	return v
}

func checkCheckpoints(t *testing.T, f *rec, n *counter) {
	state := mustOK(VerifyMembershipChain(f.list("membership_events"), VerifyChainOptions{}))(t, f.path)
	var firstDigest string
	for i, c := range f.recs("state_digest_cases") {
		var rows []StateRow
		for _, raw := range c.list("rows") {
			tuple, ok := raw.([]any)
			if !ok || len(tuple) != 3 {
				t.Fatalf("%s: row must be [item_id, revision, head]", c.path)
			}
			rows = append(rows, StateRow{ItemID: tuple[0].(string), Revision: tuple[1].(int64), Head: tuple[2].(string)})
		}
		eqStr(t, c.path+" digest", mustOK(ComputeStateDigest(rows))(t, c.path), c.str("digest"))
		if i == 0 {
			firstDigest = c.str("digest")
		}
		c.done()
		n.add(1)
	}
	cp := f.raw("checkpoint")
	got := mustOK(VerifyCheckpoint(cp, state))(t, "checkpoint")
	eqJSON(t, "checkpoint", got, cp)
	eqStr(t, "checkpoint state_digest", got.StateDigest, firstDigest)
	n.add(1)
	for _, c := range f.recs("invalid_checkpoints") {
		_, err := VerifyCheckpoint(c.raw("checkpoint"), state)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	rb := f.obj("rollback")
	witnessed := checkpointView(rb.obj("witnessed"))
	for _, c := range rb.recs("accept") {
		if err := CheckRollback(witnessed, checkpointView(c.obj("incoming"))); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		c.done()
		n.add(1)
	}
	for _, c := range rb.recs("reject") {
		expectCode(t, c, CheckRollback(witnessed, checkpointView(c.obj("incoming"))))
		c.done()
		n.add(1)
	}
	rb.done()
}

func auditHead(t *testing.T, c *rec, k string) *AuditHead {
	if c.raw(k) == nil {
		return nil
	}
	h := c.obj(k)
	out := &AuditHead{Seq: h.i64("seq"), Head: h.str("head")}
	h.done()
	return out
}

func checkAudit(t *testing.T, f *rec, n *counter) {
	key := f.b64("key")
	vaultID := f.str("vault_id")
	state := mustOK(VerifyMembershipChain(f.list("membership_events"), VerifyChainOptions{}))(t, f.path)
	mustOK(VerifyAuditCheckpoint(f.raw("checkpoint"), state))(t, "checkpoint")
	n.add(1)
	for _, c := range f.recs("invalid_checkpoints") {
		_, err := VerifyAuditCheckpoint(c.raw("checkpoint"), state)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("cases") {
		chain := mustOK(VerifyAuditChain(c.list("entries"), key, vaultID, auditHead(t, c, "witnessed")))(t, c.path)
		events := make([]any, len(chain.Events))
		for i, e := range chain.Events {
			events[i] = e
		}
		var head any
		if chain.Head != nil {
			head = *chain.Head
		}
		eqJSON(t, c.path+" events", events, c.raw("events"))
		eqJSON(t, c.path+" head", head, c.raw("head"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := VerifyAuditChain(c.list("entries"), key, vaultID, auditHead(t, c, "witnessed"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

// effectiveGrantRaw mirrors the TS effectiveGrant(local, policy, sensitivity)
// on untyped input: the local grant is validated first.
func effectiveGrantRaw(local, policy, sensitivity any) (LocalGrant, error) {
	g, err := ParseLocalGrant(local)
	if err != nil {
		return LocalGrant{}, err
	}
	s, ok := sensitivity.(string)
	if !ok {
		return LocalGrant{}, badRequest("sensitivity must be a string")
	}
	return EffectiveGrant(g, policy, s)
}

func checkPolicy(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		local := mustOK(ParseLocalGrant(c.raw("local")))(t, c.path)
		grant := mustOK(effectiveGrantRaw(c.raw("local"), c.raw("policy"), c.raw("sensitivity")))(t, c.path)
		eqJSON(t, c.path+" grant", grant, c.raw("expected"))
		if grant.TTLs > local.TTLs {
			t.Errorf("%s: grant widened ttl", c.path)
		}
		for _, p := range grant.Projects {
			if !contains(local.Projects, p) {
				t.Errorf("%s: grant widened projects", c.path)
			}
		}
		for _, a := range grant.Agents {
			if !contains(local.Agents, a) {
				t.Errorf("%s: grant widened agents", c.path)
			}
		}
		if (local.RequireApproval || c.raw("sensitivity") == SensitivityHigh) && !grant.RequireApproval {
			t.Errorf("%s: grant dropped require_approval", c.path)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := effectiveGrantRaw(c.raw("local"), c.raw("policy"), c.raw("sensitivity"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkProof(t *testing.T, f *rec, n *counter) {
	signPub := f.b64("sign_pub")
	b := f.obj("build")
	header := mustOK(BuildProof(BuildProofArgs{
		HTM: b.str("htm"), HTU: b.str("htu"), TS: b.i64("ts"), JTI: b.str("jti"), Token: b.str("token"),
		Body: b.b64("body"), SecretKey: f.b64("sign_seed"),
	}))(t, b.path)
	eqStr(t, b.path+" header", header, b.str("header"))
	b.done()
	n.add(1)
	opts := func(c *rec) VerifyProofOptions {
		v := c.obj("verify")
		var seen []string
		for _, j := range v.list("seen_jtis") {
			seen = append(seen, j.(string))
		}
		o := VerifyProofOptions{
			HTM: v.str("htm"), HTU: v.str("htu"), Token: v.str("token"), Body: v.b64("body"), NowMs: v.i64("now"),
			SignPub: signPub, IsReplay: func(jti string) bool { return contains(seen, jti) },
		}
		v.done()
		return o
	}
	for _, c := range f.recs("cases") {
		p := mustOK(VerifyProof(c.str("header"), opts(c)))(t, c.path)
		eqJSON(t, c.path+" proof", p, c.raw("proof"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := VerifyProof(c.str("header"), opts(c))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}
