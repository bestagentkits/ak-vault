package akv1

import "testing"

func init() { vectorHandlers["lease.json"] = checkLease }

func leaseStrings(t *testing.T, v any, what string) []string {
	t.Helper()
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: expected an array", what)
	}
	out := make([]string, len(list))
	for i, s := range list {
		if out[i], ok = s.(string); !ok {
			t.Fatalf("%s: expected strings", what)
		}
	}
	return out
}

func checkLease(t *testing.T, f *rec, n *counter) {
	keys := sealKeys(t)
	devices := map[string]approvalDevice{}
	for _, d := range f.recs("devices") {
		_ = d.b64("kx_secret") // device fixtures share one shape; leases never use kx
		r := d.obj("record")
		devices[d.str("name")] = approvalDevice{seed: d.b64("sign_seed"), id: r.str("device_id"), signPub: r.str("sign_pub")}
		for _, k := range []string{"kx_pub", "account", "role", "kind"} {
			r.str(k)
		}
		r.done()
		d.done()
	}
	approver := devices["alice-laptop"]
	account, vaultID := f.str("account"), f.str("vault_id")
	requestSeed, leaseSecret, leasePub := f.b64("request_seed"), f.b64("lease_secret"), f.b64("lease_pub")
	eqStr(t, "requester_key", B64Encode(mustOK(SignPublicKey(requestSeed))(t, "request_seed")), f.str("requester_key"))
	eqStr(t, "lease_pub", B64Encode(mustOK(KxPublicKey(leaseSecret))(t, "lease_secret")), B64Encode(leasePub))

	var first any
	var vars []string
	for _, c := range f.recs("requests") {
		epoch := c.i64("key_epoch")
		raw := c.raw("wire")
		wire := mustOK(ParseLeaseRequest(raw))(t, c.path+".wire")
		subject := mustOK(ParseLeaseSubject(c.raw("subject")))(t, c.path+".subject")
		if first == nil {
			first, vars = raw, subject.Vars()
		}
		got := mustOK(sealLeaseRequestWithVectorValues(requestSeed, SealLeaseRequestArgs{
			VaultID: wire.VaultID, KeyEpoch: epoch, Account: wire.Account, SealPub: keys[epoch].public, LeasePub: leasePub,
			TTLS: wire.TTLS, TS: wire.TS, ExpiresAt: wire.ExpiresAt, Subject: subject,
		}, leaseVectorValues{leaseID: wire.LeaseID, esk: c.b64("esk"), nonce: mustOK(B64Decode(wire.N))(t, c.path+".n")}))(t, c.path)
		eqJSON(t, c.path+" wire", got, raw)
		eqStr(t, c.path+" plaintext", string(mustOK(CJSON(subject))(t, c.path)), c.str("plaintext"))
		eqStr(t, c.path+" digest", mustOK(LeaseRequestDigest(raw))(t, c.path), c.str("digest"))
		eqJSON(t, c.path+" verify", mustOK(VerifyLeaseRequestSignature(raw))(t, c.path+" verify"), raw)
		_, opened, digest, err := OpenLeaseRequest(keys[epoch].secret, raw, wire.VaultID, wire.Account, c.str("digest"))
		if err != nil {
			t.Fatalf("%s open: %v", c.path, err)
		}
		eqJSON(t, c.path+" opened subject", opened, c.raw("subject"))
		eqStr(t, c.path+" opened digest", digest, c.str("digest"))
		c.str("name")
		c.done()
		n.add(1)
	}
	firstWire := mustOK(ParseLeaseRequest(first))(t, "requests[0]")

	for _, c := range f.recs("grants") {
		raw := c.raw("grant")
		g := mustOK(ParseLeaseGrant(raw))(t, c.path+".grant")
		args := SignLeaseGrantArgs{Request: first, Decision: g.Decision, ApproverKey: mustOK(B64Decode(approver.signPub))(t, c.path), TS: g.TS, RequestedVars: vars}
		var fixed leaseVectorValues
		if g.Decision == LeaseAllow {
			p := mustOK(ParseLeasePayload(c.raw("payload")))(t, c.path+".payload")
			args.Payload = &p
			if g.ExpiresAt != g.TS+firstWire.TTLS*1000 {
				args.ExpiresAt = g.ExpiresAt
			}
			fixed = leaseVectorValues{esk: c.b64("esk"), nonce: mustOK(B64Decode(g.N))(t, c.path+".n")}
			eqStr(t, c.path+" plaintext", string(mustOK(CJSON(p))(t, c.path)), c.str("plaintext"))
		} else {
			for _, k := range []string{"esk", "payload", "plaintext"} {
				if c.raw(k) != nil {
					t.Errorf("%s.%s: expected null on a deny", c.path, k)
				}
			}
		}
		eqJSON(t, c.path+" grant", mustOK(signLeaseGrantWithVectorValues(approver.seed, args, fixed))(t, c.path), raw)
		opened, payload, err := OpenLeaseGrant(leaseSecret, raw, first, c.i64("now"), vars, nil)
		if err != nil {
			t.Fatalf("%s open: %v", c.path, err)
		}
		eqStr(t, c.path+" decision", opened.Decision, g.Decision)
		if g.Decision == LeaseAllow {
			eqJSON(t, c.path+" opened payload", payload, c.raw("payload"))
		}
		c.str("name")
		c.done()
		n.add(1)
	}

	for _, c := range f.recs("request_invalid") {
		_, _, _, err := OpenLeaseRequest(keys[c.i64("open_with_epoch")].secret, c.raw("wire"), c.str("vault_id"), c.str("account"), c.str("lease_code"))
		expectCode(t, c, err)
		c.str("name")
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("grant_invalid") {
		var approvers []string
		if c.has("approvers") {
			approvers = leaseStrings(t, c.raw("approvers"), c.path+".approvers")
		}
		_, _, err := OpenLeaseGrant(c.b64("lease_secret"), c.raw("grant"), c.raw("request"), c.i64("now"), leaseStrings(t, c.raw("requested_vars"), c.path+".requested_vars"), approvers)
		expectCode(t, c, err)
		c.str("name")
		c.done()
		n.add(1)
	}
	checkLeaseRoundTrip(t, keys[3], account, vaultID, approver, vars)
	n.add(1)
}

// checkLeaseRoundTrip runs fresh keys end to end and the signer-side refusals.
func checkLeaseRoundTrip(t *testing.T, sk sealKeyVector, account, vaultID string, approver approvalDevice, vars []string) {
	leaseSecret, leasePub, requestSeed, requestPub, err := GenerateLeaseKeys()
	if err != nil {
		t.Fatal(err)
	}
	subject := LeaseSubject{Secrets: []LeaseRef{{Var: "STRIPE_KEY", Ref: "a"}, {Var: "DB_URL", Ref: "b"}}}
	w := mustOK(SealLeaseRequest(requestSeed, SealLeaseRequestArgs{
		VaultID: vaultID, KeyEpoch: 3, Account: account, SealPub: sk.public, LeasePub: leasePub, TTLS: 60, TS: 1000, ExpiresAt: 61000, Subject: subject,
	}))(t, "round trip seal")
	code := mustOK(LeaseRequestDigest(w))(t, "round trip digest")
	_, opened, _, err := OpenLeaseRequest(sk.secret, w, vaultID, account, code)
	if err != nil {
		t.Fatalf("round trip open: %v", err)
	}
	approverKey := mustOK(B64Decode(approver.signPub))(t, "approver key")
	payload := LeasePayload{Secrets: []LeaseValue{{Var: "DB_URL", Value: "v"}}}
	g := mustOK(SignLeaseGrant(approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseAllow, Payload: &payload, ApproverKey: approverKey, TS: 2000, RequestedVars: opened.Vars()}))(t, "round trip grant")
	if g.ExpiresAt != 62000 {
		t.Errorf("round trip expires_at = %d, want 62000", g.ExpiresAt)
	}
	_, got, err := OpenLeaseGrant(leaseSecret, g, w, 2000, vars, []string{approver.id})
	if err != nil {
		t.Fatalf("round trip open grant: %v", err)
	}
	eqJSON(t, "round trip payload", got, payload)

	refusals := []struct {
		name, want string
		seed       []byte
		args       SignLeaseGrantArgs
	}{
		{"self grant", CodeForbidden, requestSeed, SignLeaseGrantArgs{Request: w, Decision: LeaseDeny, ApproverKey: requestPub, TS: 2000}},
		{"unrequested var", CodeForbidden, approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseAllow, Payload: &LeasePayload{Secrets: []LeaseValue{{Var: "OTHER", Value: "v"}}}, ApproverKey: approverKey, TS: 2000, RequestedVars: []string{"DB_URL"}}},
		{"expiry beyond ttl", CodeBadRequest, approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseAllow, Payload: &payload, ApproverKey: approverKey, TS: 2000, ExpiresAt: 2000 + 60001, RequestedVars: []string{"DB_URL"}}},
		{"deny with values", CodeBadRequest, approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseDeny, Payload: &payload, ApproverKey: approverKey, TS: 2000}},
		{"allow without values", CodeBadRequest, approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseAllow, ApproverKey: approverKey, TS: 2000}},
		{"approver key not the seed", CodeBadRequest, approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseDeny, ApproverKey: requestPub, TS: 2000}},
		{"before request", CodeBadRequest, approver.seed, SignLeaseGrantArgs{Request: w, Decision: LeaseDeny, ApproverKey: approverKey, TS: 999}},
	}
	for _, r := range refusals {
		if _, err := SignLeaseGrant(r.seed, r.args); CodeOf(err) != r.want {
			t.Errorf("round trip %s: got %v, want %s", r.name, err, r.want)
		}
	}
}
