package akv1

import "testing"

func init() { vectorHandlers["approval.json"] = checkApproval }

type approvalDevice struct {
	seed    []byte
	id      string
	signPub string
}

func checkApproval(t *testing.T, f *rec, n *counter) {
	keys := sealKeys(t)
	devices := map[string]approvalDevice{}
	for _, d := range f.recs("devices") {
		_ = d.b64("kx_secret") // device fixtures share one shape; approvals never use kx
		r := d.obj("record")
		devices[d.str("name")] = approvalDevice{seed: d.b64("sign_seed"), id: r.str("device_id"), signPub: r.str("sign_pub")}
		for _, k := range []string{"kx_pub", "account", "role", "kind"} {
			r.str(k)
		}
		r.done()
		d.done()
	}
	requester, approver := devices["alice-phone"], devices["alice-laptop"]

	var first any
	for _, c := range f.recs("cases") {
		epoch := c.i64("key_epoch")
		wire := mustOK(ParseApprovalRequest(c.raw("wire")))(t, c.path+".wire")
		if first == nil {
			first = c.raw("wire")
		}
		subject := mustOK(ParseApprovalSubject(c.raw("subject")))(t, c.path+".subject")
		got := mustOK(SealApprovalRequest(SealApprovalRequestArgs{
			VK: keys[epoch].vk, SignSecret: requester.seed, VaultID: wire.VaultID, KeyEpoch: epoch, Requester: requester.id,
			RequestID: wire.RequestID, TS: wire.TS, ExpiresAt: wire.ExpiresAt, Subject: subject,
			nonce: mustOK(B64Decode(wire.N))(t, c.path+".n"),
		}))(t, c.path)
		eqJSON(t, c.path+" wire", got, c.raw("wire"))
		eqStr(t, c.path+" plaintext", string(mustOK(CJSON(subject))(t, c.path)), c.str("plaintext"))
		_, opened, err := OpenApprovalRequest(keys[epoch].vk, c.raw("wire"), wire.VaultID, requester.signPub)
		if err != nil {
			t.Fatalf("%s open: %v", c.path, err)
		}
		eqJSON(t, c.path+" opened subject", opened, c.raw("subject"))
		eqStr(t, c.path+" digest", mustOK(ApprovalRequestDigest(c.raw("wire")))(t, c.path), c.str("digest"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("decisions") {
		want := mustOK(ParseApprovalDecision(c.raw("decision")))(t, c.path)
		got := mustOK(SignApprovalDecision(approver.seed, first, want.Decision, want.TTLS, approver.id, want.TS))(t, c.path)
		eqJSON(t, c.path+" decision", got, c.raw("decision"))
		mustOK(VerifyApprovalDecision(c.raw("decision"), first, approver.signPub, 86400))(t, c.path+" verify")
		c.str("name")
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		dev := devices[c.str("requester_device")]
		_, _, err := OpenApprovalRequest(keys[c.i64("open_with_epoch")].vk, c.raw("wire"), c.str("vault_id"), dev.signPub)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("decision_invalid") {
		dev := devices[c.str("approver_device")]
		_, err := VerifyApprovalDecision(c.raw("decision"), c.raw("request"), dev.signPub, c.i64("max_ttl_s"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}
