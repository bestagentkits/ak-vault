package akv1

import "testing"

// enroll-commit.json: committed device enrollment (spec §3.9).

func sas2InputOf(r *rec) SAS2Input {
	return SAS2Input{
		VaultID: r.str("vault_id"), VaultOrigin: r.str("vault_origin"), TrustAnchor: r.str("trust_anchor"),
		Initiator: r.str("initiator"), Joiner: r.raw("joiner"), NonceI: r.str("nonce_i"), NonceJ: r.str("nonce_j"),
	}
}

func checkEnrollCommit(t *testing.T, f *rec, n *counter) {
	join := f.raw("join")
	jc := mustOK(ParseJoin2Code(f.str("join_code")))(t, "join_code")
	eqJSON(t, "parsed join", dropHeader(jc.JSONValue()), join)
	eqStr(t, "encoded join", mustOK(EncodeJoin2Code(jc))(t, "encode join"), f.str("join_code"))

	offer := f.raw("offer")
	oc := mustOK(ParseOffer2Code(f.str("offer_code")))(t, "offer_code")
	eqJSON(t, "parsed offer", dropHeader(oc.JSONValue()), offer)
	eqStr(t, "encoded offer", mustOK(EncodeOffer2Code(oc))(t, "encode offer"), f.str("offer_code"))

	reveal := f.raw("reveal")
	rc := mustOK(ParseReveal2Code(f.str("reveal_code")))(t, "reveal_code")
	eqJSON(t, "parsed reveal", dropHeader(rc.JSONValue()), reveal)
	eqStr(t, "encoded reveal", mustOK(EncodeReveal2Code(rc))(t, "encode reveal"), f.str("reveal_code"))
	n.add(6)

	// v1 and v2 parsers refuse each other's codes.
	if _, err := ParseJoinCode(f.str("join_code")); CodeOf(err) != CodeBadRequest {
		t.Errorf("v1 join parser accepted a v2 code: %v", err)
	}
	if _, err := ParseOfferCode(f.str("offer_code")); CodeOf(err) != CodeBadRequest {
		t.Errorf("v1 offer parser accepted a v2 code: %v", err)
	}
	n.add(2)

	commit := f.obj("commit")
	got := mustOK(NonceJCommit(commit.str("nonce_j")))(t, "commit")
	eqStr(t, "nonce_j_commit", got, commit.str("nonce_j_commit"))
	eqStr(t, "join commit", jc.NonceJCommit, got)
	eqStr(t, "offer commit", oc.NonceJCommit, got)
	eqStr(t, "reveal nonce_j", rc.NonceJ, commit.str("nonce_j"))
	commit.done()
	n.add(4)

	for _, c := range f.recs("reveal_check") {
		c.str("name")
		err := VerifyNonceJReveal(c.str("nonce_j_commit"), c.str("nonce_j"))
		if want := c.str("expect"); want == "ok" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", c.path, err)
			}
		} else if CodeOf(err) != want {
			t.Errorf("%s: want %s, got %v", c.path, want, err)
		}
		c.done()
		n.add(1)
	}

	sas := f.obj("sas2")
	in := sas2InputOf(sas.obj("input"))
	transcript := mustOK(SAS2Transcript(in))(t, "sas2 transcript")
	eqStr(t, "sas2 transcript", string(transcript), sas.str("transcript_text"))
	eqStr(t, "sas2 code", mustOK(SAS2Code(in))(t, "sas2 code"), sas.str("code"))
	digest := mustOK(SAS2Digest(in))(t, "sas2 digest")
	eqStr(t, "sas2 digest", digest, sas.str("digest"))
	legacy := mustOK(SASCode(SASInput{VaultID: in.VaultID, Initiator: in.Initiator, Joiner: in.Joiner, NonceI: in.NonceI, NonceJ: in.NonceJ}))(t, "legacy code")
	eqStr(t, "legacy code", legacy, sas.str("legacy_code"))
	n.add(4)
	for _, c := range sas.recs("changed") {
		c.str("name")
		d := mustOK(SAS2Digest(sas2InputOf(c.obj("input"))))(t, c.path)
		eqStr(t, c.path+" digest", d, c.str("digest"))
		if d == digest {
			t.Errorf("%s: digest did not change", c.path)
		}
		c.done()
		n.add(1)
	}
	sas.done()

	g := f.obj("ground_sas")
	gin := sas2InputOf(g.obj("sas_input"))
	gin.NonceJ = g.str("ground_nonce_j")
	eqStr(t, "ground code", mustOK(SAS2Code(gin))(t, "ground code"), g.str("target_code"))
	expectCode(t, g, VerifyNonceJReveal(g.str("forged_commit"), g.str("ground_nonce_j")))
	g.done()
	n.add(2)

	for _, c := range f.recs("invalid_join") {
		_, err := ParseJoin2Code(c.str("code_text"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid_offer") {
		_, err := ParseOffer2Code(c.str("code_text"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid_reveal") {
		_, err := ParseReveal2Code(c.str("code_text"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

// dropHeader removes v and ctx from a code object, matching the vectors' objects.
func dropHeader(v any) map[string]any {
	m := v.(map[string]any)
	delete(m, "v")
	delete(m, "ctx")
	return m
}
