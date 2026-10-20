package akv1

// Unit tests for the remote-access additions (spec §3.6–§3.8, §5.1, §9.7)
// with fixed small inputs. The cross-language vectors are checked in
// vectors_remote_access_test.go.

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func fixedBytes(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func fixedID(b byte) string { return B64Encode(fixedBytes(b, IDBytes)) }

type raFixture struct {
	vaultID      string
	owner, extra DeviceKeys // human owner devices; extra joins at seq 2
	machine      DeviceKeys // machine owner device from genesis
	events       []any
	vk1, vk2     []byte
}

// newRAFixture builds genesis (seq 0, epoch 1), rekey (seq 1, epoch 2) and a
// device_add of a second human owner device (seq 2).
func newRAFixture(t *testing.T) raFixture {
	t.Helper()
	f := raFixture{vaultID: fixedID(0x11), vk1: fixedBytes(0x21, 32), vk2: fixedBytes(0x22, 32)}
	f.owner = mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindHuman, fixedBytes(1, 32), fixedBytes(2, 32)))(t, "owner")
	f.machine = mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindMachine, fixedBytes(3, 32), fixedBytes(4, 32)))(t, "machine")
	f.extra = mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindHuman, fixedBytes(5, 32), fixedBytes(6, 32)))(t, "extra")
	recovery := mustOK(SignPublicKey(fixedBytes(7, 32)))(t, "recovery")
	digest := B64Encode(fixedBytes(9, 32))
	g := mustOK(BuildGenesisEvent(f.vaultID, 1000, f.owner.Record.DeviceID, map[string]any{
		"vault_kind": VaultPersonal, "owner_account": "acct-1", "recovery_sign_pub": B64Encode(recovery),
		"devices": []any{f.owner.Record.JSONValue(), f.machine.Record.JSONValue()}, "wraps_digest": digest,
	}, f.owner.SignSecret))(t, "genesis")
	s0 := mustOK(VerifyMembershipChain([]any{g}, VerifyChainOptions{}))(t, "chain0")
	rk := mustOK(NextMembershipEvent(s0, EventRekey, 2000, f.owner.Record.DeviceID, map[string]any{
		"new_key_epoch": int64(2), "wraps_digest": digest, "needs_rotate": []any{},
	}, f.owner.SignSecret))(t, "rekey")
	s1 := mustOK(VerifyMembershipChain([]any{g, rk}, VerifyChainOptions{}))(t, "chain1")
	add := mustOK(NextMembershipEvent(s1, EventDeviceAdd, 3000, f.owner.Record.DeviceID, map[string]any{
		"device": f.extra.Record.JSONValue(), "sas": digest, "wraps_digest": digest,
	}, f.owner.SignSecret))(t, "device_add")
	f.events = []any{g, rk, add}
	mustOK(VerifyMembershipChain(f.events, VerifyChainOptions{}))(t, "chain2")
	return f
}

func (f raFixture) doc(t *testing.T, signer DeviceKeys, vk []byte, epoch, seq int64) SealKeyDoc {
	t.Helper()
	return mustOK(BuildSealKeyDoc(BuildSealKeyDocArgs{VK: vk, VaultID: f.vaultID, KeyEpoch: epoch, MembershipSeq: seq, Author: signer.Record.DeviceID, TS: 5000, SignSeed: signer.SignSecret}))(t, "build doc")
}

func TestSealKeyDocVerify(t *testing.T) {
	f := newRAFixture(t)
	verify := func(doc any, vk []byte) error {
		_, err := VerifySealKeyDoc(doc, f.events, VerifySealKeyDocOptions{VK: vk})
		return err
	}
	if err := verify(f.doc(t, f.owner, f.vk1, 1, 0), f.vk1); err != nil {
		t.Errorf("epoch 1 at seq 0: %v", err)
	}
	if err := verify(f.doc(t, f.extra, f.vk2, 2, 2), f.vk2); err != nil {
		t.Errorf("epoch 2 at seq 2 by the added device: %v", err)
	}
	if err := verify(f.doc(t, f.owner, f.vk2, 2, 1), nil); err != nil {
		t.Errorf("epoch 2 at seq 1 without VK: %v", err)
	}
	wantCode(t, "wrong epoch at seq", verify(f.doc(t, f.owner, f.vk2, 2, 0), nil), CodeBadRequest)
	wantCode(t, "seq beyond head", verify(f.doc(t, f.owner, f.vk2, 2, 3), nil), CodeBadRequest)
	wantCode(t, "author not yet added", verify(f.doc(t, f.extra, f.vk1, 1, 0), nil), CodeForbidden)
	wantCode(t, "machine author", verify(f.doc(t, f.machine, f.vk2, 2, 2), nil), CodeForbidden)
	wantCode(t, "seal_pub not from VK", verify(f.doc(t, f.owner, f.vk1, 1, 0), fixedBytes(0x55, 32)), CodeForbidden)

	other := f.doc(t, f.owner, f.vk1, 1, 0)
	other.VaultID = fixedID(0x12)
	wantCode(t, "other vault", verify(other, nil), CodeBadRequest)
	tampered := f.doc(t, f.owner, f.vk1, 1, 0)
	tampered.TS++
	wantCode(t, "tampered", verify(tampered, nil), CodeInvalidSignature)
	v2 := f.doc(t, f.owner, f.vk1, 1, 0).JSONValue().(map[string]any)
	v2["v"] = int64(2)
	wantCode(t, "v 2", verify(v2, nil), CodeUnsupportedVersion)
	extra := f.doc(t, f.owner, f.vk1, 1, 0).JSONValue().(map[string]any)
	extra["x"] = int64(1)
	wantCode(t, "extra key", verify(extra, nil), CodeBadRequest)

	p1 := mustOK(DeriveSealKeyPair(f.vk1, f.vaultID, 1))(t, "pair1")
	p2 := mustOK(DeriveSealKeyPair(f.vk1, f.vaultID, 2))(t, "pair2")
	if bytes.Equal(p1.Public, p2.Public) {
		t.Error("seal_pub must differ per epoch")
	}
}

func sealFixture(t *testing.T, pt SealedOpPlaintext) (SealKeyPair, SealOpArgs) {
	t.Helper()
	pair := mustOK(DeriveSealKeyPair(fixedBytes(0x21, 32), fixedID(0x11), 1))(t, "pair")
	return pair, SealOpArgs{
		SealPub: pair.Public, VaultID: fixedID(0x11), KeyEpoch: 1, SealedID: fixedID(0x33),
		Origin: SealedOrigin{Kind: SealedOriginMCP, Account: "acct-1", ClientID: "client-a", GrantID: "grant-1"},
		TS:     1767225600000, Plaintext: pt, ephemeralSecret: fixedBytes(0x44, 32), nonce: fixedBytes(0x45, NonceBytes),
	}
}

func TestCheckSealedDrainContext(t *testing.T) {
	pair, args := sealFixture(t, SealedOpPlaintext{Op: SealedOpDelete, Name: "A"})
	op := mustOK(SealOp(args))(t, "seal")
	opened := mustOK(OpenSealedOp(pair.Secret, op.JSONValue(), args.VaultID))(t, "open")
	never := func(string) bool { return false }
	ok := SealedDrainOptions{Account: "acct-1", Now: op.TS, SealedTTLS: 60, Seen: never}
	if err := CheckSealedDrain(opened, ok); err != nil {
		t.Fatalf("fresh op: %v", err)
	}
	for name, o := range map[string]SealedDrainOptions{
		"zero ttl":      {Account: "acct-1", Now: op.TS, SealedTTLS: 0, Seen: never},
		"negative now":  {Account: "acct-1", Now: -1, SealedTTLS: 60, Seen: never},
		"no seen set":   {Account: "acct-1", Now: op.TS, SealedTTLS: 60},
		"empty account": {Account: "", Now: op.TS, SealedTTLS: 60, Seen: never},
		"long account":  {Account: strings.Repeat("a", MaxAccountLength+1), Now: op.TS, SealedTTLS: 60, Seen: never},
	} {
		if CodeOf(CheckSealedDrain(opened, o)) != CodeBadRequest {
			t.Errorf("%s: want bad_request", name)
		}
	}
	// Only OpenSealedOp produces an OpenedSealedOp; the zero value is refused.
	if CodeOf(CheckSealedDrain(OpenedSealedOp{}, ok)) != CodeBadRequest {
		t.Error("zero OpenedSealedOp: want bad_request")
	}
}

func TestSealedOpRoundTripsAndRefusals(t *testing.T) {
	for _, pt := range []SealedOpPlaintext{
		{Op: SealedOpSet, Name: "STRIPE_KEY", Value: "sk_test_1", Sensitivity: SensitivityHigh},
		{Op: SealedOpSet, Name: "EMPTY", Value: ""},
		{Op: SealedOpDelete, Name: "OLD"},
	} {
		pair, args := sealFixture(t, pt)
		op := mustOK(SealOp(args))(t, "seal")
		opened := mustOK(OpenSealedOp(pair.Secret, op.JSONValue(), args.VaultID))(t, "open")
		eqJSON(t, "plaintext", opened.Plaintext(), pt)
		eqJSON(t, "wire", opened.Wire(), op)
	}

	pair, args := sealFixture(t, SealedOpPlaintext{Op: SealedOpSet, Name: "N", Value: "v"})
	op := mustOK(SealOp(args))(t, "seal")
	open := func(m map[string]any) error {
		_, err := OpenSealedOp(pair.Secret, m, args.VaultID)
		return err
	}
	mutate := func(fn func(m map[string]any)) map[string]any {
		m := op.JSONValue().(map[string]any)
		m["origin"] = op.Origin.JSONValue()
		fn(m)
		return m
	}
	wrongEpoch := mustOK(DeriveSealKeyPair(fixedBytes(0x21, 32), fixedID(0x11), 2))(t, "pair2")
	_, err := OpenSealedOp(wrongEpoch.Secret, op.JSONValue(), args.VaultID)
	wantCode(t, "wrong epoch key", err, CodeDecryptFailed)
	wantCode(t, "tampered account", open(mutate(func(m map[string]any) { m["origin"].(map[string]any)["account"] = "acct-2" })), CodeDecryptFailed)
	wantCode(t, "tampered client", open(mutate(func(m map[string]any) { m["origin"].(map[string]any)["client_id"] = "client-b" })), CodeDecryptFailed)
	wantCode(t, "tampered ts", open(mutate(func(m map[string]any) { m["ts"] = int64(1) })), CodeDecryptFailed)
	wantCode(t, "tampered sealed_id", open(mutate(func(m map[string]any) { m["sealed_id"] = fixedID(0x34) })), CodeDecryptFailed)
	wantCode(t, "other vault", open(mutate(func(m map[string]any) { m["vault_id"] = fixedID(0x12) })), CodeBadRequest)
	wantCode(t, "unknown alg", open(mutate(func(m map[string]any) { m["alg"] = "x25519-xc20p" })), CodeUnsupportedVersion)
	wantCode(t, "v 2", open(mutate(func(m map[string]any) { m["v"] = int64(2) })), CodeUnsupportedVersion)
	wantCode(t, "origin kind", open(mutate(func(m map[string]any) { m["origin"].(map[string]any)["kind"] = "web" })), CodeBadRequest)
	wantCode(t, "origin extra key", open(mutate(func(m map[string]any) { m["origin"].(map[string]any)["x"] = "y" })), CodeBadRequest)
	wantCode(t, "non-ASCII grant", open(mutate(func(m map[string]any) { m["origin"].(map[string]any)["grant_id"] = "granté" })), CodeBadRequest)
	wantCode(t, "all-zero shared secret", open(mutate(func(m map[string]any) { m["epk"] = B64Encode(make([]byte, 32)) })), CodeBadRequest)

	// A plaintext that decrypts but breaks the rules is bad_request.
	for name, raw := range map[string]string{
		"delete with value":   `{"name":"N","op":"delete","value":"v"}`,
		"delete with sens":    `{"name":"N","op":"delete","sensitivity":"high"}`,
		"set without value":   `{"name":"N","op":"set"}`,
		"unknown op":          `{"name":"N","op":"rename"}`,
		"unknown key":         `{"name":"N","op":"set","value":"v","x":1}`,
		"not canonical":       `{"op":"set","name":"N","value":"v"}`,
		"empty name":          `{"name":"","op":"set","value":"v"}`,
		"unknown sensitivity": `{"name":"N","op":"set","sensitivity":"low","value":"v"}`,
	} {
		bad := op
		shared := mustOK(X25519Shared(args.ephemeralSecret, pair.Public))(t, name)
		epk, _ := B64Decode(op.Epk)
		ct := mustOK(XC20PSeal(deriveSealKey(shared, epk, pair.Public), args.nonce, []byte(raw), sealedOpAAD(op)))(t, name)
		bad.Ct = B64Encode(ct)
		wantCode(t, name, open(bad.JSONValue().(map[string]any)), CodeBadRequest)
	}

	_, big := sealFixture(t, SealedOpPlaintext{Op: SealedOpSet, Name: "N", Value: strings.Repeat("a", 65520)})
	_, err = SealOp(big)
	wantCode(t, "oversize plaintext", err, CodeBadRequest)
}

func TestNameTags(t *testing.T) {
	vk := fixedBytes(0x21, 32)
	k1 := mustOK(NameIndexKey(vk, fixedID(0x11), 1))(t, "k1")
	k2 := mustOK(NameIndexKey(vk, fixedID(0x11), 2))(t, "k2")
	kv := mustOK(NameIndexKey(vk, fixedID(0x12), 1))(t, "kv")
	nfc := mustOK(NameTag(k1, "café"))(t, "nfc")
	if nfd := mustOK(NameTag(k1, "café"))(t, "nfd"); nfd != nfc {
		t.Error("NFC and NFD spellings must give the same tag")
	}
	if mustOK(NameTag(k2, "café"))(t, "e2") == nfc || mustOK(NameTag(kv, "café"))(t, "v2") == nfc {
		t.Error("another epoch or vault must give another tag")
	}
	if b, _ := B64Decode(nfc); len(b) != NameTagBytes {
		t.Errorf("tag length %d", len(b))
	}
	_, err := NameTag(k1, "")
	wantCode(t, "empty name", err, CodeBadRequest)
	_, err = NameTag(k1, "\xff")
	wantCode(t, "invalid UTF-8", err, CodeBadRequest)

	rec := SignedRecord{KeyEpoch: 2}
	_, err = NewItemPutBody(rec, &ItemNameTag{KeyEpoch: 1, Tag: nfc})
	wantCode(t, "tag epoch mismatch", err, CodeBadRequest)
	rec.Tombstone = true
	_, err = NewItemPutBody(rec, &ItemNameTag{KeyEpoch: 2, Tag: nfc})
	wantCode(t, "tag on tombstone", err, CodeBadRequest)
}

func enrollFixture(t *testing.T) (JoinCode, OfferCode) {
	t.Helper()
	dev := mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindHuman, fixedBytes(1, 32), fixedBytes(2, 32)))(t, "dev")
	join := JoinCode{Account: "acct-1", Device: dev.Record, NonceJ: fixedID(0x61), Label: "laptop (work)"}
	cp := mustOK(SignCheckpoint(Checkpoint{VaultID: fixedID(0x11), MembershipSeq: 2, MembershipHead: B64Encode(fixedBytes(8, 32)), LogSeq: 0, StateDigest: B64Encode(fixedBytes(9, 32)), KeyEpoch: 1, TS: 1000, Author: dev.Record.DeviceID}, dev.SignSecret))(t, "cp")
	offer := OfferCode{VaultOrigin: "https://vault.agentkit.best", VaultID: fixedID(0x11), Initiator: fixedID(0x71), Joiner: dev.Record.DeviceID, NonceI: fixedID(0x62), NonceJ: fixedID(0x61), TrustAnchor: dev.Record.SignPub, Checkpoint: cp}
	return join, offer
}

func TestEnrollCodes(t *testing.T) {
	join, offer := enrollFixture(t)
	jc := mustOK(EncodeJoinCode(join))(t, "join")
	oc := mustOK(EncodeOfferCode(offer))(t, "offer")
	if !strings.HasPrefix(jc, JoinCodePrefix) || !strings.HasPrefix(oc, OfferCodePrefix) {
		t.Fatal("prefixes")
	}
	eqJSON(t, "join round trip", mustOK(ParseJoinCode(jc))(t, "parse join"), join)
	eqJSON(t, "offer round trip", mustOK(ParseOfferCode(oc))(t, "parse offer"), offer)
	split := oc[:20] + "\n  " + oc[20:40] + " \t" + oc[40:] + "　"
	eqJSON(t, "split offer", mustOK(ParseOfferCode(split))(t, "split"), offer)

	encodeRaw := func(prefix string, obj map[string]any) string {
		return prefix + B64Encode(mustOK(CJSON(obj))(t, "cjson"))
	}
	joinObj := func(fn func(m map[string]any)) string {
		m := join.JSONValue().(map[string]any)
		fn(m)
		return encodeRaw(JoinCodePrefix, m)
	}
	offerObj := func(fn func(m map[string]any)) string {
		m := offer.JSONValue().(map[string]any)
		fn(m)
		return encodeRaw(OfferCodePrefix, m)
	}
	parseJ := func(c string) error { _, err := ParseJoinCode(c); return err }
	parseO := func(c string) error { _, err := ParseOfferCode(c); return err }

	wantCode(t, "join as offer", parseO(OfferCodePrefix+jc[len(JoinCodePrefix):]), CodeBadRequest)
	wantCode(t, "wrong prefix", parseJ("akj2-"+jc[len(JoinCodePrefix):]), CodeBadRequest)
	wantCode(t, "oversize", parseJ(JoinCodePrefix+strings.Repeat("A", MaxEnrollCodeBytes)), CodeBadRequest)
	wantCode(t, "v 2", parseJ(joinObj(func(m map[string]any) { m["v"] = int64(2) })), CodeUnsupportedVersion)
	wantCode(t, "extra key", parseJ(joinObj(func(m map[string]any) { m["x"] = int64(1) })), CodeBadRequest)
	wantCode(t, "missing key", parseJ(joinObj(func(m map[string]any) { delete(m, "label") })), CodeBadRequest)
	wantCode(t, "wrong ctx", parseJ(joinObj(func(m map[string]any) { m["ctx"] = OfferCodeContext })), CodeBadRequest)
	wantCode(t, "non-ASCII label", parseJ(joinObj(func(m map[string]any) { m["label"] = "café" })), CodeBadRequest)
	wantCode(t, "long label", parseJ(joinObj(func(m map[string]any) { m["label"] = strings.Repeat("a", 65) })), CodeBadRequest)
	wantCode(t, "account mismatch", parseJ(joinObj(func(m map[string]any) { m["account"] = "acct-2" })), CodeBadRequest)
	wantCode(t, "non-canonical json", parseJ(JoinCodePrefix+B64Encode([]byte(`{"v":1, "ctx":"x"}`))), CodeBadRequest)
	machine := mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindMachine, fixedBytes(3, 32), fixedBytes(4, 32)))(t, "m")
	wantCode(t, "machine device", parseJ(joinObj(func(m map[string]any) { m["device"] = machine.Record.JSONValue() })), CodeBadRequest)
	editor := mustOK(CreateDeviceKeys("acct-1", RoleEditor, KindHuman, fixedBytes(3, 32), fixedBytes(4, 32)))(t, "e")
	wantCode(t, "non-owner device", parseJ(joinObj(func(m map[string]any) { m["device"] = editor.Record.JSONValue() })), CodeBadRequest)
	other := offer
	other.VaultID = fixedID(0x12)
	_, err := EncodeOfferCode(other)
	wantCode(t, "checkpoint of another vault", err, CodeBadRequest)

	for origin, ok := range map[string]bool{
		"https://vault.agentkit.best": true, "https://vault.agentkit.best:8443": true, "http://localhost:8787": true,
		"http://127.0.0.2": true, "http://[::1]:8787": true,
		"https://Vault.agentkit.best": false, "HTTPS://vault.agentkit.best": false, "https://vault.agentkit.best/": false,
		"https://vault.agentkit.best:443": false, "https://vault.agentkit.best.": false, "https://u@vault.agentkit.best": false,
		"https://vault.agentkit.best?x": false, "https://vault.agentkit.best#x": false, "http://vault.agentkit.best": false,
		"http://localhost:80": false, "ftp://vault.agentkit.best": false, "https://vault.agentkit.best:": false,
		"http://[0:0:0:0:0:0:0:1]": false, "https://vault.agentkit.best:0443": false, "": false,
	} {
		err := parseO(offerObj(func(m map[string]any) { m["vault_origin"] = origin }))
		if ok && err != nil {
			t.Errorf("origin %q: %v", origin, err)
		}
		if !ok {
			wantCode(t, "origin "+origin, err, CodeBadRequest)
		}
	}
}

func TestProfileValidation(t *testing.T) {
	by := fixedID(0x01)
	field := func(v any) map[string]any {
		return map[string]any{"value": v, "by": by, "at": int64(1), "src": ProfileSrcLocal}
	}
	good := map[string]any{
		"provider": field("stripe"), "tags": field([]any{"billing", "live"}), "kind": field("api_key"),
		"sensitivity": field("high"), "expires_at": field("2027-02-28T23:59:59Z"), "rotate_url": field("https://dashboard.stripe.com/apikeys"),
		"description": field(strings.Repeat("é", 1024)),
	}
	if _, err := ValidateProfile(good); err != nil {
		t.Fatalf("good profile: %v", err)
	}
	bad := map[string]any{
		"unknown key":        map[string]any{"color": field("red")},
		"extra field key":    map[string]any{"provider": map[string]any{"value": "x", "by": by, "at": int64(1), "src": "local", "x": int64(1)}},
		"unknown src":        map[string]any{"provider": map[string]any{"value": "x", "by": by, "at": int64(1), "src": "sync"}},
		"over-length text":   map[string]any{"provider": field(strings.Repeat("a", 129))},
		"empty text":         map[string]any{"provider": field("")},
		"control char":       map[string]any{"provider": field("a\nb")},
		"bidi override":      map[string]any{"description": field("a‮b")},
		"line separator":     map[string]any{"description": field("a b")},
		"duplicate list":     map[string]any{"tags": field([]any{"a", "a"})},
		"comma in list":      map[string]any{"tags": field([]any{"a,b"})},
		"empty list":         map[string]any{"tags": field([]any{})},
		"long list item":     map[string]any{"tags": field([]any{strings.Repeat("a", 65)})},
		"list as text":       map[string]any{"tags": field("a")},
		"unknown kind":       map[string]any{"kind": field("ssh_key")},
		"unknown sens":       map[string]any{"sensitivity": field("low")},
		"bad expires":        map[string]any{"expires_at": field("2027-02-30T00:00:00Z")},
		"offset expires":     map[string]any{"expires_at": field("2027-02-28T00:00:00+00:00")},
		"http rotate url":    map[string]any{"rotate_url": field("http://x")},
		"bad by":             map[string]any{"provider": map[string]any{"value": "x", "by": "dev", "at": int64(1), "src": "local"}},
		"profile not object": []any{},
	}
	for name, p := range bad {
		_, err := ValidateProfile(p)
		wantCode(t, name, err, CodeBadRequest)
	}
	list := make([]any, 33)
	for i := range list {
		list[i] = strings.Repeat("x", i+1)
	}
	_, err := ValidateProfile(map[string]any{"tags": field(list)})
	wantCode(t, "33 list items", err, CodeBadRequest)
}

func TestCarryForwardMeta(t *testing.T) {
	got := CarryForwardMeta(map[string]any{
		"kind": "policy", "item_ids": []any{}, "policy": map[string]any{}, "profile": map[string]any{},
		"whentouse": "x", "usage_hosts": "x", "usagehosts": "x", "rotateurl": "x", "keep_me": "y",
	})
	eqJSON(t, "carried meta", got, map[string]any{"keep_me": "y"})
}

func TestRelayFrames(t *testing.T) {
	dev := mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindHuman, fixedBytes(1, 32), fixedBytes(2, 32)))(t, "dev")
	other := mustOK(CreateDeviceKeys("acct-1", RoleOwner, KindHuman, fixedBytes(3, 32), fixedBytes(4, 32)))(t, "other")
	hello := mustOK(SignHello(RelayFrame{Type: RelayHello, DeviceID: dev.Record.DeviceID, Vaults: []string{fixedID(0x11)}, Tools: []string{ToolSearch, ToolSet}, TS: 1000}, dev.SignSecret))(t, "hello")
	helloBytes := mustOK(CJSON(hello))(t, "cjson")
	mustOK(VerifyHello(helloBytes, VerifyHelloOptions{SignPub: dev.Record.SignPub, Now: 1000}))(t, "verify hello")
	_, err := VerifyHello(helloBytes, VerifyHelloOptions{SignPub: other.Record.SignPub, Now: 1000})
	wantCode(t, "hello under another key", err, CodeForbidden)
	_, err = VerifyHello(helloBytes, VerifyHelloOptions{SignPub: dev.Record.SignPub, Now: 1000 + ProofMaxSkewMs + 1})
	wantCode(t, "stale hello", err, CodeUnauthorized)

	ok := mustOK(SignResult(RelayFrame{Type: RelayResult, CallID: fixedID(0x21), OK: true, Result: map[string]any{"items": []any{}}}, dev.SignSecret))(t, "result")
	mustOK(VerifyResult(mustOK(CJSON(ok))(t, "cjson"), dev.Record.SignPub))(t, "verify result")
	byOther := mustOK(SignResult(RelayFrame{Type: RelayResult, CallID: fixedID(0x21), OK: false, ErrorCode: RelayErrDenied}, other.SignSecret))(t, "other result")
	_, err = VerifyResult(byOther, dev.Record.SignPub)
	wantCode(t, "result signed by another device", err, CodeInvalidSignature)

	frames := map[string]string{
		"ready":  `{"exp":1767225600,"type":"ready","v":1}`,
		"reauth": `{"proof":"p.q.r","token":"a.b.c","type":"reauth","v":1}`,
		"call":   `{"args":{"query":"stripe"},"call_id":"` + fixedID(0x21) + `","caller":{"client_id":"c","grant_id":"g","scopes":["vault-mcp:read"]},"deadline_ms":60000,"tool":"search","type":"call","v":1,"vault_id":"` + fixedID(0x11) + `"}`,
	}
	for name, raw := range frames {
		if _, err := ParseRelayFrame([]byte(raw), RelayFrameOptions{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	okMap := ok.JSONValue().(map[string]any)
	okMap["error"] = map[string]any{"code": "denied"}
	refused := map[string][]byte{
		"unknown type":    []byte(`{"type":"ping","v":1}`),
		"extra key":       []byte(`{"exp":1,"type":"ready","v":1,"x":1}`),
		"missing key":     []byte(`{"type":"ready","v":1}`),
		"not canonical":   []byte(`{"v":1,"type":"ready","exp":1}`),
		"ok with error":   mustOK(CJSON(okMap))(t, "cjson"),
		"unknown code":    []byte(`{"call_id":"` + fixedID(0x21) + `","error":{"code":"boom"},"ok":false,"sig":"` + B64Encode(make([]byte, 64)) + `","type":"result","v":1}`),
		"duplicate tools": []byte(`{"device_id":"` + dev.Record.DeviceID + `","sig":"` + B64Encode(make([]byte, 64)) + `","tools":["set","set"],"ts":1,"type":"hello","v":1,"vaults":["` + fixedID(0x11) + `"]}`),
	}
	for name, raw := range refused {
		_, err := ParseRelayFrame(raw, RelayFrameOptions{})
		wantCode(t, name, err, CodeBadRequest)
	}
	_, err = ParseRelayFrame([]byte(frames["ready"]), RelayFrameOptions{Binary: true})
	wantCode(t, "binary frame", err, CodeBadRequest)
	_, err = ParseRelayFrame([]byte(frames["call"]), RelayFrameOptions{MaxBytes: 64})
	wantCode(t, "oversize frame", err, CodeBadRequest)
	_, err = ParseRelayFrame([]byte(`{"exp":1,"type":"ready","v":2}`), RelayFrameOptions{})
	wantCode(t, "v 2", err, CodeUnsupportedVersion)

	if !(RelayCaller{Scopes: []string{ScopeMCPUse}}).Covers(ToolRun) || (RelayCaller{Scopes: []string{ScopeMCPRead}}).Covers(ToolSet) {
		t.Error("tool scopes")
	}
}

func TestValidateToolArgs(t *testing.T) {
	good := map[string]map[string]any{
		ToolSearch:   {"query": "stripe", "fields": []any{"name", "tags"}, "limit": int64(50)},
		ToolList:     {},
		ToolDescribe: {"name": "N"},
		ToolSet:      {"name": "N", "value": "", "sensitivity": "high"},
		ToolDelete:   {"name": "N"},
		ToolRequest:  {"name": "N", "purpose": "deploy", "ttl_s": int64(86400)},
		ToolRun:      {"argv": []any{"npm", ""}, "env": []any{map[string]any{"var": "STRIPE_KEY", "name": "N"}}, "timeout_s": int64(110)},
	}
	for tool, args := range good {
		if err := ValidateToolArgs(tool, args); err != nil {
			t.Errorf("%s: %v", tool, err)
		}
	}
	bad := []struct {
		tool string
		args map[string]any
	}{
		{ToolSearch, map[string]any{"query": ""}},
		{ToolSearch, map[string]any{"query": "x", "fields": []any{"value"}}},
		{ToolSearch, map[string]any{"query": "x", "limit": int64(51)}},
		{ToolList, map[string]any{"cursor": strings.Repeat("c", 257)}},
		{ToolDescribe, map[string]any{"name": "N", "vault_id": fixedID(0x11)}},
		{ToolSet, map[string]any{"name": "N"}},
		{ToolSet, map[string]any{"name": "N", "value": strings.Repeat("v", 65530)}},
		{ToolRequest, map[string]any{"name": "N", "purpose": "x", "ttl_s": int64(0)}},
		{ToolRun, map[string]any{"argv": []any{}, "env": []any{map[string]any{"var": "A", "name": "N"}}}},
		{ToolRun, map[string]any{"argv": []any{"x"}, "env": []any{map[string]any{"var": "a", "name": "N"}}}},
		{ToolRun, map[string]any{"argv": []any{"x"}, "env": []any{map[string]any{"var": "A", "name": "N"}, map[string]any{"var": "A", "name": "M"}}}},
		{ToolRun, map[string]any{"argv": []any{"x"}, "env": []any{map[string]any{"var": "A", "name": "N"}}, "timeout_s": int64(111)}},
		{"exec", map[string]any{}},
	}
	for i, c := range bad {
		wantCode(t, c.tool+" case "+strconv.Itoa(i), ValidateToolArgs(c.tool, c.args), CodeBadRequest)
	}
}
