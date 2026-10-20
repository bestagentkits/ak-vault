package akv1

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// Remote access vectors: seal-key, sealed-op, name-tag, enroll-codes,
// profile and relay-frames (spec §3.6-3.8, §5.1, §9.7).

type sealKeyVector struct {
	vk, secret, public []byte
}

// sealKeys returns seal-key.json seal_keys by key epoch, without marking the
// keys as consumed (sealed-op.json and name-tag.json read them too).
func sealKeys(t *testing.T) map[int64]sealKeyVector {
	t.Helper()
	m := loadVectorJSON(t, filepath.Join(vectorsDir(t), "seal-key.json"))
	out := map[int64]sealKeyVector{}
	for _, raw := range m["seal_keys"].([]any) {
		k := raw.(map[string]any)
		dec := func(name string) []byte {
			b, err := B64Decode(k[name].(string))
			if err != nil {
				t.Fatalf("seal-key.json seal_keys %s: %v", name, err)
			}
			return b
		}
		out[k["key_epoch"].(int64)] = sealKeyVector{vk: dec("vk"), secret: dec("seal_sk"), public: dec("seal_pub")}
	}
	return out
}

// sealKeyChainOptions reads a seal-key case's optional chain pins.
func sealKeyChainOptions(c *rec, vaultID string) VerifyChainOptions {
	opts := VerifyChainOptions{VaultID: vaultID}
	if c.has("trusted_anchor") {
		opts.TrustedAnchor = c.str("trusted_anchor")
	}
	if c.has("witnessed_checkpoint") {
		w := c.obj("witnessed_checkpoint")
		opts.Witnessed = &WitnessedMembership{MembershipSeq: w.i64("membership_seq"), MembershipHead: w.str("membership_head")}
		w.done()
	}
	return opts
}

// optVK reads a vk that may be null (not held).
func optVK(c *rec) []byte {
	if c.raw("vk") == nil {
		return nil
	}
	return c.b64("vk")
}

func checkSealKey(t *testing.T, f *rec, n *counter) {
	vaultID := f.str("vault_id")
	eqStr(t, "chain", f.str("chain"), "membership.json chains[0]")
	shared, _, _ := membershipChains(t)
	events := shared.([]any)

	for _, k := range f.recs("seal_keys") {
		pair := mustOK(DeriveSealKeyPair(k.b64("vk"), vaultID, k.i64("key_epoch")))(t, k.path)
		eqStr(t, k.path+" seal_sk", B64Encode(pair.Secret), k.str("seal_sk"))
		eqStr(t, k.path+" seal_pub", B64Encode(pair.Public), k.str("seal_pub"))
		k.done()
		n.add(1)
	}
	o := f.obj("other_vault_seal_pub")
	pair := mustOK(DeriveSealKeyPair(o.b64("vk"), o.str("vault_id"), o.i64("key_epoch")))(t, o.path)
	eqStr(t, o.path, B64Encode(pair.Public), o.str("seal_pub"))
	o.done()
	n.add(1)

	for _, c := range f.recs("cases") {
		got := mustOK(VerifySealKeyDoc(c.raw("doc"), events, VerifySealKeyDocOptions{Chain: sealKeyChainOptions(c, vaultID), VK: optVK(c)}))(t, c.path)
		eqJSON(t, c.path, got, c.raw("doc"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := VerifySealKeyDoc(c.raw("doc"), events, VerifySealKeyDocOptions{Chain: sealKeyChainOptions(c, c.str("vault_id")), VK: optVK(c)})
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	replace := func(c *rec) error {
		var stored *SealKeyDoc
		if c.raw("stored") != nil {
			d := mustOK(ParseSealKeyDoc(c.raw("stored")))(t, c.path+".stored")
			stored = &d
		}
		incoming := mustOK(ParseSealKeyDoc(c.raw("incoming")))(t, c.path+".incoming")
		return CheckSealKeyDocReplace(stored, incoming)
	}
	for _, c := range f.recs("replace_cases") {
		if err := replace(c); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("replace_invalid") {
		expectCode(t, c, replace(c))
		c.done()
		n.add(1)
	}
}

// plaintextOf builds a SealedOpPlaintext from a vector op object, refusing
// keys the struct cannot carry so nothing is silently dropped.
func plaintextOf(t *testing.T, what string, op map[string]any) SealedOpPlaintext {
	t.Helper()
	var p SealedOpPlaintext
	for k, v := range op {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s: op.%s is not a string", what, k)
		}
		switch k {
		case "op":
			p.Op = s
		case "name":
			p.Name = s
		case "value":
			p.Value = s
		case "sensitivity":
			p.Sensitivity = s
		default:
			t.Fatalf("%s: unexpected op key %s", what, k)
		}
	}
	return p
}

func parseOrigin(t *testing.T, what string, v any) SealedOrigin {
	t.Helper()
	o, err := parseSealedOrigin(v, what)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return o
}

func checkSealedOp(t *testing.T, f *rec, n *counter) {
	keys := sealKeys(t)
	origin := parseOrigin(t, "origin", f.raw("origin"))
	var vaultID string

	for _, c := range f.recs("cases") {
		epoch := c.i64("key_epoch")
		w := c.obj("wire")
		wire := mustOK(ParseSealedOp(w.m))(t, c.path+".wire")
		vaultID = wire.VaultID
		op := c.raw("op").(map[string]any)
		got := mustOK(SealOp(SealOpArgs{
			SealPub: keys[epoch].public, VaultID: wire.VaultID, KeyEpoch: epoch, SealedID: wire.SealedID,
			Origin: wire.Origin, TS: wire.TS, Plaintext: plaintextOf(t, c.path, op),
			ephemeralSecret: c.b64("ephemeral_secret"), nonce: mustOK(B64Decode(wire.N))(t, c.path+".n"),
		}))(t, c.path)
		eqJSON(t, c.path+" wire", got, c.raw("wire"))
		eqStr(t, c.path+" plaintext", string(mustOK(CJSON(op))(t, c.path)), c.str("plaintext"))
		opened := mustOK(OpenSealedOp(keys[epoch].secret, c.raw("wire"), wire.VaultID))(t, c.path+" open")
		eqJSON(t, c.path+" opened op", opened.Plaintext(), op)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		wire := c.raw("wire")
		if c.has("ct_zero_bytes") {
			m := map[string]any{}
			for k, v := range wire.(map[string]any) {
				m[k] = v
			}
			m["ct"] = B64Encode(make([]byte, c.i64("ct_zero_bytes")))
			wire = m
		}
		_, err := OpenSealedOp(keys[c.i64("open_with_epoch")].secret, wire, c.str("vault_id"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("seal_invalid") {
		op := c.raw("op").(map[string]any)
		if c.has("value_fill") {
			m := map[string]any{"value": strings.Repeat(c.str("value_fill"), int(c.i64("value_length")))}
			for k, v := range op {
				m[k] = v
			}
			op = m
		}
		_, err := SealOp(SealOpArgs{SealPub: keys[3].public, VaultID: vaultID, KeyEpoch: 3, Origin: origin, TS: 1, Plaintext: plaintextOf(t, c.path, op)})
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	// Fresh seals use fresh randomness and still open.
	del := SealedOpPlaintext{Op: SealedOpDelete, Name: "A"}
	a := mustOK(SealOp(SealOpArgs{SealPub: keys[3].public, VaultID: vaultID, KeyEpoch: 3, Origin: origin, TS: 1, Plaintext: del}))(t, "fresh a")
	b := mustOK(SealOp(SealOpArgs{SealPub: keys[3].public, VaultID: vaultID, KeyEpoch: 3, Origin: origin, TS: 1, Plaintext: del}))(t, "fresh b")
	if a.Epk == b.Epk || a.SealedID == b.SealedID {
		t.Error("fresh seals reuse epk or sealed_id")
	}
	fresh := mustOK(OpenSealedOp(keys[3].secret, a, vaultID))(t, "open fresh")
	eqJSON(t, "fresh op", fresh.Plaintext(), del)
	n.add(1)

	d := f.obj("drain")
	drainWire := mustOK(ParseSealedOp(d.raw("wire")))(t, d.path+".wire")
	drainOpened := mustOK(OpenSealedOp(keys[drainWire.KeyEpoch].secret, d.raw("wire"), drainWire.VaultID))(t, d.path+".wire open")
	drain := func(c *rec) error {
		seen := map[string]bool{}
		for _, s := range c.list("seen") {
			seen[s.(string)] = true
		}
		return CheckSealedDrain(drainOpened, SealedDrainOptions{
			Account: c.str("account"), Now: c.i64("now"), SealedTTLS: c.i64("sealed_ttl_s"),
			Seen: func(id string) bool { return seen[id] },
		})
	}
	for _, c := range d.recs("cases") {
		if err := drain(c); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		c.done()
		n.add(1)
	}
	for _, c := range d.recs("invalid") {
		expectCode(t, c, drain(c))
		c.done()
		n.add(1)
	}
	d.done()
}

func checkNameTag(t *testing.T, f *rec, n *counter) {
	keys := sealKeys(t)
	tagOf := func(c *rec) (string, error) {
		k := mustOK(NameIndexKey(keys[c.i64("key_epoch")].vk, c.str("vault_id"), c.i64("key_epoch")))(t, c.path)
		name := c.str("name")
		if c.has("name_utf16_hex") {
			// A lone surrogate has no UTF-8 form; Go receives its WTF-8 bytes.
			units := mustOK(hex.DecodeString(c.str("name_utf16_hex")))(t, c.path)
			var b []byte
			for i := 0; i+1 < len(units); i += 2 {
				r := rune(units[i])<<8 | rune(units[i+1])
				b = append(b, wtf8(r)...)
			}
			name = string(b)
		}
		return NameTag(k, name)
	}
	for _, c := range f.recs("index_keys") {
		k := mustOK(NameIndexKey(c.b64("vk"), c.str("vault_id"), c.i64("key_epoch")))(t, c.path)
		eqStr(t, c.path, B64Encode(k), c.str("index_key"))
		c.done()
		n.add(1)
	}
	same := f.recs("same_tag")
	if len(same) < 2 || same[0].m["name"] == same[1].m["name"] {
		t.Error("same_tag must hold distinct spellings")
	}
	for _, c := range same {
		eqStr(t, c.path, mustOK(tagOf(c))(t, c.path), same[0].str("tag"))
		c.str("tag")
		c.done()
		n.add(1)
	}
	seen := map[string]bool{}
	for _, c := range f.recs("distinct_tags") {
		tag := mustOK(tagOf(c))(t, c.path)
		eqStr(t, c.path, tag, c.str("tag"))
		if seen[tag] {
			t.Errorf("%s: tag repeats", c.path)
		}
		seen[tag] = true
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("known_answers") {
		eqStr(t, c.path, mustOK(tagOf(c))(t, c.path), c.str("tag"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := tagOf(c)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

// wtf8 encodes one UTF-16 code unit (a surrogate included) as WTF-8.
func wtf8(r rune) []byte {
	if utf16.IsSurrogate(r) {
		return []byte{byte(0xE0 | r>>12), byte(0x80 | (r>>6)&0x3F), byte(0x80 | r&0x3F)}
	}
	return []byte(string(r))
}

func checkEnrollCodes(t *testing.T, f *rec, n *counter) {
	join := f.raw("join")
	jc := mustOK(ParseJoinCode(f.str("join_code")))(t, "join_code")
	eqJSON(t, "parsed join", joinFields(jc), join)
	eqStr(t, "encoded join", mustOK(EncodeJoinCode(jc))(t, "encode join"), f.str("join_code"))
	split := mustOK(ParseJoinCode(f.str("whitespace_split")))(t, "whitespace_split")
	eqJSON(t, "whitespace_split", joinFields(split), join)

	offer := f.raw("offer")
	oc := mustOK(ParseOfferCode(f.str("offer_code")))(t, "offer_code")
	eqJSON(t, "parsed offer", offerFields(oc), offer)
	eqStr(t, "encoded offer", mustOK(EncodeOfferCode(oc))(t, "encode offer"), f.str("offer_code"))
	n.add(3)

	origins := f.obj("origins")
	for _, o := range origins.list("canonical") {
		if err := ValidateVaultOrigin(o.(string)); err != nil {
			t.Errorf("origin %q refused: %v", o, err)
		}
		n.add(1)
	}
	for _, o := range origins.list("non_canonical") {
		if err := ValidateVaultOrigin(o.(string)); CodeOf(err) != CodeBadRequest {
			t.Errorf("origin %q: want bad_request, got %v", o, err)
		}
		n.add(1)
	}
	origins.done()
	for _, c := range f.recs("invalid_join") {
		_, err := ParseJoinCode(c.str("code_text"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid_offer") {
		_, err := ParseOfferCode(c.str("code_text"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

// joinFields and offerFields drop v and ctx, matching the vectors' objects.
func joinFields(j JoinCode) map[string]any {
	m := j.JSONValue().(map[string]any)
	delete(m, "v")
	delete(m, "ctx")
	return m
}

func offerFields(o OfferCode) map[string]any {
	m := o.JSONValue().(map[string]any)
	delete(m, "v")
	delete(m, "ctx")
	return m
}

// profileOrigins reads an optional prev_origins object.
func profileOrigins(c *rec, key string) map[string]string {
	if !c.has(key) {
		return nil
	}
	out := map[string]string{}
	for k, v := range c.raw(key).(map[string]any) {
		out[k] = v.(string)
	}
	return out
}

func profileRecord(r *rec) SignedRecord {
	record := SignedRecord{Author: r.str("author"), TS: r.i64("ts"), BaseRevision: r.i64("base_revision")}
	r.done()
	return record
}

func profileCheckJSON(got ProfileCheck) map[string]any {
	origins := map[string]any{}
	for k, v := range got.Origins {
		origins[k] = v
	}
	return map[string]any{"profile": got.Profile, "dropped": stringsToAny(got.Dropped), "origins": origins}
}

func checkProfile(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		record := profileRecord(c.obj("record"))
		next := mustOK(ValidateProfile(c.raw("next")))(t, c.path+".next")
		var prev Profile
		if record.BaseRevision != 0 && c.raw("prev") != nil {
			prev = mustOK(ValidateProfile(c.raw("prev")))(t, c.path+".prev")
		}
		c.raw("prev")
		self := ""
		if c.has("self_device_id") {
			self = c.str("self_device_id")
		}
		got := CheckProfileProvenance(prev, profileOrigins(c, "prev_origins"), next, record, self)
		eqJSON(t, c.path, profileCheckJSON(got), c.raw("expect"))
		c.done()
		n.add(1)
	}
	for _, ch := range f.recs("chains") {
		self := ch.str("self_device_id")
		start := ch.obj("start")
		var prev Profile
		if start.raw("prev") != nil {
			prev = mustOK(ValidateProfile(start.raw("prev")))(t, start.path+".prev")
		}
		prevOrigins := profileOrigins(start, "prev_origins")
		start.done()
		for _, s := range ch.recs("steps") {
			record := profileRecord(s.obj("record"))
			next := mustOK(ValidateProfile(s.raw("next")))(t, s.path+".next")
			got := CheckProfileProvenance(prev, prevOrigins, next, record, self)
			eqJSON(t, s.path, profileCheckJSON(got), s.raw("expect"))
			prev, prevOrigins = got.Profile, got.Origins
			s.done()
			n.add(1)
		}
		ch.done()
	}
	for _, c := range f.recs("invalid") {
		_, err := ValidateProfile(c.raw("profile"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	eqJSON(t, "valid_limits", mustOK(ValidateProfile(f.raw("valid_limits")))(t, "valid_limits"), f.raw("valid_limits"))
	cf := f.obj("carry_forward")
	eqJSON(t, "carry_forward", CarryForwardMeta(cf.raw("meta").(map[string]any)), cf.raw("expect"))
	cf.done()
	n.add(2)
}

func checkRelayFrames(t *testing.T, f *rec, n *counter) {
	opts := RelayFrameOptions{MaxBytes: int(f.i64("max_bytes"))}
	dev := f.obj("device")
	signPub := dev.str("sign_pub")
	eqStr(t, "device_id", mustOK(DeviceIDFromSignPubB64(signPub))(t, "device"), dev.str("device_id"))
	dev.done()
	now := f.i64("now")

	frames := map[string]string{}
	for _, c := range f.recs("frames") {
		text := c.str("text")
		frames[c.str("name")] = text
		got := mustOK(ParseRelayFrame([]byte(text), opts))(t, c.path)
		eqStr(t, c.path, string(mustOK(CJSON(got))(t, c.path)), text)
		c.done()
		n.add(1)
	}
	hello := mustOK(VerifyHello([]byte(frames["hello"]), VerifyHelloOptions{SignPub: signPub, Now: now}))(t, "verify hello")
	eqStr(t, "verified hello", string(mustOK(CJSON(hello))(t, "hello")), frames["hello"])
	for _, name := range []string{"result_ok", "result_error"} {
		r := mustOK(VerifyResult([]byte(frames[name]), signPub))(t, "verify "+name)
		eqStr(t, "verified "+name, string(mustOK(CJSON(r))(t, name)), frames[name])
	}
	n.add(3)

	for _, c := range f.recs("invalid_text") {
		o := opts
		var data []byte
		if c.has("binary_utf8") {
			o.Binary = true
			data = []byte(c.str("binary_utf8"))
		} else {
			data = []byte(c.str("text"))
		}
		_, err := ParseRelayFrame(data, o)
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid_hello") {
		_, err := VerifyHello(c.raw("frame"), VerifyHelloOptions{SignPub: c.str("sign_pub"), Now: c.i64("now")})
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid_result") {
		_, err := VerifyResult(c.raw("frame"), c.str("sign_pub"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("tool_args") {
		args := c.raw("args").(map[string]any)
		before := mustOK(CJSON(args))(t, c.path)
		if err := ValidateToolArgs(c.str("tool"), args); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		if !bytes.Equal(mustOK(CJSON(args))(t, c.path), before) {
			t.Errorf("%s: args changed", c.path)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("tool_args_invalid") {
		args := c.raw("args").(map[string]any)
		if c.has("value_fill") {
			m := map[string]any{"value": strings.Repeat(c.str("value_fill"), int(c.i64("value_length")))}
			for k, v := range args {
				m[k] = v
			}
			args = m
		}
		expectCode(t, c, ValidateToolArgs(c.str("tool"), args))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("tool_results") {
		if err := ValidateToolResult(c.str("tool"), c.raw("result").(map[string]any)); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("tool_results_invalid") {
		expectCode(t, c, ValidateToolResult(c.str("tool"), c.raw("result").(map[string]any)))
		c.done()
		n.add(1)
	}
}
