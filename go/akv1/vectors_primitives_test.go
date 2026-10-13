package akv1

import (
	"testing"

	"golang.org/x/text/unicode/norm"
)

func checkCanonicalJSON(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		input, output := c.str("input"), c.str("output")
		v := mustOK(ParseJSON([]byte(input)))(t, c.path)
		eqStr(t, c.path+" cjson(parse(input))", string(mustOK(CJSON(v))(t, c.path)), output)
		w := mustOK(CJSONParse([]byte(output)))(t, c.path)
		eqStr(t, c.path+" cjson(cjsonParse(output))", string(mustOK(CJSON(w))(t, c.path)), output)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		input := []byte(c.str("input"))
		var err error
		switch mode := c.str("mode"); mode {
		case "parse":
			var v any
			if v, err = ParseJSON(input); err == nil {
				_, err = CJSON(v)
			}
		case "canonical":
			_, err = CJSONParse(input)
		default:
			t.Fatalf("%s: unknown mode %q", c.path, mode)
		}
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkKid(t *testing.T, f *rec, n *counter) {
	for _, e := range f.recs("ed25519") {
		pub := mustOK(SignPublicKey(e.b64("seed")))(t, e.path)
		eqStr(t, e.path+" public_key", B64Encode(pub), e.str("public_key"))
		eqStr(t, e.path+" kid", Kid(pub), e.str("kid"))
		eqStr(t, e.path+" device id", mustOK(DeviceIDFromSignPub(pub))(t, e.path), e.str("kid"))
		e.done()
		n.add(1)
	}
	for _, x := range f.recs("x25519") {
		pub := mustOK(KxPublicKey(x.b64("secret")))(t, x.path)
		eqStr(t, x.path+" public_key", B64Encode(pub), x.str("public_key"))
		eqStr(t, x.path+" kid", Kid(pub), x.str("kid"))
		x.done()
		n.add(1)
	}
	for _, s := range f.recs("signing") {
		ctx := s.str("context")
		obj := s.raw("object").(map[string]any)
		in := mustOK(SigningInput(ctx, obj))(t, s.path)
		eqStr(t, s.path+" signing_input", string(in), s.str("signing_input"))
		sig := mustOK(SignDetached(ctx, obj, s.b64("seed")))(t, s.path)
		eqStr(t, s.path+" sig", sig, s.str("sig"))
		signed := map[string]any{}
		for k, v := range obj {
			signed[k] = v
		}
		signed["sig"] = sig
		if err := VerifyObject(ctx, signed, s.str("public_key")); err != nil {
			t.Errorf("%s: verify: %v", s.path, err)
		}
		s.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		expectCode(t, c, VerifyObject(c.str("context"), c.raw("object"), c.str("public_key")))
		c.done()
		n.add(1)
	}
}

func checkAEAD(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		key := c.b64("key")
		aad := c.raw("aad")
		eqStr(t, c.path+" aad_cjson", string(mustOK(CJSON(aad))(t, c.path)), c.str("aad_cjson"))
		env := mustOK(SealEnvelope(key, c.b64("plaintext"), aad, SealOptions{Kid: c.str("kid"), Nonce: c.b64("nonce")}))(t, c.path)
		eqJSON(t, c.path+" envelope", env, c.raw("envelope"))
		pt := mustOK(OpenEnvelope(key, c.raw("envelope"), aad, c.str("kid")))(t, c.path)
		eqStr(t, c.path+" plaintext", B64Encode(pt), c.str("plaintext"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		var err error
		if c.has("envelopes") {
			var envs []Envelope
			for _, raw := range c.list("envelopes") {
				envs = append(envs, mustOK(ParseEnvelope(raw))(t, c.path))
			}
			err = AssertUniqueNonces(envs)
		} else {
			_, err = OpenEnvelope(c.b64("key"), c.raw("envelope"), c.raw("aad"), "")
		}
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func itemCtx(c *rec) ItemContext {
	return ItemContext{
		VaultID: c.str("vault_id"), ItemID: c.str("item_id"), BaseRevision: c.i64("base_revision"),
		KeyEpoch: c.i64("key_epoch"), Author: c.str("author"), Tombstone: c.boolean("tombstone"),
	}
}

func checkItem(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		vk := c.b64("vk")
		ctx := itemCtx(c)
		key := mustOK(DeriveItemKey(vk, ctx.VaultID, ctx.ItemID, ctx.KeyEpoch))(t, c.path)
		eqStr(t, c.path+" item_key", B64Encode(key), c.str("item_key"))
		eqStr(t, c.path+" aad_cjson", string(mustOK(CJSON(mustOK(ItemAAD(ctx))(t, c.path)))(t, c.path)), c.str("aad_cjson"))
		payload := mustOK(ParseItemPayload(c.raw("payload"), ctx.Tombstone))(t, c.path)
		eqStr(t, c.path+" plaintext", string(mustOK(CJSON(payload))(t, c.path)), c.str("plaintext"))
		env := mustOK(SealItem(vk, ctx, payload, c.b64("nonce")))(t, c.path)
		eqJSON(t, c.path+" env", env, c.raw("env"))
		opened := mustOK(OpenItem(vk, ctx, c.raw("env")))(t, c.path)
		eqJSON(t, c.path+" opened payload", opened, c.raw("payload"))
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := OpenItem(c.b64("vk"), itemCtx(c), c.raw("env"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkWrapX25519(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		rcpt := c.obj("recipient")
		esk := c.b64("ephemeral_secret")
		kxPub := rcpt.b64("kx_pub")
		shared := mustOK(X25519Shared(esk, kxPub))(t, c.path)
		eqStr(t, c.path+" shared", B64Encode(shared), c.str("shared"))
		epk := mustOK(KxPublicKey(esk))(t, c.path)
		eqStr(t, c.path+" epk", B64Encode(epk), c.str("epk"))
		eqStr(t, c.path+" wrap_key", B64Encode(deriveWrapKey(shared, epk, kxPub)), c.str("wrap_key"))
		w := mustOK(WrapToDevice(WrapToDeviceArgs{
			VK: c.b64("vk"), VaultID: c.str("vault_id"), KeyEpoch: c.i64("key_epoch"),
			RecipientID: rcpt.str("device_id"), RecipientKxPub: kxPub, EphemeralSecret: esk, Nonce: c.b64("nonce"),
		}))(t, c.path)
		eqJSON(t, c.path+" wrap", w, c.raw("wrap"))
		vk := mustOK(UnwrapFromDevice(c.raw("wrap"), c.str("vault_id"), rcpt.str("device_id"), rcpt.b64("kx_secret")))(t, c.path)
		eqStr(t, c.path+" vk", B64Encode(vk), c.str("vk"))
		rcpt.done()
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := UnwrapFromDevice(c.raw("wrap"), c.str("vault_id"), c.str("device_id"), c.b64("kx_secret"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkWrapPassword(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		params := ArgonParams{T: c.i64("t"), M: c.i64("m"), P: c.i64("p")}
		password, nfc := c.str("password"), c.str("password_nfc")
		salt := c.b64("salt")
		// DerivePasswordKEK normalizes to NFC, so the raw input and its NFC
		// form must derive the same KEK.
		eqStr(t, c.path+" nfc", norm.NFC.String(password), nfc)
		eqStr(t, c.path+" kek(password)", B64Encode(mustOK(DerivePasswordKEK(password, salt, params))(t, c.path)), c.str("kek"))
		eqStr(t, c.path+" kek(password_nfc)", B64Encode(mustOK(DerivePasswordKEK(nfc, salt, params))(t, c.path)), c.str("kek"))
		w := mustOK(WrapWithPassword(WrapWithPasswordArgs{
			VK: c.b64("vk"), VaultID: c.str("vault_id"), KeyEpoch: c.i64("key_epoch"), Password: password,
			Params: params, Salt: salt, Nonce: c.b64("nonce"),
		}))(t, c.path)
		eqJSON(t, c.path+" wrap", w, c.raw("wrap"))
		vk, upgrade, err := UnwrapWithPassword(c.raw("wrap"), c.str("vault_id"), nfc)
		if err != nil {
			t.Fatalf("%s: unwrap: %v", c.path, err)
		}
		eqStr(t, c.path+" vk", B64Encode(vk), c.str("vk"))
		if upgrade != c.boolean("needs_upgrade") {
			t.Errorf("%s: needs_upgrade = %v", c.path, upgrade)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, _, err := UnwrapWithPassword(c.raw("wrap"), c.str("vault_id"), c.str("password"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func checkWrapRecovery(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		rk := c.b64("rk")
		eqStr(t, c.path+" display", mustOK(EncodeRecoveryKey(rk))(t, c.path), c.str("display"))
		eqStr(t, c.path+" decode", B64Encode(mustOK(DecodeRecoveryKey(c.str("display")))(t, c.path)), c.str("rk"))
		if c.has("wrap") {
			eqStr(t, c.path+" kek", B64Encode(mustOK(DeriveRecoveryKEK(rk))(t, c.path)), c.str("kek"))
			w := mustOK(WrapWithRecoveryKey(c.b64("vk"), c.str("vault_id"), c.i64("key_epoch"), rk, c.b64("nonce")))(t, c.path)
			eqJSON(t, c.path+" wrap", w, c.raw("wrap"))
			vk := mustOK(UnwrapWithRecoveryKey(c.raw("wrap"), c.str("vault_id"), rk))(t, c.path)
			eqStr(t, c.path+" vk", B64Encode(vk), c.str("vk"))
		}
		c.done()
		n.add(1)
	}
	for _, a := range f.recs("decode_aliases") {
		eqStr(t, a.path, B64Encode(mustOK(DecodeRecoveryKey(a.str("input")))(t, a.path)), a.str("rk"))
		a.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid_display") {
		_, err := DecodeRecoveryKey(c.str("display"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := UnwrapWithRecoveryKey(c.raw("wrap"), c.str("vault_id"), c.b64("rk"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}
