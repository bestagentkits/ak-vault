package akv1

import (
	"strings"
	"testing"
)

func init() { vectorHandlers["kit-backup.json"] = checkKitBackup }

func kitFromRec(t *testing.T, r *rec) KitBackupKit {
	return mustOK(ParseKitBackupKit(r.raw("kit")))(t, r.path+".kit")
}

func expectedFromRec(r *rec) KitBackupExpected {
	e := r.obj("expected")
	out := KitBackupExpected{Account: e.str("account")}
	if e.has("vault_id") {
		out.VaultID = e.str("vault_id")
	}
	if e.has("recovery_sign_pub") {
		out.RecoverySignPub = e.str("recovery_sign_pub")
	}
	e.done()
	return out
}

func paramsFromRaw(t *testing.T, r *rec, key string) ArgonParams {
	p := r.obj(key)
	out := ArgonParams{T: p.i64("t"), M: p.i64("m"), P: p.i64("p")}
	p.done()
	return out
}

func checkKitBackup(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		kit := kitFromRec(t, c)
		file := mustOK(SealKitBackup(KitBackupSealArgs{
			Kit: kit, RecoverySignPub: c.str("recovery_sign_pub"), Passphrase: c.str("passphrase"),
			Params: paramsFromRaw(t, c, "params"), Salt: c.b64("salt"), Nonce: c.b64("nonce"),
		}))(t, c.path)
		eqJSON(t, c.path+" file", file.JSONValue(), c.raw("file"))
		text := mustOK(KitBackupFileBytes(file))(t, c.path+" bytes")
		eqStr(t, c.path+" file_text", string(text), c.str("file_text"))
		input := c.str("passphrase")
		if c.has("passphrase_input") {
			input = c.str("passphrase_input")
		}
		expected := expectedFromRec(c)
		for label, in := range map[string]any{"text": c.str("file_text"), "bytes+newline": append([]byte(c.str("file_text")), '\n'), "object": c.raw("file"), "reformatted": []byte(c.str("file_text_reformatted"))} {
			pass := c.str("passphrase")
			if label == "text" {
				pass = input
			}
			got := mustOK(OpenKitBackup(in, pass, expected))(t, c.path+" open "+label)
			eqJSON(t, c.path+" opened "+label, got.JSONValue(), c.raw("kit"))
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		var input any
		if c.has("file_text") {
			input = c.str("file_text") + strings.Repeat(" ", int(optI64(c, "trailing_spaces")))
		} else {
			input = c.raw("file")
		}
		_, err := OpenKitBackup(input, c.str("passphrase"), expectedFromRec(c))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("seal_invalid") {
		pass := c.str("passphrase")
		if c.has("passphrase_fill") {
			pass = strings.Repeat(c.str("passphrase_fill"), int(c.i64("passphrase_length")))
		}
		signPub := c.str("recovery_sign_pub")
		params := ArgonParams{}
		if c.has("params") {
			params = paramsFromRaw(t, c, "params")
		}
		var err error
		kit, kerr := ParseKitBackupKit(c.raw("kit"))
		if kerr != nil {
			err = kerr
		} else {
			_, err = SealKitBackup(KitBackupSealArgs{Kit: kit, RecoverySignPub: signPub, Passphrase: pass, Params: params})
		}
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func optI64(r *rec, k string) int64 {
	if r.has(k) {
		return r.i64(k)
	}
	return 0
}

func TestKitBackupFreshSealsDifferAndPassphraseShape(t *testing.T) {
	a, b := GenerateBackupPassphrase(), GenerateBackupPassphrase()
	if a == b || len(a) != 39 || strings.Count(a, "-") != 7 {
		t.Fatalf("generated passphrases repeat or have the wrong shape: %q %q", a, b)
	}
	kit := KitBackupKit{VaultID: RandomID(), Account: "acct_test", VaultOrigin: "https://vault.example.test", RecoveryKey: B64Encode(GenerateRecoveryKey())}
	args := KitBackupSealArgs{Kit: kit, RecoverySignPub: B64Encode(make([]byte, 32)), Passphrase: a, Params: ArgonParams{T: 3, M: 65536, P: 1}}
	x := mustOK(SealKitBackup(args))(t, "seal x")
	y := mustOK(SealKitBackup(args))(t, "seal y")
	if x.S == y.S || x.N == y.N || x.Ct == y.Ct {
		t.Fatal("fresh seals reuse a salt, nonce or ciphertext")
	}
	got := mustOK(OpenKitBackup(mustOK(KitBackupFileBytes(y))(t, "bytes"), a, KitBackupExpected{Account: kit.Account}))(t, "open")
	if got != kit {
		t.Fatal("opened kit differs")
	}
}
