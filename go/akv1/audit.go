package akv1

import "strconv"

// AuditHead identifies the last entry of an audit chain: its seq and hash.
type AuditHead struct {
	Seq  int64
	Head string
}

// JSONValue returns {"seq","head"}.
func (h AuditHead) JSONValue() any { return map[string]any{"seq": h.Seq, "head": h.Head} }

// AuditCheckpoint is {"v":1,"vault_id","seq","head","author","ts","sig"} signed
// with akv1/audit-checkpoint; head is the hash of entry seq (spec §7, §11).
type AuditCheckpoint struct {
	VaultID string
	Seq     int64
	Head    string
	Author  string
	TS      int64
	Sig     string // empty for an unsigned checkpoint
}

// JSONValue returns the wire object ("sig" omitted when empty).
func (c AuditCheckpoint) JSONValue() any {
	m := map[string]any{"v": int64(1), "vault_id": c.VaultID, "seq": c.Seq, "head": c.Head, "author": c.Author, "ts": c.TS}
	if c.Sig != "" {
		m["sig"] = c.Sig
	}
	return m
}

// DeriveAuditKey computes the audit key of one key epoch,
// HKDF(ikm=vk, salt=b64decode(vault_id), info=utf8("akv1/audit-key\n")||cjson({key_epoch}), L=32)
// (the item-key salt convention).
func DeriveAuditKey(vk []byte, vaultID string, keyEpoch int64) ([]byte, error) {
	if len(vk) != KeyBytes {
		return nil, badRequest("vault key must be 32 bytes")
	}
	if _, err := asInt(keyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return nil, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return nil, err
	}
	salt, _ := B64Decode(vaultID)
	info, err := CJSON(map[string]any{"key_epoch": keyEpoch})
	if err != nil {
		return nil, err
	}
	return hkdf32(vk, salt, concatBytes([]byte("akv1/audit-key\n"), info)), nil
}

// AuditAAD returns {ctx:"akv1/audit", vault_id, seq, prev, key_epoch}.
func AuditAAD(vaultID string, seq int64, prev string, keyEpoch int64) map[string]any {
	return map[string]any{"ctx": "akv1/audit", "vault_id": vaultID, "seq": seq, "prev": prev, "key_epoch": keyEpoch}
}

// AuditEntryHash returns b64 sha256(cjson(entry)).
func AuditEntryHash(entry Envelope) (string, error) {
	b, err := CJSON(entry)
	if err != nil {
		return "", err
	}
	return SHA256B64(b), nil
}

// AppendAuditEntry encrypts event as the entry after head (nil for the first
// entry, seq 0 and prev "") under the audit key derived from vk, the vault key
// of keyEpoch (the vault's current epoch; the Worker refuses any other), with
// kid "e<keyEpoch>". nonce is nil in production (random).
func AppendAuditEntry(vk []byte, vaultID string, keyEpoch int64, head *AuditHead, event map[string]any, nonce []byte) (Envelope, AuditHead, error) {
	seq, prev := int64(0), ""
	if head != nil {
		seq, prev = head.Seq+1, head.Head
	}
	key, err := DeriveAuditKey(vk, vaultID, keyEpoch)
	if err != nil {
		return Envelope{}, AuditHead{}, err
	}
	kid, err := EpochTag(keyEpoch)
	if err != nil {
		return Envelope{}, AuditHead{}, err
	}
	plaintext, err := CJSON(event)
	if err != nil {
		return Envelope{}, AuditHead{}, err
	}
	entry, err := SealEnvelope(key, plaintext, AuditAAD(vaultID, seq, prev, keyEpoch), SealOptions{Kid: kid, Nonce: nonce})
	if err != nil {
		return Envelope{}, AuditHead{}, err
	}
	h, err := AuditEntryHash(entry)
	if err != nil {
		return Envelope{}, AuditHead{}, err
	}
	return entry, AuditHead{Seq: seq, Head: h}, nil
}

// AuditChain is the result of VerifyAuditChain. Head is nil for an empty chain.
// Events[i] is nil for an opaque entry (an epoch the verifier holds no key for).
type AuditChain struct {
	Events []map[string]any
	Head   *AuditHead
}

// VaultKeyLookup returns the vault key of a key epoch, or false when the caller
// holds none.
type VaultKeyLookup func(keyEpoch int64) ([]byte, bool)

// VerifyAuditChain replays a whole untrusted audit chain, decrypting every
// entry whose epoch key the caller holds (selected from the entry's
// "e<key_epoch>" kid); an entry at an epoch without a key is opaque (hash-chained
// and epoch-checked, nil in Events). keyEpoch is the current key epoch of the
// verified membership state. Rejects: a kid that is not an epoch tag, an epoch
// lower than the previous entry's or above keyEpoch (bad_request); reordered,
// dropped or substituted decryptable entries (decrypt_failed); a chain shorter
// than, or with a different entry at, the witnessed (already
// signature-verified) checkpoint (rollback); reused nonces (bad_request).
func VerifyAuditChain(entries []any, vaultKeys VaultKeyLookup, vaultID string, keyEpoch int64, witnessed *AuditHead) (AuditChain, error) {
	if len(entries) > 1_000_000 {
		return AuditChain{}, badRequest("audit entries must be an array of at most 1000000 entries")
	}
	parsed := make([]Envelope, 0, len(entries))
	for i, raw := range entries {
		e, err := parseEnvelopeAs(raw, "audit entry "+strconv.Itoa(i))
		if err != nil {
			return AuditChain{}, err
		}
		parsed = append(parsed, e)
	}
	if err := AssertUniqueNonces(parsed); err != nil {
		return AuditChain{}, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return AuditChain{}, err
	}
	if _, err := asInt(keyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return AuditChain{}, err
	}
	keys := map[int64][]byte{}
	events := make([]map[string]any, 0, len(parsed))
	hashes := make([]string, 0, len(parsed))
	lastEpoch := int64(0)
	for seq, entry := range parsed {
		epoch, err := ParseEpochTag(entry.Kid)
		if err != nil {
			return AuditChain{}, err
		}
		if epoch < lastEpoch {
			return AuditChain{}, badRequest("audit key epoch decreased along the chain")
		}
		if epoch > keyEpoch {
			return AuditChain{}, badRequest("audit key epoch is ahead of the membership state")
		}
		lastEpoch = epoch
		key, cached := keys[epoch]
		if !cached {
			if vk, ok := vaultKeys(epoch); ok {
				if key, err = DeriveAuditKey(vk, vaultID, epoch); err != nil {
					return AuditChain{}, err
				}
			}
			keys[epoch] = key
		}
		prev := ""
		if seq > 0 {
			prev = hashes[seq-1]
		}
		var event map[string]any
		if key != nil {
			plaintext, err := openParsedEnvelope(key, entry, AuditAAD(vaultID, int64(seq), prev, epoch))
			if err != nil {
				return AuditChain{}, err
			}
			v, err := CJSONParse(plaintext)
			if err != nil {
				return AuditChain{}, err
			}
			if event, err = asObject(v, "audit event"); err != nil {
				return AuditChain{}, err
			}
		}
		events = append(events, event)
		h, err := AuditEntryHash(entry)
		if err != nil {
			return AuditChain{}, err
		}
		hashes = append(hashes, h)
	}
	if witnessed != nil {
		if witnessed.Seq < 0 || witnessed.Seq >= int64(len(hashes)) {
			return AuditChain{}, newErr(CodeRollback, "audit chain is behind the witnessed checkpoint")
		}
		if hashes[witnessed.Seq] != witnessed.Head {
			return AuditChain{}, newErr(CodeRollback, "audit chain forks from the witnessed checkpoint")
		}
	}
	out := AuditChain{Events: events}
	if n := len(hashes); n > 0 {
		out.Head = &AuditHead{Seq: int64(n - 1), Head: hashes[n-1]}
	}
	return out, nil
}

// SignAuditCheckpoint signs c (its Sig is replaced) with an Ed25519 seed.
func SignAuditCheckpoint(c AuditCheckpoint, seed []byte) (AuditCheckpoint, error) {
	c.Sig = ""
	sig, err := SignDetached(ContextAuditCheckpoint, c, seed)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	c.Sig = sig
	return c, nil
}

// ParseAuditCheckpoint structurally validates an untrusted audit checkpoint.
func ParseAuditCheckpoint(v any) (AuditCheckpoint, error) {
	const what = "audit checkpoint"
	obj, err := asObject(v, what)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return AuditCheckpoint{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "seq", "head", "author", "ts", "sig"}, what); err != nil {
		return AuditCheckpoint{}, err
	}
	var c AuditCheckpoint
	if c.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return AuditCheckpoint{}, err
	}
	if c.Seq, err = asUint(obj["seq"], what+".seq"); err != nil {
		return AuditCheckpoint{}, err
	}
	if c.Head, err = asB64(obj["head"], what+".head", 32); err != nil {
		return AuditCheckpoint{}, err
	}
	if c.Author, err = asID(obj["author"], what+".author"); err != nil {
		return AuditCheckpoint{}, err
	}
	if c.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return AuditCheckpoint{}, err
	}
	if c.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return AuditCheckpoint{}, err
	}
	return c, nil
}

// VerifyAuditCheckpoint verifies an audit checkpoint signed by a current member device.
func VerifyAuditCheckpoint(v any, state MembershipState) (AuditCheckpoint, error) {
	c, err := ParseAuditCheckpoint(v)
	if err != nil {
		return AuditCheckpoint{}, err
	}
	if c.VaultID != state.VaultID {
		return AuditCheckpoint{}, badRequest("audit checkpoint belongs to another vault")
	}
	d, ok := state.FindDevice(c.Author)
	if !ok {
		return AuditCheckpoint{}, newErr(CodeForbidden, "audit checkpoint author is not a current device")
	}
	if err := VerifyObject(ContextAuditCheckpoint, c, d.SignPub); err != nil {
		return AuditCheckpoint{}, err
	}
	return c, nil
}
