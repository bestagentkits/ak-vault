package akv1

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Item sensitivities (spec §3.2).
const (
	SensitivityNormal = "normal"
	SensitivityHigh   = "high"
)

var sensitivities = []string{SensitivityNormal, SensitivityHigh}

// ItemPayload is the decrypted item plaintext. A tombstone payload is exactly
// {"deleted":true} and is represented by Deleted=true with the other fields empty.
type ItemPayload struct {
	Deleted     bool
	Name        string
	Value       string
	Meta        map[string]any
	Sensitivity string
}

// JSONValue returns the plaintext object that is canonically encoded and encrypted.
func (p ItemPayload) JSONValue() any {
	if p.Deleted {
		return map[string]any{"deleted": true}
	}
	meta := p.Meta
	if meta == nil {
		meta = map[string]any{}
	}
	return map[string]any{"name": p.Name, "value": p.Value, "meta": meta, "sensitivity": p.Sensitivity}
}

// ItemContext is the authenticated context bound into every item ciphertext.
type ItemContext struct {
	VaultID      string
	ItemID       string
	BaseRevision int64
	KeyEpoch     int64
	Author       string
	Tombstone    bool
}

// hkdf32 is HKDF-SHA256 (RFC 5869) with a 32-byte output.
func hkdf32(ikm, salt, info []byte) []byte {
	out := make([]byte, 32)
	// HKDF-SHA256 can produce up to 8160 bytes; reading 32 cannot fail.
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, info), out); err != nil {
		panic("akv1: hkdf: " + err.Error())
	}
	return out
}

// DeriveItemKey computes
// HKDF(ikm=vk, salt=b64decode(vault_id), info=utf8("akv1/item-key\n")||cjson({item_id,key_epoch}), L=32).
func DeriveItemKey(vk []byte, vaultID, itemID string, keyEpoch int64) ([]byte, error) {
	if len(vk) != KeyBytes {
		return nil, badRequest("vault key must be 32 bytes")
	}
	if _, err := asID(itemID, "item_id"); err != nil {
		return nil, err
	}
	if _, err := asInt(keyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return nil, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return nil, err
	}
	salt, _ := B64Decode(vaultID)
	info, err := CJSON(map[string]any{"item_id": itemID, "key_epoch": keyEpoch})
	if err != nil {
		return nil, err
	}
	return hkdf32(vk, salt, concatBytes([]byte("akv1/item-key\n"), info)), nil
}

// ItemAAD returns the validated item AAD object
// {ctx:"akv1/item", vault_id, item_id, base_revision, key_epoch, author, tombstone}.
func ItemAAD(ctx ItemContext) (map[string]any, error) {
	if _, err := asID(ctx.VaultID, "vault_id"); err != nil {
		return nil, err
	}
	if _, err := asID(ctx.ItemID, "item_id"); err != nil {
		return nil, err
	}
	if _, err := asUint(ctx.BaseRevision, "base_revision"); err != nil {
		return nil, err
	}
	if _, err := asInt(ctx.KeyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return nil, err
	}
	if _, err := asID(ctx.Author, "author"); err != nil {
		return nil, err
	}
	return map[string]any{
		"ctx": "akv1/item", "vault_id": ctx.VaultID, "item_id": ctx.ItemID,
		"base_revision": ctx.BaseRevision, "key_epoch": ctx.KeyEpoch, "author": ctx.Author, "tombstone": ctx.Tombstone,
	}, nil
}

// ParseItemPayload validates an untrusted (decrypted) payload object.
func ParseItemPayload(v any, tombstone bool) (ItemPayload, error) {
	obj, err := asObject(v, "item payload")
	if err != nil {
		return ItemPayload{}, err
	}
	if tombstone {
		if err := exactKeys(obj, []string{"deleted"}, "tombstone payload"); err != nil {
			return ItemPayload{}, err
		}
		if obj["deleted"] != true {
			return ItemPayload{}, badRequest(`tombstone payload must be {"deleted":true}`)
		}
		return ItemPayload{Deleted: true}, nil
	}
	if err := exactKeys(obj, []string{"name", "value", "meta", "sensitivity"}, "item payload"); err != nil {
		return ItemPayload{}, err
	}
	meta, err := asObject(obj["meta"], "item payload.meta")
	if err != nil {
		return ItemPayload{}, err
	}
	if _, err := CJSON(meta); err != nil { // meta must be inside the canonical data model
		return ItemPayload{}, err
	}
	name, err := asString(obj["name"], "item payload.name", 4096, 1)
	if err != nil {
		return ItemPayload{}, err
	}
	value, err := asString(obj["value"], "item payload.value", 65536, 0)
	if err != nil {
		return ItemPayload{}, err
	}
	sens, err := asEnum(obj["sensitivity"], sensitivities, "item payload.sensitivity")
	if err != nil {
		return ItemPayload{}, err
	}
	return ItemPayload{Name: name, Value: value, Meta: meta, Sensitivity: sens}, nil
}

// SealItem validates payload against ctx.Tombstone and encrypts it under the
// derived item key with kid "e<key_epoch>". nonce is nil in production.
func SealItem(vk []byte, ctx ItemContext, payload ItemPayload, nonce []byte) (Envelope, error) {
	parsed, err := ParseItemPayload(payload.JSONValue(), ctx.Tombstone)
	if err != nil {
		return Envelope{}, err
	}
	key, err := DeriveItemKey(vk, ctx.VaultID, ctx.ItemID, ctx.KeyEpoch)
	if err != nil {
		return Envelope{}, err
	}
	plaintext, err := CJSON(parsed)
	if err != nil {
		return Envelope{}, err
	}
	aad, err := ItemAAD(ctx)
	if err != nil {
		return Envelope{}, err
	}
	kid, err := EpochTag(ctx.KeyEpoch)
	if err != nil {
		return Envelope{}, err
	}
	return SealEnvelope(key, plaintext, aad, SealOptions{Kid: kid, Nonce: nonce})
}

// OpenItem decrypts an untrusted envelope and validates the payload, which
// must itself be canonical JSON.
func OpenItem(vk []byte, ctx ItemContext, env any) (ItemPayload, error) {
	key, err := DeriveItemKey(vk, ctx.VaultID, ctx.ItemID, ctx.KeyEpoch)
	if err != nil {
		return ItemPayload{}, err
	}
	aad, err := ItemAAD(ctx)
	if err != nil {
		return ItemPayload{}, err
	}
	kid, err := EpochTag(ctx.KeyEpoch)
	if err != nil {
		return ItemPayload{}, err
	}
	plaintext, err := OpenEnvelope(key, env, aad, kid)
	if err != nil {
		return ItemPayload{}, err
	}
	v, err := CJSONParse(plaintext)
	if err != nil {
		return ItemPayload{}, err
	}
	return ParseItemPayload(v, ctx.Tombstone)
}
