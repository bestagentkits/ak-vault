package akv1

import (
	"crypto/sha256"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/text/unicode/norm"
)

// Name tags (spec §3.7): a keyed blind index devices compute so a reader can
// find an item by name without pulling the vault. The Worker never holds the
// index key; a tag is a hint that the reader verifies by decrypting.

// NameTagBytes is the decoded size of a name tag.
const NameTagBytes = 16

// NameIndexKey computes
// NameIndexKey[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id), info=utf8("akv1/name-index\n")||cjson({"key_epoch":e}), L=32).
func NameIndexKey(vk []byte, vaultID string, keyEpoch int64) ([]byte, error) {
	return deriveEpochKey(vk, vaultID, keyEpoch, "akv1/name-index\n")
}

// NameTag computes b64(HKDF(ikm=indexKey, salt="", info=utf8("akv1/name-tag\n")||utf8(NFC(name)), L=16)).
// name is an item payload name (1–4096 UTF-16 code units, valid UTF-8).
func NameTag(indexKey []byte, name string) (string, error) {
	if len(indexKey) != KeyBytes {
		return "", badRequest("name index key must be 32 bytes")
	}
	if !utf8.ValidString(name) {
		return "", badRequest("name must be valid UTF-8")
	}
	if _, err := asString(name, "name", MaxItemNameLength, 1); err != nil {
		return "", err
	}
	info := concatBytes([]byte("akv1/name-tag\n"), []byte(norm.NFC.String(name)))
	out := make([]byte, NameTagBytes)
	// A nil salt is the RFC 5869 default (HashLen zero bytes).
	if _, err := io.ReadFull(hkdf.New(sha256.New, indexKey, nil, info), out); err != nil {
		panic("akv1: hkdf: " + err.Error())
	}
	return B64Encode(out), nil
}

// ItemNameTag is the unsigned, untrusted tag sent beside a record:
// {"key_epoch":e,"tag":"<b64 16B>"}.
type ItemNameTag struct {
	KeyEpoch int64
	Tag      string
}

// JSONValue returns the wire object.
func (t ItemNameTag) JSONValue() any {
	return map[string]any{"key_epoch": t.KeyEpoch, "tag": t.Tag}
}

// ItemPutBody is the PUT /v1/vaults/{vid}/items/{iid} body: the bare record
// when NameTag is nil, otherwise the {"record","name_tag"} wrapper (§3.7).
type ItemPutBody struct {
	Record  SignedRecord
	NameTag *ItemNameTag
}

// JSONValue returns the request body.
func (b ItemPutBody) JSONValue() any {
	if b.NameTag == nil {
		return b.Record.JSONValue()
	}
	return map[string]any{"record": b.Record.JSONValue(), "name_tag": b.NameTag.JSONValue()}
}

// NewItemPutBody builds the item PUT body for a record and an optional tag,
// refusing (bad_request) a tag whose key_epoch differs from the record's, a
// tag on a tombstone, or a malformed tag.
func NewItemPutBody(record SignedRecord, tag *ItemNameTag) (ItemPutBody, error) {
	if tag != nil {
		if record.Tombstone {
			return ItemPutBody{}, badRequest("a tombstone carries no name_tag")
		}
		if tag.KeyEpoch != record.KeyEpoch {
			return ItemPutBody{}, badRequest("name_tag.key_epoch must equal record.key_epoch")
		}
		if _, err := asB64(tag.Tag, "name_tag.tag", NameTagBytes); err != nil {
			return ItemPutBody{}, err
		}
	}
	return ItemPutBody{Record: record, NameTag: tag}, nil
}
