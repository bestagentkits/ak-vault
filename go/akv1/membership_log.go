package akv1

import "strconv"

// WitnessedMembership is the membership part of the highest checkpoint a
// client witnessed. VaultID is optional ("" = not checked).
type WitnessedMembership struct {
	VaultID        string
	MembershipSeq  int64
	MembershipHead string
}

// VerifyChainOptions configures VerifyMembershipChain. Zero values disable a check.
type VerifyChainOptions struct {
	// TrustedAnchor is the pinned b64 sign_pub of the genesis author; mismatch is CodeForbidden.
	TrustedAnchor string
	// Witnessed is the highest witnessed checkpoint; a shorter or forked chain is CodeRollback.
	Witnessed *WitnessedMembership
	// VaultID is the expected vault; mismatch is CodeBadRequest.
	VaultID string
}

// MembershipEventHash returns b64(sha256(signing input)) of an event: the next event's prev.
func MembershipEventHash(e MembershipEvent) (string, error) {
	in, err := SigningInput(ContextMembership, e)
	if err != nil {
		return "", err
	}
	return SHA256B64(in), nil
}

// SignMembershipEvent signs a fully specified event with an Ed25519 seed.
func SignMembershipEvent(e MembershipEvent, seed []byte) (MembershipEvent, error) {
	e.Sig = ""
	sig, err := SignDetached(ContextMembership, e, seed)
	if err != nil {
		return MembershipEvent{}, err
	}
	e.Sig = sig
	return e, nil
}

// BuildGenesisEvent builds and signs the genesis event (seq 0, key_epoch 1, prev "").
func BuildGenesisEvent(vaultID string, ts int64, author string, body map[string]any, seed []byte) (MembershipEvent, error) {
	return SignMembershipEvent(MembershipEvent{
		Type: EventGenesis, VaultID: vaultID, Seq: 0, Prev: "", MembershipEpoch: 0, KeyEpoch: 1, TS: ts, Author: author, Body: body,
	}, seed)
}

// NextMembershipEvent builds and signs the event following state; seq, prev
// and epochs are filled in (key_epoch advances only for rekey).
func NextMembershipEvent(state MembershipState, typ string, ts int64, author string, body map[string]any, seed []byte) (MembershipEvent, error) {
	if typ == EventGenesis || !contains(membershipEvTypes, typ) {
		return MembershipEvent{}, newErr(CodeUnsupportedVersion, "unsupported event type")
	}
	seq := state.Seq + 1
	keyEpoch := state.KeyEpoch
	if typ == EventRekey {
		keyEpoch++
	}
	return SignMembershipEvent(MembershipEvent{
		Type: typ, VaultID: state.VaultID, Seq: seq, Prev: state.Head, MembershipEpoch: seq, KeyEpoch: keyEpoch, TS: ts, Author: author, Body: body,
	}, seed)
}

// VerifyMembershipChain replays an untrusted membership chain from genesis and
// returns the derived state.
//
// Rejects (code): unknown v/type (unsupported_version); malformed fields,
// non-sequential seq, wrong prev, membership_epoch != seq, key_epoch change
// without rekey (bad_request); bad signature (invalid_signature); author not a
// current human owner device or the recovery key for device_add/device_remove,
// removed device reappearing, demoting/removing the last owner, member ops in
// non-shared vaults, untrusted anchor (forbidden); key_epoch decreasing, chain
// behind or forked from the witnessed checkpoint (rollback).
func VerifyMembershipChain(events []any, opts VerifyChainOptions) (MembershipState, error) {
	if len(events) > 1_000_000 {
		return MembershipState{}, badRequest("membership events must be an array of at most 1000000 entries")
	}
	if len(events) == 0 {
		return MembershipState{}, badRequest("membership chain is empty")
	}
	r := newReplayState()
	hashes := make([]string, 0, len(events))
	vaultID := ""
	for i, raw := range events {
		e, err := parseMembershipEventAs(raw, "membership event "+strconv.Itoa(i))
		if err != nil {
			return MembershipState{}, err
		}
		if err := checkChainLink(e, i, &vaultID, hashes, opts); err != nil {
			return MembershipState{}, err
		}
		if i == 0 {
			if e.Type != EventGenesis {
				return MembershipState{}, badRequest("chain must start with genesis")
			}
			if e.KeyEpoch != 1 {
				return MembershipState{}, badRequest("genesis key_epoch must be 1")
			}
			author, err := r.applyGenesis(e.Body, e.Author)
			if err != nil {
				return MembershipState{}, err
			}
			if opts.TrustedAnchor != "" && opts.TrustedAnchor != author.SignPub {
				return MembershipState{}, newErr(CodeForbidden, "genesis author is not the trusted anchor")
			}
			if err := VerifyObject(ContextMembership, e, author.SignPub); err != nil {
				return MembershipState{}, err
			}
		} else {
			if e.KeyEpoch < r.keyEpoch {
				return MembershipState{}, newErr(CodeRollback, "key_epoch decreased")
			}
			if e.Type != EventRekey && e.KeyEpoch != r.keyEpoch {
				return MembershipState{}, badRequest("key_epoch changes only on rekey")
			}
			key, err := r.authorKey(e)
			if err != nil {
				return MembershipState{}, err
			}
			if err := VerifyObject(ContextMembership, e, key); err != nil {
				return MembershipState{}, err
			}
			if err := r.apply(e); err != nil {
				return MembershipState{}, err
			}
		}
		h, err := MembershipEventHash(e)
		if err != nil {
			return MembershipState{}, err
		}
		hashes = append(hashes, h)
	}
	if w := opts.Witnessed; w != nil {
		if w.VaultID != "" && w.VaultID != vaultID {
			return MembershipState{}, badRequest("checkpoint belongs to another vault")
		}
		if w.MembershipSeq < 0 || w.MembershipSeq >= int64(len(hashes)) {
			return MembershipState{}, newErr(CodeRollback, "membership chain is behind the witnessed checkpoint")
		}
		if hashes[w.MembershipSeq] != w.MembershipHead {
			return MembershipState{}, newErr(CodeRollback, "membership chain forks from the witnessed checkpoint")
		}
	}
	last := int64(len(events) - 1)
	return r.snapshot(vaultID, last, hashes[last]), nil
}

// checkChainLink enforces vault, seq, prev and membership_epoch linkage of event i.
func checkChainLink(e MembershipEvent, i int, vaultID *string, hashes []string, opts VerifyChainOptions) error {
	if i == 0 {
		*vaultID = e.VaultID
		if opts.VaultID != "" && opts.VaultID != e.VaultID {
			return badRequest("membership chain belongs to another vault")
		}
	} else if e.VaultID != *vaultID {
		return badRequest("membership event belongs to another vault")
	}
	if e.Seq != int64(i) {
		return badRequest("non-sequential seq")
	}
	expectedPrev := ""
	if i > 0 {
		expectedPrev = hashes[i-1]
	}
	if e.Prev != expectedPrev {
		return badRequest("wrong prev hash")
	}
	if e.MembershipEpoch != e.Seq {
		return badRequest("membership_epoch must equal seq")
	}
	return nil
}
