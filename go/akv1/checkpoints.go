package akv1

// Checkpoint is a signed anti-rollback checkpoint (spec §6).
type Checkpoint struct {
	VaultID        string
	MembershipSeq  int64
	MembershipHead string
	LogSeq         int64
	StateDigest    string
	KeyEpoch       int64
	TS             int64
	Author         string
	Sig            string // empty for an unsigned checkpoint
}

// JSONValue returns the wire object ("sig" omitted when empty).
func (c Checkpoint) JSONValue() any {
	m := map[string]any{
		"v": int64(1), "vault_id": c.VaultID, "membership_seq": c.MembershipSeq, "membership_head": c.MembershipHead,
		"log_seq": c.LogSeq, "state_digest": c.StateDigest, "key_epoch": c.KeyEpoch, "ts": c.TS, "author": c.Author,
	}
	if c.Sig != "" {
		m["sig"] = c.Sig
	}
	return m
}

// View returns the comparable part of the checkpoint.
func (c Checkpoint) View() CheckpointView {
	return CheckpointView{VaultID: c.VaultID, MembershipSeq: c.MembershipSeq, MembershipHead: c.MembershipHead, LogSeq: c.LogSeq, StateDigest: c.StateDigest, KeyEpoch: c.KeyEpoch}
}

// CheckpointView is the comparable part of a checkpoint; a freshly pulled
// state can be expressed as one.
type CheckpointView struct {
	VaultID        string
	MembershipSeq  int64
	MembershipHead string
	LogSeq         int64
	StateDigest    string
	KeyEpoch       int64
}

// SignCheckpoint signs c (its Sig is replaced) with an Ed25519 seed.
func SignCheckpoint(c Checkpoint, seed []byte) (Checkpoint, error) {
	c.Sig = ""
	sig, err := SignDetached(ContextCheckpoint, c, seed)
	if err != nil {
		return Checkpoint{}, err
	}
	c.Sig = sig
	return c, nil
}

// ParseCheckpoint structurally validates an untrusted checkpoint.
func ParseCheckpoint(v any) (Checkpoint, error) {
	const what = "checkpoint"
	obj, err := asObject(v, what)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return Checkpoint{}, err
	}
	if err := exactKeys(obj, []string{"v", "vault_id", "membership_seq", "membership_head", "log_seq", "state_digest", "key_epoch", "ts", "author", "sig"}, what); err != nil {
		return Checkpoint{}, err
	}
	var c Checkpoint
	if c.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return Checkpoint{}, err
	}
	if c.MembershipSeq, err = asUint(obj["membership_seq"], what+".membership_seq"); err != nil {
		return Checkpoint{}, err
	}
	if c.MembershipHead, err = asB64(obj["membership_head"], what+".membership_head", 32); err != nil {
		return Checkpoint{}, err
	}
	if c.LogSeq, err = asUint(obj["log_seq"], what+".log_seq"); err != nil {
		return Checkpoint{}, err
	}
	if c.StateDigest, err = asB64(obj["state_digest"], what+".state_digest", 32); err != nil {
		return Checkpoint{}, err
	}
	if c.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return Checkpoint{}, err
	}
	if c.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return Checkpoint{}, err
	}
	if c.Author, err = asID(obj["author"], what+".author"); err != nil {
		return Checkpoint{}, err
	}
	if c.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return Checkpoint{}, err
	}
	return c, nil
}

// VerifyCheckpoint verifies a checkpoint signed by any current member device
// of state (other vault: bad_request; unknown author: forbidden; bad
// signature: invalid_signature).
func VerifyCheckpoint(v any, state MembershipState) (Checkpoint, error) {
	c, err := ParseCheckpoint(v)
	if err != nil {
		return Checkpoint{}, err
	}
	if c.VaultID != state.VaultID {
		return Checkpoint{}, badRequest("checkpoint belongs to another vault")
	}
	d, ok := state.FindDevice(c.Author)
	if !ok {
		return Checkpoint{}, newErr(CodeForbidden, "checkpoint author is not a current device")
	}
	if err := VerifyObject(ContextCheckpoint, c, d.SignPub); err != nil {
		return Checkpoint{}, err
	}
	return c, nil
}

// CheckRollback returns CodeRollback if incoming is older than or forked from
// witnessed: lower membership_seq, same membership_seq with a different head,
// lower log_seq, same log_seq with a different state_digest, or lower key_epoch.
//
// It compares checkpoints only, so it is not the whole spec §6 check: a log
// restored below witnessed.LogSeq and regrown past it passes. Callers MUST also
// replay the log with VerifyChangeLog passing the head they kept at
// witnessed.LogSeq in KeptHeads, and, for a peer's checkpoint (which carries no
// head), compare the state digest they computed at that position.
func CheckRollback(witnessed, incoming CheckpointView) error {
	if witnessed.VaultID != incoming.VaultID {
		return badRequest("checkpoint belongs to another vault")
	}
	if incoming.MembershipSeq < witnessed.MembershipSeq {
		return newErr(CodeRollback, "membership head is behind the witnessed checkpoint")
	}
	if incoming.MembershipSeq == witnessed.MembershipSeq && incoming.MembershipHead != witnessed.MembershipHead {
		return newErr(CodeRollback, "membership head forks from the witnessed checkpoint")
	}
	if incoming.LogSeq < witnessed.LogSeq {
		return newErr(CodeRollback, "log_seq is behind the witnessed checkpoint")
	}
	if incoming.LogSeq == witnessed.LogSeq && incoming.StateDigest != witnessed.StateDigest {
		return newErr(CodeRollback, "state forks from the witnessed checkpoint")
	}
	if incoming.KeyEpoch < witnessed.KeyEpoch {
		return newErr(CodeRollback, "key_epoch is behind the witnessed checkpoint")
	}
	return nil
}
