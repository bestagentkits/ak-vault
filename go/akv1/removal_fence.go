package akv1

// authorTerm is a device as it was when it wrote a record: its signing key,
// kind, the role at the end of the term (at removal, or now) and the role
// changes of the term in chain order.
type authorTerm struct {
	signPub   string
	kind      string
	finalRole string
	changes   []RoleChange
}

// selectAuthorTerm returns the term of author that wrote a record at keyEpoch.
// Writes are refused between a removal and the next rekey, so a record at or
// below the key epoch of a removal belongs to the device as it was up to its
// first such removal, and a newer record to the current device. ok is false
// when no term could have written it.
func selectAuthorTerm(state MembershipState, author string, keyEpoch int64) (authorTerm, bool) {
	var removals []DeviceRemoval
	for _, rm := range state.Removals {
		if rm.DeviceID == author {
			removals = append(removals, rm)
		}
	}
	index := -1
	for i, rm := range removals {
		if keyEpoch <= rm.KeyEpoch {
			index = i
			break
		}
	}
	var after, before *DeviceRemoval
	switch {
	case index == -1 && len(removals) > 0:
		after = &removals[len(removals)-1]
	case index > 0:
		after = &removals[index-1]
	}
	if index >= 0 {
		before = &removals[index]
	}
	var changes []RoleChange
	for _, c := range state.RoleChanges {
		if c.DeviceID == author && (after == nil || c.ChangedSeq > after.RemovedSeq) && (before == nil || c.ChangedSeq < before.RemovedSeq) {
			changes = append(changes, c)
		}
	}
	if before != nil {
		return authorTerm{signPub: before.SignPub, kind: before.Kind, finalRole: before.Role, changes: changes}, true
	}
	d, ok := state.FindDevice(author)
	if !ok {
		return authorTerm{}, false
	}
	return authorTerm{signPub: d.SignPub, kind: d.Kind, finalRole: d.Role, changes: changes}, true
}

// rolesAt returns the roles the term may have held at change-log position
// logSeq. Let i be the first fenced change (chain order) whose log_fence is at
// or above logSeq, and j the last fenced change before it. The record lies
// after change j and before change i, so the author held the role each change
// in (j, i] replaced, plus the final role when there is no i. Without legacy
// (unfenced) changes that is exactly one role; a legacy change has no position,
// so every role around it is a candidate.
func (t authorTerm) rolesAt(logSeq int64) []string {
	i := -1
	for k, c := range t.changes {
		if c.Fenced() && logSeq <= *c.LogFence {
			i = k
			break
		}
	}
	end, j := len(t.changes), len(t.changes)-1
	if i >= 0 {
		end, j = i+1, i-1
	}
	for j >= 0 && !t.changes[j].Fenced() {
		j--
	}
	roles := make([]string, 0, end-j)
	for _, c := range t.changes[j+1 : end] {
		roles = append(roles, c.PrevRole)
	}
	if i == -1 {
		roles = append(roles, t.finalRole)
	}
	return roles
}

// mayWrite reports whether a device of role and kind is a writer: a human
// owner or editor (spec §11). An allowlist, so a role or kind outside the
// closed sets is never a writer.
func mayWrite(role, kind string) bool {
	return kind == KindHuman && (role == RoleOwner || role == RoleEditor)
}

// VerifyLoggedRecord verifies a record read from the change log at position
// logSeq against verified membership, for current, removed and demoted
// authors alike (spec §5, §6). Every device_remove, member_remove and
// role_set carries a signed log_fence, the change-log position its author had
// verified gap-free. This check binds the position: it refuses a removed
// author's record above its removal fence, and a record whose author, at that
// position, was not a writer (a reader, a machine device, or an editor
// demoted at or below that position). Each fence also signs log_head, which
// binds the contents of every position at or below it; VerifyChangeLog
// replays the log and checks it (spec §5).
//
// Order: record parses (bad_request / unsupported_version); same vault
// (bad_request); logSeq >= 1 (bad_request); the record key_epoch is not above
// the state's key_epoch (forbidden); the author is a current device, or a
// removed device whose record key_epoch is not newer than the epoch current at
// its last removal, else forbidden; signature under the author's key
// (invalid_signature); for every removal of the author whose epoch is >= the
// record's key_epoch, a logSeq above that removal's log_fence is forbidden; the
// author's kind is human and every role it may have held at logSeq is owner
// or editor (forbidden). A legacy role_set signed no fence, so around one the
// author must have been a writer under each role it held between the
// neighbouring fenced changes.
func VerifyLoggedRecord(v any, state MembershipState, logSeq int64) (SignedRecord, error) {
	r, err := ParseRecord(v)
	if err != nil {
		return SignedRecord{}, err
	}
	if r.VaultID != state.VaultID {
		return SignedRecord{}, badRequest("record belongs to another vault")
	}
	if _, err := asInt(logSeq, "log_seq", 1, MaxSafeInteger); err != nil {
		return SignedRecord{}, err
	}
	if r.KeyEpoch > state.KeyEpoch {
		return SignedRecord{}, newErr(CodeForbidden, "record key epoch is newer than the verified membership")
	}
	term, ok := selectAuthorTerm(state, r.Author, r.KeyEpoch)
	if !ok {
		for _, rm := range state.Removals {
			if rm.DeviceID == r.Author {
				return SignedRecord{}, newErr(CodeForbidden, "record key epoch is newer than its removed author could hold")
			}
		}
		return SignedRecord{}, newErr(CodeForbidden, "record author was never a member device")
	}
	if err := VerifyObject(ContextRecord, r, term.signPub); err != nil {
		return SignedRecord{}, err
	}
	for _, rm := range state.Removals {
		if rm.DeviceID == r.Author && r.KeyEpoch <= rm.KeyEpoch && logSeq > rm.LogFence {
			return SignedRecord{}, newErr(CodeForbidden, "record by a removed author is ordered after its removal fence")
		}
	}
	for _, role := range term.rolesAt(logSeq) {
		if !mayWrite(role, term.kind) {
			return SignedRecord{}, newErr(CodeForbidden, "record author could not write at this log position")
		}
	}
	return r, nil
}
