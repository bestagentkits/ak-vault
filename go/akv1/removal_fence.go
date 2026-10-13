package akv1

// VerifyLoggedRecord verifies a record read from the change log at position
// logSeq against verified membership, for current and removed authors alike
// (spec §5, §6). Every device_remove and member_remove carries a signed
// log_fence, the change-log head its author had verified gap-free. The fence
// binds a position, not the log contents: it refuses a removed author's record
// above the fence, while the contents of positions at or below it are trusted
// only by a client that holds its own copy of them (spec §5). Writes are
// refused between a removal and the next rekey, so every legitimate later
// write by a re-added device ID uses a newer key epoch and is unaffected.
//
// Order: record parses (bad_request / unsupported_version); same vault
// (bad_request); logSeq >= 1 (bad_request); the author is a current device, or a
// removed device whose record key_epoch is not newer than the epoch current at
// its last removal, else forbidden; signature under the author's key
// (invalid_signature); for every removal of the author whose epoch is >= the
// record's key_epoch, a logSeq above that removal's log_fence is forbidden.
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
	var removals []DeviceRemoval
	for _, rm := range state.Removals {
		if rm.DeviceID == r.Author {
			removals = append(removals, rm)
		}
	}
	var signPub string
	if d, ok := state.FindDevice(r.Author); ok {
		signPub = d.SignPub
	} else {
		if len(removals) == 0 {
			return SignedRecord{}, newErr(CodeForbidden, "record author was never a member device")
		}
		last := removals[len(removals)-1]
		if r.KeyEpoch > last.KeyEpoch {
			return SignedRecord{}, newErr(CodeForbidden, "record key epoch is newer than its removed author could hold")
		}
		signPub = last.SignPub
	}
	if err := VerifyObject(ContextRecord, r, signPub); err != nil {
		return SignedRecord{}, err
	}
	for _, rm := range removals {
		if r.KeyEpoch <= rm.KeyEpoch && logSeq > rm.LogFence {
			return SignedRecord{}, newErr(CodeForbidden, "record by a removed author is ordered after its removal fence")
		}
	}
	return r, nil
}
