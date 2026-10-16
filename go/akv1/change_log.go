package akv1

import "strconv"

// Change-log head chain and log replay against signed removal fences (spec §5).
//
// Every change-log position n has a head that commits to the prefix 1..n:
//
//	log_head[0] = ""
//	log_head[n] = b64 sha256(utf8("akv1/log-head") || 0x0A ||
//	              cjson({"conflict_id", "log_seq": n, "prev": log_head[n-1], "record": RecordDigest}))
//
// where conflict_id is the preserved branch's ID, or null for an applied
// record. A removal signs {log_fence, log_head}, the head its author computed
// itself at the fence, so a device that first reads the log after the removal
// detects any position at or below the fence that differs from what the
// remover verified.

// MaxChangeLogEntries bounds the entries of one VerifyChangeLog call (callers
// verify page by page).
const MaxChangeLogEntries = 100000

// ChangeLogCursor is a verified change-log position and the head at it. The
// zero value is the empty log (position 0, head "").
type ChangeLogCursor struct {
	LogSeq  int64
	LogHead string
}

// JSONValue returns {"log_seq","log_head"}.
func (c ChangeLogCursor) JSONValue() any {
	return map[string]any{"log_seq": c.LogSeq, "log_head": c.LogHead}
}

// NextLogHead returns the head at logSeq given the head at logSeq-1 (prev),
// the entry's conflict ID ("" for an applied record, encoded as null) and its
// RecordDigest.
func NextLogHead(prev string, logSeq int64, conflictID string, recordDigest string) (string, error) {
	var cid any
	if conflictID != "" {
		cid = conflictID
	}
	b, err := CJSON(map[string]any{"conflict_id": cid, "log_seq": logSeq, "prev": prev, "record": recordDigest})
	if err != nil {
		return "", err
	}
	return SHA256B64(concatBytes([]byte("akv1/log-head\n"), b)), nil
}

// ParseLogPosition validates a {log_fence, log_head} pair: the head is ""
// exactly when the position is 0, else b64 of 32 bytes (bad_request).
func ParseLogPosition(logSeq, logHead any, seqName, headName string) (ChangeLogCursor, error) {
	seq, err := asInt(logSeq, seqName, 0, MaxSafeInteger)
	if err != nil {
		return ChangeLogCursor{}, err
	}
	if seq == 0 {
		if s, ok := logHead.(string); !ok || s != "" {
			return ChangeLogCursor{}, badRequest("%s must be \"\" at position 0", headName)
		}
		return ChangeLogCursor{}, nil
	}
	head, err := asB64(logHead, headName, 32)
	if err != nil {
		return ChangeLogCursor{}, err
	}
	return ChangeLogCursor{LogSeq: seq, LogHead: head}, nil
}

// VerifyChangeLogOptions configures VerifyChangeLog.
type VerifyChangeLogOptions struct {
	// From is the cursor the entries continue from (zero value: the empty
	// log). It MUST be a cursor this client computed itself, from position 1,
	// never a value the server supplied.
	From ChangeLogCursor
	// Complete states that the entries reach the server's current head (the
	// last page); a removal fence beyond the last entry is then rollback.
	Complete bool
	// KeptHeads are heads this client computed earlier, by position. Every
	// removal whose fence lies below From (other than at 0) MUST be covered: a
	// missing head is bad_request, a different one rollback. Keep the head of
	// every verified position, or verify again from the empty log. A kept head
	// at a position this call covers (From's or an entry's) MUST equal the head
	// computed there, and with Complete no kept head may lie beyond the last
	// position (rollback): a log restored below a position the client holds,
	// then regrown past it, is refused here, which CheckRollback on checkpoints
	// alone does not do. Pass at least the head at the highest witnessed
	// checkpoint's log_seq.
	KeptHeads map[int64]string
}

// VerifiedChangeLog is the result of VerifyChangeLog.
type VerifiedChangeLog struct {
	Head    ChangeLogCursor // cursor after the last entry (From when there are none)
	Records []SignedRecord  // verified records in log order
}

// VerifyChangeLog verifies change-log entries {log_seq, conflict_id, record}
// that continue from opts.From, against verified membership. Order: From is a
// valid position (bad_request); entries is bounded; every removal whose fence
// is at From matches From.LogHead (rollback); every removal whose fence lies in
// 1..From.LogSeq-1 has a kept head (bad_request) equal to its signed head
// (rollback); then per entry: exact
// keys, log_seq integer, conflict_id null or an ID (bad_request); log_seq is
// the previous position + 1 (rollback: gap, repeat or reorder);
// VerifyLoggedRecord(record, state, log_seq); the head advances. Every removal
// whose log_fence is a covered position (From's or an entry's) MUST have
// signed exactly the head computed there (rollback), and every kept head at a
// covered position MUST equal it (rollback). With opts.Complete, a removal
// fence or a kept head beyond the last position is rollback.
func VerifyChangeLog(entries []any, state MembershipState, opts VerifyChangeLogOptions) (VerifiedChangeLog, error) {
	head, err := ParseLogPosition(opts.From.LogSeq, opts.From.LogHead, "from.log_seq", "from.log_head")
	if err != nil {
		return VerifiedChangeLog{}, err
	}
	if len(entries) > MaxChangeLogEntries {
		return VerifiedChangeLog{}, badRequest("entries must be an array of at most %d entries", MaxChangeLogEntries)
	}
	checkFences := func(at ChangeLogCursor) error {
		for _, rm := range state.Removals {
			if rm.LogFence == at.LogSeq && rm.LogHead != at.LogHead {
				return newErr(CodeRollback, "change log differs from the log a removal fence signed")
			}
		}
		if kept, ok := opts.KeptHeads[at.LogSeq]; ok && kept != at.LogHead {
			return newErr(CodeRollback, "change log differs from a head this client kept")
		}
		return nil
	}
	if err := checkFences(head); err != nil {
		return VerifiedChangeLog{}, err
	}
	for _, rm := range state.Removals {
		if rm.LogFence == 0 || rm.LogFence >= head.LogSeq {
			continue
		}
		kept, ok := opts.KeptHeads[rm.LogFence]
		if !ok {
			return VerifiedChangeLog{}, badRequest("a removal fence lies below from; pass the head kept at that position")
		}
		if kept != rm.LogHead {
			return VerifiedChangeLog{}, newErr(CodeRollback, "change log differs from the log a removal fence signed")
		}
	}
	records := make([]SignedRecord, 0, len(entries))
	for i, raw := range entries {
		what := "entries[" + strconv.Itoa(i) + "]"
		entry, err := asObject(raw, what)
		if err != nil {
			return VerifiedChangeLog{}, err
		}
		if err := exactKeys(entry, []string{"log_seq", "conflict_id", "record"}, what); err != nil {
			return VerifiedChangeLog{}, err
		}
		logSeq, err := asInt(entry["log_seq"], what+".log_seq", 1, MaxSafeInteger)
		if err != nil {
			return VerifiedChangeLog{}, err
		}
		conflictID := ""
		if entry["conflict_id"] != nil {
			if conflictID, err = asID(entry["conflict_id"], what+".conflict_id"); err != nil {
				return VerifiedChangeLog{}, err
			}
		}
		if logSeq != head.LogSeq+1 {
			return VerifiedChangeLog{}, newErr(CodeRollback, "change log is not contiguous")
		}
		r, err := VerifyLoggedRecord(entry["record"], state, logSeq)
		if err != nil {
			return VerifiedChangeLog{}, err
		}
		digest, err := RecordDigest(r)
		if err != nil {
			return VerifiedChangeLog{}, err
		}
		next, err := NextLogHead(head.LogHead, logSeq, conflictID, digest)
		if err != nil {
			return VerifiedChangeLog{}, err
		}
		head = ChangeLogCursor{LogSeq: logSeq, LogHead: next}
		if err := checkFences(head); err != nil {
			return VerifiedChangeLog{}, err
		}
		records = append(records, r)
	}
	if opts.Complete {
		for _, rm := range state.Removals {
			if rm.LogFence > head.LogSeq {
				return VerifiedChangeLog{}, newErr(CodeRollback, "change log is behind a signed removal fence")
			}
		}
		for logSeq := range opts.KeptHeads {
			if logSeq > head.LogSeq {
				return VerifiedChangeLog{}, newErr(CodeRollback, "change log is behind a head this client kept")
			}
		}
	}
	return VerifiedChangeLog{Head: head, Records: records}, nil
}
