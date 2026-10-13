package akv1

import (
	"sort"
)

// ConflictBranch is a record preserved after a CAS mismatch.
type ConflictBranch struct {
	ConflictID   string
	RecordDigest string
	Record       SignedRecord
}

// ItemState is the per-item CAS / conflict / tombstone state (spec §5).
type ItemState struct {
	VaultID           string
	ItemID            string
	Revision          int64 // 0 for an item that was never written
	Tombstone         bool
	TombstoneRevision int64  // highest revision at which the item was tombstoned
	Head              string // RecordDigest of the record at Revision ("" if none)
	Conflicts         []ConflictBranch
	Seen              []string // digests of every applied or preserved record
}

// EmptyItemState is the state of an item that was never written.
func EmptyItemState(vaultID, itemID string) ItemState {
	return ItemState{VaultID: vaultID, ItemID: itemID}
}

// Apply outcomes.
const (
	OutcomeApplied  = "applied"
	OutcomeConflict = "conflict"
)

// ApplyOutcome is {status:"applied", revision} or {status:"conflict", conflict_id}.
type ApplyOutcome struct {
	Status     string
	Revision   int64  // set when applied
	ConflictID string // set when conflict
}

// JSONValue returns the outcome object.
func (o ApplyOutcome) JSONValue() any {
	if o.Status == OutcomeConflict {
		return map[string]any{"status": o.Status, "conflict_id": o.ConflictID}
	}
	return map[string]any{"status": o.Status, "revision": o.Revision}
}

// ApplyRecord is the pure CAS model for an already verified and authorized
// record. state is nil for a new item; conflictID ("" = random) is assigned on
// CAS mismatch. Rules, in order:
//  1. record already seen for this item -> CodeConflict (replay; not preserved);
//  2. base_revision < highest tombstone revision -> CodeTombstoned (not preserved);
//  3. base_revision != current revision -> outcome conflict, preserved as a branch;
//  4. tombstone of a missing or deleted item, or resolves naming an unknown
//     branch -> CodeBadRequest;
//  5. otherwise applied: revision = base_revision + 1, resolved branches removed.
//
// The input state is never mutated; a new state is returned.
func ApplyRecord(state *ItemState, r SignedRecord, conflictID string) (ItemState, ApplyOutcome, error) {
	cur := EmptyItemState(r.VaultID, r.ItemID)
	if state != nil {
		cur = *state
	}
	if cur.VaultID != r.VaultID || cur.ItemID != r.ItemID {
		return ItemState{}, ApplyOutcome{}, badRequest("record does not belong to this item")
	}
	digest, err := RecordDigest(r)
	if err != nil {
		return ItemState{}, ApplyOutcome{}, err
	}
	if contains(cur.Seen, digest) {
		return ItemState{}, ApplyOutcome{}, newErr(CodeConflict, "replayed record")
	}
	if r.BaseRevision < cur.TombstoneRevision {
		return ItemState{}, ApplyOutcome{}, newErr(CodeTombstoned, "item was deleted at a later revision")
	}
	seen := append(append([]string(nil), cur.Seen...), digest)

	if r.BaseRevision != cur.Revision {
		if conflictID == "" {
			conflictID = RandomID()
		}
		if _, err := asID(conflictID, "conflict_id"); err != nil {
			return ItemState{}, ApplyOutcome{}, err
		}
		for _, c := range cur.Conflicts {
			if c.ConflictID == conflictID {
				return ItemState{}, ApplyOutcome{}, badRequest("duplicate conflict_id")
			}
		}
		next := cur
		next.Conflicts = append(append([]ConflictBranch(nil), cur.Conflicts...), ConflictBranch{ConflictID: conflictID, RecordDigest: digest, Record: r})
		next.Seen = seen
		return next, ApplyOutcome{Status: OutcomeConflict, ConflictID: conflictID}, nil
	}

	if r.Tombstone && (cur.Revision == 0 || cur.Tombstone) {
		return ItemState{}, ApplyOutcome{}, badRequest("cannot delete a missing or deleted item")
	}
	known := make(map[string]bool, len(cur.Conflicts))
	for _, c := range cur.Conflicts {
		known[c.ConflictID] = true
	}
	for _, id := range r.Resolves {
		if !known[id] {
			return ItemState{}, ApplyOutcome{}, badRequest("resolves names an unknown conflict branch")
		}
	}
	revision := r.BaseRevision + 1
	next := cur
	next.Revision = revision
	next.Tombstone = r.Tombstone
	if r.Tombstone {
		next.TombstoneRevision = revision
	}
	next.Head = digest
	next.Conflicts = nil
	for _, c := range cur.Conflicts {
		if !contains(r.Resolves, c.ConflictID) {
			next.Conflicts = append(next.Conflicts, c)
		}
	}
	next.Seen = seen
	return next, ApplyOutcome{Status: OutcomeApplied, Revision: revision}, nil
}

// StateRow is the (item_id, revision, head) triple covered by a state digest.
type StateRow struct {
	ItemID   string
	Revision int64
	Head     string
}

// ComputeStateDigest returns b64 sha256(cjson(sorted [[item_id, revision, head]...]))
// sorted by item_id byte order; rows at revision 0 are excluded and duplicate
// items are CodeBadRequest.
func ComputeStateDigest(rows []StateRow) (string, error) {
	kept := make([]StateRow, 0, len(rows))
	for _, r := range rows {
		if r.Revision > 0 {
			kept = append(kept, r)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].ItemID < kept[j].ItemID })
	list := make([]any, len(kept))
	for i, r := range kept {
		if i > 0 && kept[i-1].ItemID == r.ItemID {
			return "", badRequest("duplicate item in state")
		}
		list[i] = []any{r.ItemID, r.Revision, r.Head}
	}
	b, err := CJSON(list)
	if err != nil {
		return "", err
	}
	return SHA256B64(b), nil
}

// StateRows converts item states to state digest rows.
func StateRows(items []ItemState) []StateRow {
	out := make([]StateRow, len(items))
	for i, it := range items {
		out[i] = StateRow{ItemID: it.ItemID, Revision: it.Revision, Head: it.Head}
	}
	return out
}
