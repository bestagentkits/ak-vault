package akv1

import (
	"path/filepath"
	"testing"
)

// TestVerifyLoggedRecordFailsClosedOnUnknownRoleOrKind alters the author of a
// record the role-history vectors accept: a role or kind outside the closed
// sets, on the device or in a role change, is never a writer.
func TestVerifyLoggedRecordFailsClosedOnUnknownRoleOrKind(t *testing.T) {
	v := loadVectorJSON(t, filepath.Join(vectorsDir(t), "role-history.json"))
	chain := v["chains"].(map[string]any)["roles"].([]any)
	state, err := VerifyMembershipChain(chain, VerifyChainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var accepted map[string]any
	for _, c := range v["cases"].([]any) {
		if cm := c.(map[string]any); cm["name"] == "editor_at_newer_key_epoch" {
			accepted = cm
		}
	}
	if accepted == nil {
		t.Fatal("role-history.json: case editor_at_newer_key_epoch not found")
	}
	record := accepted["record"]
	author := record.(map[string]any)["author"].(string)
	logSeq := accepted["log_seq"].(int64)
	if _, err := VerifyLoggedRecord(record, state, logSeq); err != nil {
		t.Fatalf("unaltered state: %v", err)
	}
	withDevice := func(role, kind string) MembershipState {
		altered := state
		altered.Devices = append([]DeviceRecord(nil), state.Devices...)
		for i, d := range altered.Devices {
			if d.DeviceID == author {
				if role != "" {
					altered.Devices[i].Role = role
				}
				if kind != "" {
					altered.Devices[i].Kind = kind
				}
			}
		}
		return altered
	}
	expectForbidden := func(name string, st MembershipState, at int64) {
		t.Helper()
		_, err := VerifyLoggedRecord(record, st, at)
		if CodeOf(err) != CodeForbidden {
			t.Errorf("%s: got %v, want forbidden", name, err)
		}
	}
	expectForbidden("unknown role", withDevice("admin", ""), logSeq)
	expectForbidden("unknown kind", withDevice("", "robot"), logSeq)
	changed := state
	changed.RoleChanges = append([]RoleChange(nil), state.RoleChanges...)
	for i, c := range changed.RoleChanges {
		if c.DeviceID == author {
			changed.RoleChanges[i].PrevRole = "admin"
			changed.RoleChanges[i].Role = "admin"
		}
	}
	expectForbidden("unknown role in a role change", changed, 2)

	emptyRole := state
	emptyRole.Devices = append([]DeviceRecord(nil), state.Devices...)
	for i, d := range emptyRole.Devices {
		if d.DeviceID == author {
			emptyRole.Devices[i].Role = ""
		}
	}
	expectForbidden("empty role", emptyRole, logSeq)

	states := map[string]MembershipState{}
	for name, raw := range v["chains"].(map[string]any) {
		st, err := VerifyMembershipChain(raw.([]any), VerifyChainOptions{})
		if err != nil {
			t.Fatal(err)
		}
		states[name] = st
	}
	caseNamed := func(name string) (any, MembershipState, int64) {
		t.Helper()
		for _, c := range v["cases"].([]any) {
			if cm := c.(map[string]any); cm["name"] == name {
				st := states[cm["chain"].(string)]
				if _, err := VerifyLoggedRecord(cm["record"], st, cm["log_seq"].(int64)); err != nil {
					t.Fatalf("%s unaltered: %v", name, err)
				}
				return cm["record"], st, cm["log_seq"].(int64)
			}
		}
		t.Fatalf("role-history.json: case %s not found", name)
		return nil, MembershipState{}, 0
	}

	// A role outside the closed set among the candidates of a legacy span.
	rec2, st2, at2 := caseNamed("legacy_reader_in_legacy_promotion_span")
	author2 := rec2.(map[string]any)["author"].(string)
	legacy := st2
	legacy.RoleChanges = append([]RoleChange(nil), st2.RoleChanges...)
	for i, c := range legacy.RoleChanges {
		if c.DeviceID == author2 && !c.Fenced() {
			legacy.RoleChanges[i].PrevRole = "admin"
		}
	}
	if _, err := VerifyLoggedRecord(rec2, legacy, at2); CodeOf(err) != CodeForbidden {
		t.Errorf("unknown role in a legacy span: got %v, want forbidden", err)
	}

	// An unknown kind on the removal that ends the author's term.
	rec3, st3, at3 := caseNamed("promoted_reader_after_promotion_fence")
	author3 := rec3.(map[string]any)["author"].(string)
	removed := st3
	removed.Removals = append([]DeviceRemoval(nil), st3.Removals...)
	for i, rm := range removed.Removals {
		if rm.DeviceID == author3 {
			removed.Removals[i].Kind = "robot"
		}
	}
	if _, err := VerifyLoggedRecord(rec3, removed, at3); CodeOf(err) != CodeForbidden {
		t.Errorf("unknown kind on a removal: got %v, want forbidden", err)
	}
}
