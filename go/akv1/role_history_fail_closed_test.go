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
}
