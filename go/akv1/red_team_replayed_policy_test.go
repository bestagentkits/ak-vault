package akv1

// Red-team: a server re-serves an older revision of a portable policy item
// (spec §5, §6, §8). A policy narrows a grant, so its older revision is the
// wider one. Re-appended, it is a replay (ApplyRecord: conflict). Restored
// below the device's witnessed position and regrown past it, the log passes
// CheckRollback alone and VerifyChangeLog refuses it against the head the
// device kept there. Documented limit: a device resuming from its own cursor
// does not see the restore in the log and keeps its newer policy. Mirrors
// packages/protocol/test/red-team-replayed-policy.test.ts. Holding the policy
// as JSON in the item value is this test's layout only.

import (
	"encoding/json"
	"reflect"
	"testing"
)

type policyReplayFixture struct {
	t      *testing.T
	state  MembershipState
	owner  DeviceKeys
	vk     []byte
	vault  string
	policy string
}

// wire round-trips v through canonical JSON, as a device receives it.
func wire(t *testing.T, v any) any {
	t.Helper()
	b, err := CJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newPolicyReplayFixture(t *testing.T) *policyReplayFixture {
	t.Helper()
	owner := mustOK(CreateDeviceKeys("acct-synthetic", RoleOwner, KindHuman, nil, nil))(t, "owner")
	recovery := mustOK(CreateDeviceKeys("acct-synthetic", RoleOwner, KindHuman, nil, nil))(t, "recovery")
	vault := RandomID()
	body := map[string]any{
		"vault_kind": "personal", "owner_account": "acct-synthetic", "recovery_sign_pub": recovery.Record.SignPub,
		"devices": []any{owner.Record.JSONValue()}, "wraps_digest": B64Encode(randomBytes(32)),
	}
	genesis := mustOK(BuildGenesisEvent(vault, 1, owner.Record.DeviceID, body, owner.SignSecret))(t, "genesis")
	state := mustOK(VerifyMembershipChain([]any{wire(t, genesis.JSONValue())}, VerifyChainOptions{}))(t, "chain")
	return &policyReplayFixture{t: t, state: state, owner: owner, vk: randomBytes(32), vault: vault, policy: RandomID()}
}

func (f *policyReplayFixture) record(itemID string, base int64, value, kind string) SignedRecord {
	ctx := ItemContext{VaultID: f.vault, ItemID: itemID, BaseRevision: base, KeyEpoch: 1, Author: f.owner.Record.DeviceID}
	env := mustOK(SealItem(f.vk, ctx, ItemPayload{Name: "ITEM", Value: value, Meta: map[string]any{"kind": kind}, Sensitivity: SensitivityNormal}, nil))(f.t, "seal")
	r := SignedRecord{VaultID: f.vault, ItemID: itemID, BaseRevision: base, KeyEpoch: 1, Author: f.owner.Record.DeviceID, TS: 1, Resolves: []string{}, Env: env}
	return mustOK(SignRecord(r, f.owner.SignSecret))(f.t, "sign")
}

type logEntry struct {
	seq      int64
	conflict string
	r        SignedRecord
}

type pulled struct {
	head  ChangeLogCursor
	items map[string]ItemState
	view  CheckpointView
}

// pull verifies the log, replays every record and returns the device's view.
func (f *policyReplayFixture) pull(entries []logEntry, items map[string]ItemState, from ChangeLogCursor, kept map[int64]string) (pulled, error) {
	raw := make([]any, len(entries))
	for i, e := range entries {
		var cid any
		if e.conflict != "" {
			cid = e.conflict
		}
		raw[i] = map[string]any{"log_seq": e.seq, "conflict_id": cid, "record": wire(f.t, e.r.JSONValue())}
	}
	v, err := VerifyChangeLog(wire(f.t, raw).([]any), f.state, VerifyChangeLogOptions{From: from, Complete: true, KeptHeads: kept})
	if err != nil {
		return pulled{}, err
	}
	out := map[string]ItemState{}
	for k, s := range items {
		out[k] = s
	}
	for i, r := range v.Records {
		var cur *ItemState
		if s, ok := out[r.ItemID]; ok {
			cur = &s
		}
		next, outcome, err := ApplyRecord(cur, r, entries[i].conflict)
		if err != nil {
			return pulled{}, err
		}
		if entries[i].conflict == "" && outcome.Status != "applied" {
			f.t.Fatalf("test log is not honest at %d", entries[i].seq)
		}
		out[r.ItemID] = next
	}
	list := make([]ItemState, 0, len(out))
	for _, s := range out {
		list = append(list, s)
	}
	digest := mustOK(ComputeStateDigest(StateRows(list)))(f.t, "digest")
	view := CheckpointView{VaultID: f.vault, MembershipSeq: f.state.Seq, MembershipHead: f.state.Head, LogSeq: v.Head.LogSeq, StateDigest: digest, KeyEpoch: f.state.KeyEpoch}
	return pulled{head: v.Head, items: out, view: view}, nil
}

// grant is the effective grant under the policy revision the device holds as head.
func (f *policyReplayFixture) grant(p pulled, log []logEntry) LocalGrant {
	item := p.items[f.policy]
	for _, e := range log {
		if e.r.ItemID != f.policy || e.r.BaseRevision != item.Revision-1 {
			continue
		}
		ctx := ItemContext{VaultID: f.vault, ItemID: f.policy, BaseRevision: e.r.BaseRevision, KeyEpoch: 1, Author: e.r.Author}
		payload := mustOK(OpenItem(f.vk, ctx, e.r.Env.JSONValue()))(f.t, "open")
		policy := mustOK(ParseJSON([]byte(payload.Value)))(f.t, "policy")
		local := LocalGrant{TTLs: 3600, Projects: []string{"proj_a", "proj_b"}, Purposes: []string{"deploy"}, Agents: []string{"claude"}}
		return mustOK(EffectiveGrant(local, policy, SensitivityNormal))(f.t, "grant")
	}
	f.t.Fatal("policy head record not in log")
	return LocalGrant{}
}

func wantCode(t *testing.T, what string, err error, code string) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Errorf("%s: want %s, got %q (%v)", what, code, got, err)
	}
}

func TestRedTeamReplayedPolicy(t *testing.T) {
	f := newPolicyReplayFixture(t)
	other, later := RandomID(), RandomID()
	wide, _ := json.Marshal(map[string]any{"allowed_projects": []string{"proj_a", "proj_b"}})
	narrow, _ := json.Marshal(map[string]any{"allowed_projects": []string{"proj_a"}, "require_approval": true})
	policyV1 := f.record(f.policy, 0, string(wide), "policy")
	policyV2 := f.record(f.policy, 1, string(narrow), "policy")
	honest := []logEntry{{1, "", policyV1}, {2, "", f.record(other, 0, "x1", "secret")}, {3, "", policyV2}}
	// Restored to position 2, then current members keep writing on the restored state.
	regrown := []logEntry{honest[0], honest[1], {3, "", f.record(other, 1, "x2", "secret")}, {4, "", f.record(later, 0, "y1", "secret")}}

	witnessed := mustOK(f.pull(honest, nil, ChangeLogCursor{}, nil))(t, "honest pull")
	if g := f.grant(witnessed, honest); !reflect.DeepEqual(g.Projects, []string{"proj_a"}) || !g.RequireApproval {
		t.Fatalf("device does not hold the narrower policy: %+v", g)
	}
	kept := map[int64]string{witnessed.head.LogSeq: witnessed.head.LogHead}

	t.Run("re-appended older revision is a replay", func(t *testing.T) {
		for _, cid := range []string{"", RandomID()} {
			log := append(append([]logEntry{}, honest...), logEntry{4, cid, policyV1})
			_, err := f.pull(log, nil, ChangeLogCursor{}, nil)
			wantCode(t, "full re-read", err, CodeConflict)
			_, err = f.pull([]logEntry{{4, cid, policyV1}}, witnessed.items, witnessed.head, nil)
			wantCode(t, "resume", err, CodeConflict)
		}
	})

	t.Run("restored and regrown passes CheckRollback alone", func(t *testing.T) {
		served := mustOK(f.pull(regrown, nil, ChangeLogCursor{}, nil))(t, "regrown pull")
		if g := f.grant(served, regrown); !reflect.DeepEqual(g.Projects, []string{"proj_a", "proj_b"}) || g.RequireApproval {
			t.Fatalf("served state should hold the older, wider policy: %+v", g)
		}
		if err := CheckRollback(witnessed.view, served.view); err != nil {
			t.Fatalf("CheckRollback alone should pass the regrown view: %v", err)
		}
		at3 := mustOK(f.pull(regrown[:3], nil, ChangeLogCursor{}, nil))(t, "regrown prefix")
		if at3.view.StateDigest == witnessed.view.StateDigest {
			t.Fatal("state digest at the witnessed position should differ")
		}
	})

	t.Run("kept head refuses the regrown log", func(t *testing.T) {
		_, err := f.pull(regrown, nil, ChangeLogCursor{}, kept)
		wantCode(t, "regrown", err, CodeRollback)
	})

	t.Run("log behind the kept head is refused", func(t *testing.T) {
		_, err := f.pull(honest[:2], nil, ChangeLogCursor{}, kept)
		wantCode(t, "behind kept head", err, CodeRollback)
		behind := mustOK(f.pull(honest[:2], nil, ChangeLogCursor{}, nil))(t, "behind")
		wantCode(t, "behind checkpoint", CheckRollback(witnessed.view, behind.view), CodeRollback)
	})

	t.Run("documented limit: resuming device keeps its newer policy", func(t *testing.T) {
		resumed := mustOK(f.pull(regrown[3:], witnessed.items, witnessed.head, nil))(t, "resume")
		if resumed.head.LogSeq != 4 || resumed.items[f.policy].Revision != 2 {
			t.Fatalf("resumed device should hold policy revision 2 at log_seq 4: %+v", resumed.head)
		}
	})
}
