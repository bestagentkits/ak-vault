package akv1

// Reproduces policy-binding.json and checks the binding properties the vectors
// cannot enumerate. Mirrors packages/protocol/test/vectors-policy-binding.test.ts.

import (
	"math/rand"
	"testing"
)

// policyItemsRaw converts the vector item list to PolicyResolutionItem values.
// A shape error is CodeBadRequest, like the TypeScript reference's shape check,
// which runs before every other check.
func policyItemsRaw(v any) ([]PolicyResolutionItem, error) {
	arr, err := asArray(v, "items", MaxResolveItems)
	if err != nil {
		return nil, err
	}
	entry := func(v any) (PolicyResolutionEntry, error) {
		obj, err := asObject(v, "entry")
		if err != nil {
			return PolicyResolutionEntry{}, err
		}
		if err := exactKeys(obj, []string{"tombstone", "payload"}, "entry"); err != nil {
			return PolicyResolutionEntry{}, err
		}
		tomb, err := asBool(obj["tombstone"], "entry.tombstone")
		if err != nil {
			return PolicyResolutionEntry{}, err
		}
		return PolicyResolutionEntry{Tombstone: tomb, Payload: obj["payload"]}, nil
	}
	out := make([]PolicyResolutionItem, 0, len(arr))
	for _, raw := range arr {
		obj, err := asObject(raw, "item")
		if err != nil {
			return nil, err
		}
		if err := exactKeys(obj, []string{"item_id", "head", "branches"}, "item"); err != nil {
			return nil, err
		}
		id, ok := obj["item_id"].(string)
		if !ok {
			return nil, badRequest("item_id must be a string")
		}
		head, err := entry(obj["head"])
		if err != nil {
			return nil, err
		}
		branchesRaw, err := asArray(obj["branches"], "branches", MaxResolveBranches)
		if err != nil {
			return nil, err
		}
		branches := make([]PolicyResolutionEntry, 0, len(branchesRaw))
		for _, b := range branchesRaw {
			e, err := entry(b)
			if err != nil {
				return nil, err
			}
			branches = append(branches, e)
		}
		out = append(out, PolicyResolutionItem{ItemID: id, Head: head, Branches: branches})
	}
	return out, nil
}

func resolveItemPolicyRaw(target, items any) (ResolvedItemPolicy, error) {
	list, err := policyItemsRaw(items)
	if err != nil {
		return ResolvedItemPolicy{}, err
	}
	s, ok := target.(string)
	if !ok {
		return ResolvedItemPolicy{}, badRequest("target must be a string")
	}
	return ResolveItemPolicy(s, list)
}

func checkPolicyBinding(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		resolved := mustOK(resolveItemPolicyRaw(c.raw("target"), c.raw("items")))(t, c.path)
		want := c.obj("expected")
		eqJSON(t, c.path+" resolved", resolved, map[string]any{"policy": want.raw("policy"), "sensitivity": want.raw("sensitivity")})
		local := mustOK(ParseLocalGrant(c.raw("local")))(t, c.path)
		var policy any
		if resolved.Policy != nil {
			policy = resolved.Policy
		}
		grant := mustOK(EffectiveGrant(local, policy, resolved.Sensitivity))(t, c.path)
		eqJSON(t, c.path+" grant", grant, want.raw("grant"))
		want.done()
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("invalid") {
		_, err := resolveItemPolicyRaw(c.raw("target"), c.raw("items"))
		expectCode(t, c, err)
		c.done()
		n.add(1)
	}
}

func bindingPolicyEntry(target string, rules map[string]any, sensitivity string) PolicyResolutionEntry {
	return PolicyResolutionEntry{Payload: ItemPayload{
		Name: "p", Value: "", Sensitivity: sensitivity,
		Meta: map[string]any{"kind": PolicyItemKind, "item_ids": []any{target}, "policy": rules},
	}}
}

func bindingSecretEntry() PolicyResolutionEntry {
	return PolicyResolutionEntry{Payload: ItemPayload{Name: "SYNTHETIC", Value: "v", Meta: map[string]any{}, Sensitivity: SensitivityNormal}}
}

func noWider(narrow, wide LocalGrant) bool {
	return narrow.TTLs <= wide.TTLs && (!wide.RequireApproval || narrow.RequireApproval) &&
		isSubsequence(narrow.Projects, wide.Projects) && isSubsequence(narrow.Purposes, wide.Purposes) && isSubsequence(narrow.Agents, wide.Agents)
}

// TestPolicyBindingOnlyNarrows adds governing policies one at a time: each
// resolution is no wider than the one before it nor than any single policy.
func TestPolicyBindingOnlyNarrows(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	names := []string{"proj_a", "proj_b", "deploy", "claude", "codex", "*"}
	pick := func() []any {
		out := []any{}
		for i := rng.Intn(4); i > 0; i-- {
			out = append(out, names[rng.Intn(len(names))])
		}
		return out
	}
	strs := func(l []any) []string {
		out := make([]string, len(l))
		for i, s := range l {
			out[i] = s.(string)
		}
		return out
	}
	target := RandomID()
	for run := 0; run < 500; run++ {
		local := LocalGrant{TTLs: int64(rng.Intn(5000)), RequireApproval: rng.Intn(2) == 0, Projects: strs(pick()), Purposes: strs(pick()), Agents: strs(pick())}
		items := []PolicyResolutionItem{{ItemID: target, Head: bindingSecretEntry()}}
		previous := mustOK(EffectiveGrant(local, nil, SensitivityNormal))(t, "base")
		for k := 1 + rng.Intn(4); k > 0; k-- {
			rules := map[string]any{}
			if rng.Intn(2) == 0 {
				rules["max_ttl_s"] = int64(rng.Intn(5000))
			}
			if rng.Intn(2) == 0 {
				rules["require_approval"] = rng.Intn(2) == 0
			}
			for _, key := range []string{"allowed_projects", "allowed_purposes", "deny_agents"} {
				if rng.Intn(2) == 0 {
					rules[key] = pick()
				}
			}
			sensitivity := []string{SensitivityNormal, SensitivityHigh}[rng.Intn(2)]
			items = append(items, PolicyResolutionItem{ItemID: RandomID(), Head: bindingPolicyEntry(target, rules, sensitivity)})
			resolved := mustOK(ResolveItemPolicy(target, items))(t, "resolve")
			var policy any
			if resolved.Policy != nil {
				policy = resolved.Policy
			}
			grant := mustOK(EffectiveGrant(local, policy, resolved.Sensitivity))(t, "grant")
			single := mustOK(EffectiveGrant(local, rules, sensitivity))(t, "single")
			if !noWider(grant, previous) || !noWider(grant, single) {
				t.Fatalf("run %d: binding widened a grant: %+v (previous %+v, single %+v)", run, grant, previous, single)
			}
			previous = grant
		}
	}
}

// TestPolicyBindingMovedPolicyRefuses seals a policy item for one vault and
// opens it in another: it does not open, and the device then refuses.
func TestPolicyBindingMovedPolicyRefuses(t *testing.T) {
	vk := randomBytes(32)
	target, policyID := RandomID(), RandomID()
	ctx := ItemContext{VaultID: RandomID(), ItemID: policyID, KeyEpoch: 1, Author: RandomID()}
	payload := bindingPolicyEntry(target, map[string]any{"max_ttl_s": int64(60)}, SensitivityHigh).Payload.(ItemPayload)
	env := mustOK(SealItem(vk, ctx, payload, nil))(t, "seal")
	opened := mustOK(OpenItem(vk, ctx, env))(t, "open")
	items := []PolicyResolutionItem{{ItemID: target, Head: bindingSecretEntry()}, {ItemID: policyID, Head: PolicyResolutionEntry{Payload: opened}}}
	resolved := mustOK(ResolveItemPolicy(target, items))(t, "resolve")
	eqJSON(t, "resolved", resolved, map[string]any{"policy": map[string]any{"max_ttl_s": int64(60)}, "sensitivity": SensitivityHigh})

	moved := ctx
	moved.VaultID = RandomID()
	if _, err := OpenItem(vk, moved, env); CodeOf(err) != CodeDecryptFailed {
		t.Fatalf("moved policy item: expected decrypt_failed, got %v", err)
	}
	items[1].Head.Payload = nil
	if _, err := ResolveItemPolicy(target, items); CodeOf(err) != CodeDecryptFailed {
		t.Fatalf("unopened policy item: expected decrypt_failed, got %v", err)
	}
}
