package akv1

import "sort"

// Policy binding (spec §8): which portable policy items cap which item.
//
// A policy item is a live item payload with meta.kind "policy", value "" and
// meta exactly {"kind":"policy","item_ids":[…],"policy":{…}}. item_ids names
// the items it governs by opaque item ID; policy is the §8 policy object; the
// payload sensitivity is the minimum sensitivity it imposes on every governed
// item. All of it is inside the item ciphertext, so the server never learns
// which item a policy governs.

// PolicyItemKind is meta.kind of a policy item.
const PolicyItemKind = "policy"

// Resolution bounds (identical to the TypeScript reference).
const (
	MaxPolicyItemIDs   = 1024
	MaxResolveItems    = 1_000_000
	MaxResolveBranches = 4096
)

// PolicyResolutionEntry is one decrypted record of an item: its head or an
// unresolved conflict branch. Payload is the decrypted payload object (an
// ItemPayload or its JSONValue) and nil when the device could not open the
// record.
type PolicyResolutionEntry struct {
	Tombstone bool
	Payload   any
}

// PolicyResolutionItem is an item as the device holds it: the current head
// and every unresolved conflict branch.
type PolicyResolutionItem struct {
	ItemID   string
	Head     PolicyResolutionEntry
	Branches []PolicyResolutionEntry
}

// ResolvedItemPolicy is the result of ResolveItemPolicy. Policy is the
// intersection of every governing policy as a §8 policy object without text,
// nil when none governs the item; pass it to EffectiveGrant with Sensitivity.
type ResolvedItemPolicy struct {
	Policy      map[string]any
	Sensitivity string
}

// JSONValue returns {"policy": object|null, "sensitivity"}.
func (r ResolvedItemPolicy) JSONValue() any {
	var policy any
	if r.Policy != nil {
		policy = r.Policy
	}
	return map[string]any{"policy": policy, "sensitivity": r.Sensitivity}
}

// PolicyItem is a parsed policy item.
type PolicyItem struct {
	ItemIDs []string
	Policy  PortablePolicy
}

// IsPolicyPayload reports whether a validated live payload is a policy item.
func IsPolicyPayload(p ItemPayload) bool {
	kind, ok := p.Meta["kind"].(string)
	return !p.Deleted && ok && kind == PolicyItemKind
}

// ParsePolicyItem validates the policy-item layout of a live payload whose
// meta.kind is "policy" (CodeBadRequest otherwise): value is "", meta has
// exactly kind, item_ids (1..1024 unique IDs, never the policy's own itemID)
// and policy (parsed by ParsePolicy).
func ParsePolicyItem(itemID string, p ItemPayload) (PolicyItem, error) {
	if _, err := asID(itemID, "item_id"); err != nil {
		return PolicyItem{}, err
	}
	if !IsPolicyPayload(p) {
		return PolicyItem{}, badRequest("item is not a policy item")
	}
	if p.Value != "" {
		return PolicyItem{}, badRequest("policy item value must be empty")
	}
	if err := exactKeys(p.Meta, []string{"kind", "item_ids", "policy"}, "policy item meta"); err != nil {
		return PolicyItem{}, err
	}
	ids, err := asIDList(p.Meta["item_ids"], "policy item meta.item_ids", MaxPolicyItemIDs)
	if err != nil {
		return PolicyItem{}, err
	}
	if len(ids) == 0 {
		return PolicyItem{}, badRequest("policy item governs no item")
	}
	if contains(ids, itemID) {
		return PolicyItem{}, badRequest("policy item names itself")
	}
	policy, err := ParsePolicy(p.Meta["policy"])
	if err != nil {
		return PolicyItem{}, err
	}
	return PolicyItem{ItemIDs: ids, Policy: policy}, nil
}

type boundEntry struct {
	payload *ItemPayload // nil for a tombstone
	policy  *PolicyItem  // nil unless a live policy item
}

func (b boundEntry) names(target string) bool {
	return b.policy != nil && contains(b.policy.ItemIDs, target)
}

// ResolveItemPolicy resolves the policies that govern target from every item
// the device holds. Checks, in order (the first failure is the result):
//  1. shape: target and every item_id are IDs, item_ids are unique, payloads
//     are objects or nil (CodeBadRequest);
//  2. any entry with a nil payload (the device could not open it, so it may be
//     a policy governing target) is CodeDecryptFailed;
//  3. every payload parses as an item payload for its Tombstone flag (CodeBadRequest);
//  4. every live policy payload parses as a policy item (CodeBadRequest);
//  5. target is present, its head is live, and neither its head nor any branch
//     is a policy item (CodeBadRequest);
//  6. an item with unresolved conflict branches whose head or any branch is a
//     live policy naming target is CodeConflict.
//
// Then every other item whose live head is a policy naming target governs it,
// combined by intersection in item_id byte order. Callers refuse release on
// any error and never fall back to the local grant alone.
func ResolveItemPolicy(target string, items []PolicyResolutionItem) (ResolvedItemPolicy, error) {
	if _, err := asID(target, "target item_id"); err != nil {
		return ResolvedItemPolicy{}, err
	}
	if len(items) > MaxResolveItems {
		return ResolvedItemPolicy{}, badRequest("items must be an array of at most %d entries", MaxResolveItems)
	}
	checkEntry := func(e PolicyResolutionEntry) error {
		if e.Payload == nil {
			return nil
		}
		_, err := asObject(e.Payload, "entry payload")
		return err
	}
	seen := make(map[string]bool, len(items))
	for _, it := range items {
		if _, err := asID(it.ItemID, "items[].item_id"); err != nil {
			return ResolvedItemPolicy{}, err
		}
		if err := checkEntry(it.Head); err != nil {
			return ResolvedItemPolicy{}, err
		}
		if len(it.Branches) > MaxResolveBranches {
			return ResolvedItemPolicy{}, badRequest("items[].branches must be an array of at most %d entries", MaxResolveBranches)
		}
		for _, b := range it.Branches {
			if err := checkEntry(b); err != nil {
				return ResolvedItemPolicy{}, err
			}
		}
	}
	for _, it := range items {
		if seen[it.ItemID] {
			return ResolvedItemPolicy{}, badRequest("items contains a duplicate item_id")
		}
		seen[it.ItemID] = true
	}
	for _, it := range items {
		for _, e := range append([]PolicyResolutionEntry{it.Head}, it.Branches...) {
			if e.Payload == nil {
				return ResolvedItemPolicy{}, newErr(CodeDecryptFailed, "an item could not be opened")
			}
		}
	}

	type parsedItem struct {
		id       string
		head     boundEntry
		branches []boundEntry
	}
	open := func(e PolicyResolutionEntry) (boundEntry, error) {
		p, err := ParseItemPayload(e.Payload, e.Tombstone)
		if err != nil || p.Deleted {
			return boundEntry{}, err
		}
		return boundEntry{payload: &p}, nil
	}
	parsed := make([]parsedItem, len(items))
	for i, it := range items {
		parsed[i].id = it.ItemID
		var err error
		if parsed[i].head, err = open(it.Head); err != nil {
			return ResolvedItemPolicy{}, err
		}
		parsed[i].branches = make([]boundEntry, len(it.Branches))
		for j, b := range it.Branches {
			if parsed[i].branches[j], err = open(b); err != nil {
				return ResolvedItemPolicy{}, err
			}
		}
	}
	bind := func(id string, e *boundEntry) error {
		if e.payload == nil || !IsPolicyPayload(*e.payload) {
			return nil
		}
		pi, err := ParsePolicyItem(id, *e.payload)
		if err != nil {
			return err
		}
		e.policy = &pi
		return nil
	}
	for i := range parsed {
		if err := bind(parsed[i].id, &parsed[i].head); err != nil {
			return ResolvedItemPolicy{}, err
		}
		for j := range parsed[i].branches {
			if err := bind(parsed[i].id, &parsed[i].branches[j]); err != nil {
				return ResolvedItemPolicy{}, err
			}
		}
	}

	var own *parsedItem
	others := make([]parsedItem, 0, len(parsed))
	for i := range parsed {
		if parsed[i].id == target {
			own = &parsed[i]
		} else {
			others = append(others, parsed[i])
		}
	}
	if own == nil || own.head.payload == nil {
		return ResolvedItemPolicy{}, badRequest("target item is not a live item")
	}
	sensitivity := SensitivityNormal
	for _, e := range append([]boundEntry{own.head}, own.branches...) {
		if e.policy != nil {
			return ResolvedItemPolicy{}, badRequest("target item is a policy item")
		}
	}
	for _, e := range append([]boundEntry{own.head}, own.branches...) {
		if e.payload != nil && e.payload.Sensitivity == SensitivityHigh {
			sensitivity = SensitivityHigh
		}
	}

	sort.Slice(others, func(a, b int) bool { return others[a].id < others[b].id })
	var governing []PortablePolicy
	for _, it := range others {
		if len(it.branches) > 0 {
			if it.head.names(target) {
				return ResolvedItemPolicy{}, newErr(CodeConflict, "a policy governing the item has an unresolved conflict")
			}
			for _, b := range it.branches {
				if b.names(target) {
					return ResolvedItemPolicy{}, newErr(CodeConflict, "a policy governing the item has an unresolved conflict")
				}
			}
			continue
		}
		if !it.head.names(target) {
			continue
		}
		governing = append(governing, it.head.policy.Policy)
		if it.head.payload.Sensitivity == SensitivityHigh {
			sensitivity = SensitivityHigh
		}
	}
	out := ResolvedItemPolicy{Sensitivity: sensitivity}
	if len(governing) > 0 {
		out.Policy = combinePolicies(governing)
	}
	return out, nil
}

// uniqueStrings keeps the first occurrence of each string, in order.
func uniqueStrings(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := []string{}
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// intersectAllowed narrows acc (nil = no restriction yet) by next (nil = absent).
func intersectAllowed(acc, next []string) []string {
	if next == nil {
		return acc
	}
	base := next
	if acc != nil {
		base = acc
	}
	out := []string{}
	for _, s := range base {
		if contains(next, s) {
			out = append(out, s)
		}
	}
	return uniqueStrings(out)
}

// combinePolicies intersects policies: max_ttl_s min, require_approval OR,
// allowed_* intersected, deny_agents united. Free text is dropped.
func combinePolicies(policies []PortablePolicy) map[string]any {
	var ttl *int64
	var approval *bool
	var projects, purposes, deny []string
	for _, p := range policies {
		if p.MaxTTLs != nil && (ttl == nil || *p.MaxTTLs < *ttl) {
			v := *p.MaxTTLs
			ttl = &v
		}
		if p.RequireApproval != nil {
			v := (approval != nil && *approval) || *p.RequireApproval
			approval = &v
		}
		projects = intersectAllowed(projects, p.AllowedProjects)
		purposes = intersectAllowed(purposes, p.AllowedPurposes)
		if p.DenyAgents != nil {
			deny = uniqueStrings(append(append([]string{}, deny...), p.DenyAgents...))
		}
	}
	out := map[string]any{}
	if ttl != nil {
		out["max_ttl_s"] = *ttl
	}
	if approval != nil {
		out["require_approval"] = *approval
	}
	if projects != nil {
		out["allowed_projects"] = stringsToAny(projects)
	}
	if purposes != nil {
		out["allowed_purposes"] = stringsToAny(purposes)
	}
	if deny != nil {
		out["deny_agents"] = stringsToAny(deny)
	}
	return out
}
