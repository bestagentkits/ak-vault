package akv1

// LocalGrant is a device-local grant for an item.
type LocalGrant struct {
	TTLs            int64
	RequireApproval bool
	Projects        []string
	Purposes        []string
	Agents          []string
}

// JSONValue returns {"ttl_s","require_approval","projects","purposes","agents"}.
func (g LocalGrant) JSONValue() any {
	return map[string]any{
		"ttl_s": g.TTLs, "require_approval": g.RequireApproval,
		"projects": stringsToAny(g.Projects), "purposes": stringsToAny(g.Purposes), "agents": stringsToAny(g.Agents),
	}
}

// PortablePolicy is a restrictive-only policy (spec §8). Nil pointers/slices
// mean "field absent" (no extra restriction, never "allow").
type PortablePolicy struct {
	MaxTTLs         *int64
	RequireApproval *bool
	AllowedProjects []string // nil = absent; empty = deny all
	AllowedPurposes []string
	DenyAgents      []string
	// UntrustedText holds author-supplied display text (description,
	// when_to_use, urls). It is never interpreted and never affects a grant.
	UntrustedText PolicyText
}

// PolicyText is inert, untrusted, author-attributed policy text.
type PolicyText struct {
	Description *string
	WhenToUse   *string
	URLs        []string
}

func asStringList(v any, what string) ([]string, error) {
	arr, err := asArray(v, what, 1024)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, err := asString(item, what+"[]", 256, 1)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// ParsePolicy parses an untrusted policy object; unknown fields or wrong
// types are CodeBadRequest (the caller denies).
func ParsePolicy(v any) (PortablePolicy, error) {
	obj, err := asObject(v, "policy")
	if err != nil {
		return PortablePolicy{}, err
	}
	if err := exactKeys(obj, nil, "policy", "max_ttl_s", "require_approval", "allowed_projects", "allowed_purposes", "deny_agents", "description", "when_to_use", "urls"); err != nil {
		return PortablePolicy{}, err
	}
	var p PortablePolicy
	if x, ok := obj["max_ttl_s"]; ok {
		n, err := asUint(x, "policy.max_ttl_s")
		if err != nil {
			return PortablePolicy{}, err
		}
		p.MaxTTLs = &n
	}
	if x, ok := obj["require_approval"]; ok {
		b, err := asBool(x, "policy.require_approval")
		if err != nil {
			return PortablePolicy{}, err
		}
		p.RequireApproval = &b
	}
	lists := []struct {
		key string
		dst *[]string
	}{{"allowed_projects", &p.AllowedProjects}, {"allowed_purposes", &p.AllowedPurposes}, {"deny_agents", &p.DenyAgents}}
	for _, l := range lists {
		if x, ok := obj[l.key]; ok {
			if *l.dst, err = asStringList(x, "policy."+l.key); err != nil {
				return PortablePolicy{}, err
			}
		}
	}
	for _, key := range []string{"description", "when_to_use"} {
		if x, ok := obj[key]; ok {
			s, err := asString(x, "policy."+key, 8192, 0)
			if err != nil {
				return PortablePolicy{}, err
			}
			if key == "description" {
				p.UntrustedText.Description = &s
			} else {
				p.UntrustedText.WhenToUse = &s
			}
		}
	}
	if x, ok := obj["urls"]; ok {
		arr, err := asArray(x, "policy.urls", 64)
		if err != nil {
			return PortablePolicy{}, err
		}
		p.UntrustedText.URLs = make([]string, 0, len(arr))
		for _, item := range arr {
			s, err := asString(item, "policy.urls[]", 2048, 0)
			if err != nil {
				return PortablePolicy{}, err
			}
			p.UntrustedText.URLs = append(p.UntrustedText.URLs, s)
		}
	}
	return p, nil
}

// ParseLocalGrant validates a local grant object.
func ParseLocalGrant(v any) (LocalGrant, error) {
	const what = "local grant"
	obj, err := asObject(v, what)
	if err != nil {
		return LocalGrant{}, err
	}
	if err := exactKeys(obj, []string{"ttl_s", "require_approval", "projects", "purposes", "agents"}, what); err != nil {
		return LocalGrant{}, err
	}
	var g LocalGrant
	if g.TTLs, err = asUint(obj["ttl_s"], what+".ttl_s"); err != nil {
		return LocalGrant{}, err
	}
	if g.RequireApproval, err = asBool(obj["require_approval"], what+".require_approval"); err != nil {
		return LocalGrant{}, err
	}
	if g.Projects, err = asStringList(obj["projects"], what+".projects"); err != nil {
		return LocalGrant{}, err
	}
	if g.Purposes, err = asStringList(obj["purposes"], what+".purposes"); err != nil {
		return LocalGrant{}, err
	}
	if g.Agents, err = asStringList(obj["agents"], what+".agents"); err != nil {
		return LocalGrant{}, err
	}
	return g, nil
}

// EffectiveGrant narrows a device-local grant by an untrusted portable policy
// (nil = no policy). ttl = min, require_approval = local OR policy OR
// sensitivity "high", projects/purposes = local filtered by allowed_* (absent
// = unchanged), agents = local minus deny_agents. The result is always a
// subset of local.
func EffectiveGrant(local LocalGrant, policy any, sensitivity string) (LocalGrant, error) {
	l, err := ParseLocalGrant(local)
	if err != nil {
		return LocalGrant{}, err
	}
	level, err := asEnum(sensitivity, sensitivities, "sensitivity")
	if err != nil {
		return LocalGrant{}, err
	}
	var p PortablePolicy
	if policy != nil {
		if p, err = ParsePolicy(policy); err != nil {
			return LocalGrant{}, err
		}
	}
	within := func(list, allowed []string) []string {
		out := []string{}
		for _, x := range list {
			if allowed == nil || contains(allowed, x) {
				out = append(out, x)
			}
		}
		return out
	}
	g := LocalGrant{
		TTLs:            l.TTLs,
		RequireApproval: l.RequireApproval || (p.RequireApproval != nil && *p.RequireApproval) || level == SensitivityHigh,
		Projects:        within(l.Projects, p.AllowedProjects),
		Purposes:        within(l.Purposes, p.AllowedPurposes),
		Agents:          []string{},
	}
	if p.MaxTTLs != nil && *p.MaxTTLs < g.TTLs {
		g.TTLs = *p.MaxTTLs
	}
	for _, a := range l.Agents {
		if !contains(p.DenyAgents, a) {
			g.Agents = append(g.Agents, a)
		}
	}
	// Defensive invariant: a policy can only narrow.
	if g.TTLs > l.TTLs || (l.RequireApproval && !g.RequireApproval) {
		return LocalGrant{}, newErr(CodeForbidden, "policy attempted to widen a grant")
	}
	return g, nil
}
