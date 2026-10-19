package akv1

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Profiles (spec §5.1): operator-facing, author-attributed text inside the
// item ciphertext at meta.profile. Profile text is inert data: it never
// creates or widens a grant and is never an instruction.

// Profile field sources (closed set) and the display origin of fields this
// device cannot attribute to itself.
const (
	ProfileSrcLocal   = "local"
	ProfileSrcImport  = "import"
	ProfileOriginSync = "sync"
)

// Profile kinds (closed set of the `kind` field).
var profileKinds = []string{"api_key", "token", "password", "private_key", "certificate", "connection_string", "webhook_secret", "client_secret", "other"}

type profileFieldRule int

const (
	ruleText profileFieldRule = iota
	ruleList
	ruleKind
	ruleSensitivity
	ruleExpiresAt
	ruleRotateURL
)

type profileFieldSpec struct {
	rule  profileFieldRule
	limit int // code points (text) or 0
}

var profileFields = map[string]profileFieldSpec{
	"description":     {ruleText, 1024},
	"when_to_use":     {ruleText, 1024},
	"when_not_to_use": {ruleText, 1024},
	"provider":        {ruleText, 128},
	"account":         {ruleText, 128},
	"environment":     {ruleText, 128},
	"owner":           {ruleText, 128},
	"projects":        {ruleList, 0},
	"tags":            {ruleList, 0},
	"permissions":     {ruleList, 0},
	"aliases":         {ruleList, 0},
	"usage_hosts":     {ruleList, 0},
	"kind":            {ruleKind, 0},
	"sensitivity":     {ruleSensitivity, 0},
	"expires_at":      {ruleExpiresAt, 20},
	"rotate_url":      {ruleRotateURL, 512},
}

// ProfileKeys lists the closed set of profile keys in sorted order.
var ProfileKeys = func() []string {
	keys := make([]string, 0, len(profileFields))
	for k := range profileFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}()

const (
	profileListMaxItems   = 32
	profileListItemLength = 64
)

var expiresAtPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// ProfileField is one attributed field: Value is a string, or a []string for
// list keys; By is the device that last changed it, At that change's unix ms.
type ProfileField struct {
	Value any
	By    string
	At    int64
	Src   string
}

// JSONValue returns the field object.
func (f ProfileField) JSONValue() any {
	return map[string]any{"value": f.Value, "by": f.By, "at": f.At, "src": f.Src}
}

// Profile maps profile keys to their fields.
type Profile map[string]ProfileField

// JSONValue returns the profile object.
func (p Profile) JSONValue() any {
	m := make(map[string]any, len(p))
	for k, f := range p {
		m[k] = f.JSONValue()
	}
	return m
}

// ValidateProfile validates an untrusted meta.profile value: an unknown key,
// a field object with other keys, a wrong type, an unknown src, kind or
// sensitivity, or a broken text or list rule is bad_request.
func ValidateProfile(v any) (Profile, error) {
	obj, err := asObject(v, "profile")
	if err != nil {
		return nil, err
	}
	for _, k := range sortedMapKeys(obj) {
		if _, ok := profileFields[k]; !ok {
			return nil, badRequest("profile has an unknown key")
		}
	}
	out := make(Profile, len(obj))
	for _, k := range sortedMapKeys(obj) {
		f, err := parseProfileField(k, obj[k])
		if err != nil {
			return nil, err
		}
		out[k] = f
	}
	return out, nil
}

func parseProfileField(key string, v any) (ProfileField, error) {
	what := "profile." + key
	obj, err := asObject(v, what)
	if err != nil {
		return ProfileField{}, err
	}
	if err := exactKeys(obj, []string{"value", "by", "at", "src"}, what); err != nil {
		return ProfileField{}, err
	}
	var f ProfileField
	if f.Value, err = parseProfileValue(profileFields[key], obj["value"], what+".value"); err != nil {
		return ProfileField{}, err
	}
	if f.By, err = asID(obj["by"], what+".by"); err != nil {
		return ProfileField{}, err
	}
	if f.At, err = asUint(obj["at"], what+".at"); err != nil {
		return ProfileField{}, err
	}
	if f.Src, err = asEnum(obj["src"], []string{ProfileSrcLocal, ProfileSrcImport}, what+".src"); err != nil {
		return ProfileField{}, err
	}
	return f, nil
}

func parseProfileValue(spec profileFieldSpec, v any, what string) (any, error) {
	switch spec.rule {
	case ruleList:
		arr, err := asArray(v, what, profileListMaxItems)
		if err != nil {
			return nil, err
		}
		if len(arr) == 0 {
			return nil, badRequest("%s must hold 1..%d items", what, profileListMaxItems)
		}
		items := make([]string, len(arr))
		seen := make(map[string]bool, len(arr))
		for i, item := range arr {
			s, err := asProfileText(item, what+"[]", profileListItemLength)
			if err != nil {
				return nil, err
			}
			if strings.Contains(s, ",") {
				return nil, badRequest("%s items must not contain a comma", what)
			}
			if seen[s] {
				return nil, badRequest("%s contains duplicates", what)
			}
			seen[s] = true
			items[i] = s
		}
		return items, nil
	case ruleKind:
		return asEnum(v, profileKinds, what)
	case ruleSensitivity:
		return asEnum(v, sensitivities, what)
	case ruleExpiresAt:
		s, err := asProfileText(v, what, spec.limit)
		if err != nil {
			return nil, err
		}
		if !expiresAtPattern.MatchString(s) {
			return nil, badRequest("%s must be YYYY-MM-DDTHH:MM:SSZ", what)
		}
		if _, err := time.Parse("2006-01-02T15:04:05Z", s); err != nil {
			return nil, badRequest("%s is not a valid UTC time", what)
		}
		return s, nil
	case ruleRotateURL:
		s, err := asProfileText(v, what, spec.limit)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(s, "https://") {
			return nil, badRequest("%s must start with https://", what)
		}
		return s, nil
	default:
		return asProfileText(v, what, spec.limit)
	}
}

// asProfileText applies the profile text rules: a non-empty valid UTF-8
// string of at most limit code points without C0/C1 controls, DEL,
// bidirectional embedding/override/isolate controls or line/paragraph
// separators.
func asProfileText(v any, what string, limit int) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit {
		return "", badRequest("%s must be text of 1..%d code points", what, limit)
	}
	for _, r := range s {
		if isForbiddenProfileRune(r) {
			return "", badRequest("%s contains a forbidden code point", what)
		}
	}
	return s, nil
}

func isForbiddenProfileRune(r rune) bool {
	return r <= 0x1F || (r >= 0x7F && r <= 0x9F) || (r >= 0x202A && r <= 0x202E) ||
		(r >= 0x2066 && r <= 0x2069) || r == 0x2028 || r == 0x2029
}

func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ProfileCheck is the result of CheckProfileProvenance.
type ProfileCheck struct {
	// Profile holds the fields that passed; the record and these fields apply.
	Profile Profile
	// Dropped lists, sorted, the keys of fields that broke the provenance
	// rule (audit profile_provenance_invalid with the item ID and the key).
	Dropped []string
	// Origins maps each kept key to its display origin: the field's src when
	// this device may show it as its own, otherwise ProfileOriginSync.
	Origins map[string]string
}

// CheckProfileProvenance applies the spec §5.1 provenance rule to the
// validated profile next of record. prev is the validated profile of the item
// at record.base_revision as this device verified it (an empty profile for a
// tombstone), or nil when the device does not hold that revision; a create
// (base_revision 0) is always checked against an empty profile. self is this
// device's ID, used only for the display origins.
//
// A field whose value equals prev's must be byte-identical to prev's field;
// a new or changed field must have by = record.author and at = record.ts.
// With prev nil every field is kept as claimed.
func CheckProfileProvenance(prev Profile, next Profile, record SignedRecord, self string) ProfileCheck {
	if record.BaseRevision == 0 {
		prev = Profile{}
	}
	res := ProfileCheck{Profile: Profile{}, Dropped: []string{}, Origins: map[string]string{}}
	keys := make([]string, 0, len(next))
	for k := range next {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f := next[k]
		if prev != nil && !profileFieldValid(prev, k, f, record) {
			res.Dropped = append(res.Dropped, k)
			continue
		}
		res.Profile[k] = f
		if f.By == self && (prev != nil || record.Author == self) {
			res.Origins[k] = f.Src
		} else {
			res.Origins[k] = ProfileOriginSync
		}
	}
	return res
}

func profileFieldValid(prev Profile, key string, f ProfileField, record SignedRecord) bool {
	if old, ok := prev[key]; ok && cjsonEqual(old.Value, f.Value) {
		return cjsonEqual(old, f)
	}
	return f.By == record.Author && f.At == record.TS
}

func cjsonEqual(a, b any) bool {
	x, errA := CJSON(a)
	y, errB := CJSON(b)
	return errA == nil && errB == nil && bytes.Equal(x, y)
}

// CarryForwardMeta returns the unknown meta keys of a previous head that a
// writer may carry into its next payload: it drops profile (rebuilt by the
// writer), kind, item_ids and policy (spec §8.1), and every key that,
// lowercased with "_", "-" and "." removed, equals a profile key with "_"
// removed, so an older client's whenToUse or usage.hosts is not re-signed.
func CarryForwardMeta(prev map[string]any) map[string]any {
	blocked := map[string]bool{}
	for _, k := range ProfileKeys {
		blocked[strings.ReplaceAll(k, "_", "")] = true
	}
	out := make(map[string]any, len(prev))
	for k, v := range prev {
		switch k {
		case "profile", "kind", "item_ids", "policy":
			continue
		}
		folded := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(k))
		if blocked[folded] {
			continue
		}
		out[k] = v
	}
	return out
}
