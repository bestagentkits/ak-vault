package akv1

import (
	"regexp"
	"unicode/utf8"
)

// Relay tool arguments and results (spec §9.7 "Tools"): canonical JSON
// objects with exact key sets. A device answers invalid args with the relay
// error invalid_args; the Worker refuses them before relaying or sealing.
// Item names are 1..4096 UTF-16 code units, query, purpose and project are
// profile text (code points), cursors, request IDs and device labels are
// UTF-8 bytes.

var (
	searchFields  = []string{"name", "description", "provider", "account", "environment", "projects", "tags"}
	envVarPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	// entryOrigins is the closed set of a tool result's profile field origins.
	entryOrigins = []string{ProfileSrcLocal, ProfileSrcImport, ProfileOriginSync}
)

const maxToolResultItems = 100

// ValidateToolArgs checks a call's args against the exact keys and limits of
// its tool. Every failure is bad_request.
func ValidateToolArgs(tool string, args map[string]any) error {
	const what = "args"
	if args == nil {
		return badRequest("%s must be an object", what)
	}
	switch tool {
	case ToolSearch:
		if err := exactKeys(args, []string{"query"}, what, "fields", "limit"); err != nil {
			return err
		}
		if _, err := asProfileText(args["query"], what+".query", 200); err != nil {
			return err
		}
		if f, ok := args["fields"]; ok {
			fields, err := asEnumSet(f, searchFields, what+".fields")
			if err != nil {
				return err
			}
			if len(fields) == 0 {
				return badRequest("%s.fields must be a non-empty set", what)
			}
		}
		return optionalInt(args, "limit", what, 1, 50)
	case ToolList:
		if err := exactKeys(args, nil, what, "cursor", "limit"); err != nil {
			return err
		}
		if c, ok := args["cursor"]; ok {
			if _, err := asUTF8Bytes(c, what+".cursor", 1, 256); err != nil {
				return err
			}
		}
		return optionalInt(args, "limit", what, 1, 100)
	case ToolDescribe, ToolDelete:
		if err := exactKeys(args, []string{"name"}, what); err != nil {
			return err
		}
		_, err := asItemName(args["name"], what+".name")
		return err
	case ToolSet:
		if err := exactKeys(args, []string{"name", "value"}, what, "sensitivity"); err != nil {
			return err
		}
		if _, err := asItemName(args["name"], what+".name"); err != nil {
			return err
		}
		if _, err := asWellFormedString(args["value"], what+".value", MaxItemValueLength, 0); err != nil {
			return err
		}
		if sv, ok := args["sensitivity"]; ok {
			if _, err := asEnum(sv, sensitivities, what+".sensitivity"); err != nil {
				return err
			}
		}
		// The sealed operation must fit one AEAD plaintext, so every set is sealable.
		op := map[string]any{"op": SealedOpSet}
		for k, v := range args {
			op[k] = v
		}
		if b, err := CJSON(op); err != nil || len(b) > MaxPlaintextBytes {
			return badRequest("%s is too large to seal", what)
		}
		return nil
	case ToolRequest:
		if err := exactKeys(args, []string{"name", "purpose"}, what, "project", "ttl_s"); err != nil {
			return err
		}
		if _, err := asItemName(args["name"], what+".name"); err != nil {
			return err
		}
		if _, err := asProfileText(args["purpose"], what+".purpose", 200); err != nil {
			return err
		}
		if p, ok := args["project"]; ok {
			if _, err := asProfileText(p, what+".project", 128); err != nil {
				return err
			}
		}
		return optionalInt(args, "ttl_s", what, 1, 86400)
	case ToolRun:
		return validateRunArgs(args)
	default:
		return badRequest("%s: unknown tool", what)
	}
}

func validateRunArgs(args map[string]any) error {
	const what = "args"
	if err := exactKeys(args, []string{"argv", "env"}, what, "cwd_project", "timeout_s"); err != nil {
		return err
	}
	argv, err := asArray(args["argv"], what+".argv", 64)
	if err != nil {
		return err
	}
	if len(argv) == 0 {
		return badRequest("%s.argv must not be empty", what)
	}
	for _, a := range argv {
		if _, err := asWellFormedString(a, what+".argv[]", MaxSafeInteger, 0); err != nil {
			return err
		}
	}
	env, err := asArray(args["env"], what+".env", 16)
	if err != nil {
		return err
	}
	if len(env) == 0 {
		return badRequest("%s.env must not be empty", what)
	}
	seen := map[string]bool{}
	for _, e := range env {
		obj, err := asObject(e, what+".env[]")
		if err != nil {
			return err
		}
		if err := exactKeys(obj, []string{"var", "name"}, what+".env[]"); err != nil {
			return err
		}
		v, err := asPrintableASCII(obj["var"], what+".env[].var", 1, 128)
		if err != nil {
			return err
		}
		if !envVarPattern.MatchString(v) {
			return badRequest("%s.env[].var is not an environment variable name", what)
		}
		if _, err := asItemName(obj["name"], what+".env[].name"); err != nil {
			return err
		}
		if seen[v] {
			return badRequest("%s.env names a variable twice", what)
		}
		seen[v] = true
	}
	if p, ok := args["cwd_project"]; ok {
		if _, err := asProfileText(p, what+".cwd_project", 128); err != nil {
			return err
		}
	}
	return optionalInt(args, "timeout_s", what, 1, 110)
}

// ValidateToolResult checks the result object of an ok:true result frame
// against the exact keys of its tool. Every failure is bad_request. A result
// never carries a secret value.
func ValidateToolResult(tool string, result map[string]any) error {
	const what = "result"
	if result == nil {
		return badRequest("%s must be an object", what)
	}
	switch tool {
	case ToolSearch:
		if err := exactKeys(result, []string{"items"}, what); err != nil {
			return err
		}
		return validateResultEntries(result["items"], what+".items")
	case ToolList:
		if err := exactKeys(result, []string{"items"}, what, "next_cursor"); err != nil {
			return err
		}
		if err := validateResultEntries(result["items"], what+".items"); err != nil {
			return err
		}
		if c, ok := result["next_cursor"]; ok {
			if _, err := asUTF8Bytes(c, what+".next_cursor", 1, 256); err != nil {
				return err
			}
		}
		return nil
	case ToolDescribe:
		if err := exactKeys(result, []string{"name", "profile", "sensitivity"}, what, "created_at", "rotated_at", "last_device_label"); err != nil {
			return err
		}
		if _, err := asItemName(result["name"], what+".name"); err != nil {
			return err
		}
		if err := validateEntryProfile(result["profile"], what+".profile"); err != nil {
			return err
		}
		if _, err := asEnum(result["sensitivity"], sensitivities, what+".sensitivity"); err != nil {
			return err
		}
		for _, k := range []string{"created_at", "rotated_at"} {
			if err := optionalInt(result, k, what, 0, MaxSafeInteger); err != nil {
				return err
			}
		}
		if l, ok := result["last_device_label"]; ok {
			if _, err := asUTF8Bytes(l, what+".last_device_label", 0, MaxDeviceLabelBytes); err != nil {
				return err
			}
		}
		return nil
	case ToolSet:
		status, err := asEnum(result["status"], []string{"written", "conflict"}, what+".status")
		if err != nil {
			return err
		}
		if status == "conflict" {
			return exactKeys(result, []string{"status"}, what)
		}
		if err := exactKeys(result, []string{"status", "revision"}, what); err != nil {
			return err
		}
		_, err = asInt(result["revision"], what+".revision", 1, MaxSafeInteger)
		return err
	case ToolDelete:
		if err := exactKeys(result, []string{"status"}, what); err != nil {
			return err
		}
		_, err := asEnum(result["status"], []string{"deleted", "conflict", "not_found"}, what+".status")
		return err
	case ToolRequest:
		if err := exactKeys(result, []string{"status", "request_id"}, what); err != nil {
			return err
		}
		if _, err := asEnum(result["status"], []string{"pending", "granted", "denied"}, what+".status"); err != nil {
			return err
		}
		_, err := asUTF8Bytes(result["request_id"], what+".request_id", 1, 64)
		return err
	case ToolRun:
		if err := exactKeys(result, []string{"exit_code", "stdout", "stderr", "truncated"}, what); err != nil {
			return err
		}
		if _, err := asUint(result["exit_code"], what+".exit_code"); err != nil {
			return err
		}
		for _, k := range []string{"stdout", "stderr"} {
			if _, err := asWellFormedString(result[k], what+"."+k, MaxSafeInteger, 0); err != nil {
				return err
			}
		}
		_, err := asBool(result["truncated"], what+".truncated")
		return err
	default:
		return badRequest("%s: unknown tool", what)
	}
}

func validateResultEntries(v any, what string) error {
	items, err := asArray(v, what, maxToolResultItems)
	if err != nil {
		return err
	}
	for _, it := range items {
		entry, err := asObject(it, what+"[]")
		if err != nil {
			return err
		}
		if err := exactKeys(entry, []string{"name", "profile", "updated_at"}, what+"[]"); err != nil {
			return err
		}
		if _, err := asItemName(entry["name"], what+"[].name"); err != nil {
			return err
		}
		if err := validateEntryProfile(entry["profile"], what+"[].profile"); err != nil {
			return err
		}
		if _, err := asUint(entry["updated_at"], what+"[].updated_at"); err != nil {
			return err
		}
	}
	return nil
}

// validateEntryProfile checks a tool result profile: profile keys mapped to
// {value, origin}, each value under its key's profile rule.
func validateEntryProfile(v any, what string) error {
	obj, err := asObject(v, what)
	if err != nil {
		return err
	}
	for _, k := range sortedMapKeys(obj) {
		spec, ok := profileFields[k]
		if !ok {
			return badRequest("%s has an unknown key", what)
		}
		field, err := asObject(obj[k], what+"."+k)
		if err != nil {
			return err
		}
		if err := exactKeys(field, []string{"value", "origin"}, what+"."+k); err != nil {
			return err
		}
		if _, err := parseProfileValue(spec, field["value"], what+"."+k+".value"); err != nil {
			return err
		}
		if _, err := asEnum(field["origin"], entryOrigins, what+"."+k+".origin"); err != nil {
			return err
		}
	}
	return nil
}

// asWellFormedString is asString (UTF-16 code unit limits) on valid UTF-8.
func asWellFormedString(v any, what string, maxLen, minLen int) (string, error) {
	s, err := asString(v, what, maxLen, minLen)
	if err != nil {
		return "", err
	}
	if !utf8.ValidString(s) {
		return "", badRequest("%s is not well-formed text", what)
	}
	return s, nil
}

// asItemName requires an item name: 1..4096 UTF-16 code units of valid UTF-8.
func asItemName(v any, what string) (string, error) {
	return asWellFormedString(v, what, MaxItemNameLength, 1)
}

// asUTF8Bytes requires valid UTF-8 text of minBytes..maxBytes bytes.
func asUTF8Bytes(v any, what string, minBytes, maxBytes int) (string, error) {
	s, ok := v.(string)
	if !ok || !utf8.ValidString(s) || len(s) < minBytes || len(s) > maxBytes {
		return "", badRequest("%s must be %d..%d bytes of text", what, minBytes, maxBytes)
	}
	return s, nil
}

func optionalInt(obj map[string]any, key, what string, min, max int64) error {
	if v, ok := obj[key]; ok {
		_, err := asInt(v, what+"."+key, min, max)
		return err
	}
	return nil
}
