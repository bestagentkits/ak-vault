package akv1

import "strconv"

// VerifyRekeyWraps checks a wrap set against a rekey event's signed
// wraps_digest (spec §4, §11 "Rekey wrap sets"). event must come from a
// verified chain (its signature is not re-checked here). state, when non-nil,
// is the verified membership state immediately after the event.
//
// Order: event is a rekey (bad_request); wraps parse (bad_request /
// unsupported_version); every wrap has key_epoch = new_key_epoch and a unique
// rcpt (bad_request); with state: state.seq/head equal the event (bad_request),
// recipients are current devices (forbidden), every current device has a wrap
// (bad_request); finally WrapsDigest(wraps) == body.wraps_digest (bad_request).
// Input order of the wraps does not matter.
func VerifyRekeyWraps(event any, wraps []any, state *MembershipState) ([]X25519Wrap, error) {
	ev, err := parseMembershipEventAs(event, "rekey event")
	if err != nil {
		return nil, err
	}
	if ev.Type != EventRekey {
		return nil, badRequest("event is not a rekey")
	}
	epoch, err := asInt(ev.Body["new_key_epoch"], "rekey.body.new_key_epoch", 1, MaxSafeInteger)
	if err != nil {
		return nil, err
	}
	if len(wraps) > 100000 {
		return nil, badRequest("wraps must be an array of at most 100000 entries")
	}
	parsed := make([]X25519Wrap, 0, len(wraps))
	for i, raw := range wraps {
		w, err := parseX25519WrapAs(raw, "wraps["+strconv.Itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, w)
	}
	rcpts := make(map[string]bool, len(parsed))
	for _, w := range parsed {
		if w.KeyEpoch != epoch {
			return nil, badRequest("wrap key_epoch differs from new_key_epoch")
		}
		if rcpts[w.Rcpt] {
			return nil, badRequest("duplicate wrap recipient")
		}
		rcpts[w.Rcpt] = true
	}
	if state != nil {
		head, err := MembershipEventHash(ev)
		if err != nil {
			return nil, err
		}
		if state.Seq != ev.Seq || state.Head != head {
			return nil, badRequest("membership state is not at the rekey event")
		}
		asValues := make([]any, len(parsed))
		for i, w := range parsed {
			asValues[i] = w.JSONValue()
		}
		if _, err := ValidateWrapRecipients(*state, asValues, ValidateWrapsOptions{KeyEpoch: epoch, RequireAll: true}); err != nil {
			return nil, err
		}
	}
	digest, err := WrapsDigest(parsed)
	if err != nil {
		return nil, err
	}
	if signed, ok := ev.Body["wraps_digest"].(string); !ok || signed != digest {
		return nil, badRequest("wrap set does not match the signed wraps_digest")
	}
	return parsed, nil
}
