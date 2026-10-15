package akv1

import (
	"fmt"
	"strconv"
)

// AddedDevices returns the devices an event adds: genesis and member_add
// devices, the device_add device; nil for every other type.
func AddedDevices(e MembershipEvent) ([]DeviceRecord, error) {
	what := e.Type + ".body"
	switch e.Type {
	case EventDeviceAdd:
		d, err := parseDeviceAs(e.Body["device"], what+".device")
		if err != nil {
			return nil, err
		}
		return []DeviceRecord{d}, nil
	case EventGenesis, EventMemberAdd:
		return parseDeviceList(e.Body["devices"], what+".devices")
	}
	return nil, nil
}

// VerifyDeviceWraps checks the wraps delivered with a device-adding event
// (genesis, device_add, member_add) against its signed wraps_digest (spec §4,
// §11). event must come from a verified chain (its signature is not re-checked
// here). A device MUST NOT use a vault key from a wrap that has not passed this
// check or VerifyRekeyWraps.
//
// Order: the event adds devices (bad_request); wraps parse (bad_request /
// unsupported_version); every rcpt is a device the event adds (forbidden); key
// epochs lie in 1..event.key_epoch and (rcpt, key_epoch) pairs are unique
// (bad_request); completeness (bad_request): every event, a recovery-authored
// device_add included, carries a wrap at event.key_epoch for every added
// device, so every device holds the key of the epoch it joined at (the audit
// verifier requires it, spec §7; older epochs are optional); finally WrapsDigest(wraps) ==
// body.wraps_digest (bad_request). Input order does not matter.
func VerifyDeviceWraps(event any, wraps []any) ([]X25519Wrap, error) {
	ev, err := parseMembershipEventAs(event, "membership event")
	if err != nil {
		return nil, err
	}
	devices, err := AddedDevices(ev)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, badRequest("event does not add devices")
	}
	added := make(map[string]bool, len(devices))
	for _, d := range devices {
		added[d.DeviceID] = true
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
	pairKey := func(rcpt string, epoch int64) string { return fmt.Sprintf("%s/%d", rcpt, epoch) }
	seen := make(map[string]bool, len(parsed))
	for _, w := range parsed {
		if !added[w.Rcpt] {
			return nil, newErr(CodeForbidden, "wrap recipient is not a device added by the event")
		}
		if w.KeyEpoch > ev.KeyEpoch {
			return nil, badRequest("wrap key_epoch is ahead of the event")
		}
		k := pairKey(w.Rcpt, w.KeyEpoch)
		if seen[k] {
			return nil, badRequest("duplicate wrap for a recipient and epoch")
		}
		seen[k] = true
	}
	for id := range added {
		if !seen[pairKey(id, ev.KeyEpoch)] {
			return nil, badRequest("wrap set is incomplete")
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
