package akv1

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
)

// ValidateWrapsOptions configures ValidateWrapRecipients.
type ValidateWrapsOptions struct {
	// KeyEpoch, when non-zero, requires every wrap to be for exactly this epoch.
	KeyEpoch int64
	// RequireAll requires a wrap for every current device at KeyEpoch (or the
	// state's key epoch when KeyEpoch is zero).
	RequireAll bool
}

// ValidateWrapRecipients validates untrusted device wraps against verified
// membership (spec §4 "injected recipient"). Rejects: malformed wraps
// (bad_request / unsupported_version), a recipient that is not a current
// member device (forbidden), an epoch above state.KeyEpoch or different from
// opts.KeyEpoch (bad_request), duplicate (rcpt, key_epoch) pairs
// (bad_request), and missing recipients when RequireAll (bad_request).
// Older retained epochs are accepted for current members.
func ValidateWrapRecipients(state MembershipState, wraps []any, opts ValidateWrapsOptions) ([]X25519Wrap, error) {
	if len(wraps) > 100000 {
		return nil, badRequest("wraps must be an array of at most 100000 entries")
	}
	current := make(map[string]bool, len(state.Devices))
	for _, d := range state.Devices {
		current[d.DeviceID] = true
	}
	parsed := make([]X25519Wrap, 0, len(wraps))
	for i, raw := range wraps {
		w, err := parseX25519WrapAs(raw, "wraps["+strconv.Itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, w)
	}
	seen := make(map[string]bool, len(parsed))
	pairKey := func(rcpt string, epoch int64) string { return fmt.Sprintf("%s/%d", rcpt, epoch) }
	for _, w := range parsed {
		if !current[w.Rcpt] {
			return nil, newErr(CodeForbidden, "wrap recipient is not a current member device")
		}
		if w.KeyEpoch > state.KeyEpoch {
			return nil, badRequest("wrap key_epoch is ahead of the membership state")
		}
		if opts.KeyEpoch != 0 && w.KeyEpoch != opts.KeyEpoch {
			return nil, badRequest("wrap key_epoch mismatch")
		}
		k := pairKey(w.Rcpt, w.KeyEpoch)
		if seen[k] {
			return nil, badRequest("duplicate wrap for a recipient and epoch")
		}
		seen[k] = true
	}
	if opts.RequireAll {
		epoch := opts.KeyEpoch
		if epoch == 0 {
			epoch = state.KeyEpoch
		}
		for id := range current {
			if !seen[pairKey(id, epoch)] {
				return nil, badRequest("a current device has no wrap")
			}
		}
	}
	return parsed, nil
}

// WrapsDigest returns b64 sha256(cjson(wraps sorted by rcpt byte order, then
// key_epoch)), the wraps_digest of a rekey or device-adding event's wrap set. A
// rekey set has one epoch, so it is sorted by rcpt alone.
func WrapsDigest(wraps []X25519Wrap) (string, error) {
	sorted := append([]X25519Wrap(nil), wraps...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Rcpt != sorted[j].Rcpt {
			return sorted[i].Rcpt < sorted[j].Rcpt
		}
		return sorted[i].KeyEpoch < sorted[j].KeyEpoch
	})
	list := make([]any, len(sorted))
	for i, w := range sorted {
		list[i] = w.JSONValue()
	}
	b, err := CJSON(list)
	if err != nil {
		return "", err
	}
	return SHA256B64(b), nil
}

// SASInput is the SAS enrollment input (spec §3.5).
type SASInput struct {
	VaultID   string
	Initiator string // device ID of the enrolling owner device
	Joiner    any    // full device record of the joining device (DeviceRecord or object)
	NonceI    string // b64 of 16 random bytes from each side
	NonceJ    string
}

// SASTranscript returns cjson({ctx:"akv1/sas", vault_id, initiator, joiner, nonce_i, nonce_j}).
func SASTranscript(in SASInput) ([]byte, error) {
	if _, err := asID(in.VaultID, "vault_id"); err != nil {
		return nil, err
	}
	if _, err := asID(in.Initiator, "initiator"); err != nil {
		return nil, err
	}
	joiner, err := parseDeviceAs(in.Joiner, "joiner")
	if err != nil {
		return nil, err
	}
	if _, err := asB64(in.NonceI, "nonce_i", 16); err != nil {
		return nil, err
	}
	if _, err := asB64(in.NonceJ, "nonce_j", 16); err != nil {
		return nil, err
	}
	return CJSON(map[string]any{
		"ctx": "akv1/sas", "vault_id": in.VaultID, "initiator": in.Initiator,
		"joiner": joiner, "nonce_i": in.NonceI, "nonce_j": in.NonceJ,
	})
}

// SASCode returns the six-digit code both devices display:
// uint32be(sha256(transcript)[0:4]) mod 10^6, zero-padded.
func SASCode(in SASInput) (string, error) {
	t, err := SASTranscript(in)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(SHA256(t)[:4])%1_000_000), nil
}

// SASDigest returns b64(sha256(transcript)), the value of device_add.body.sas.
func SASDigest(in SASInput) (string, error) {
	t, err := SASTranscript(in)
	if err != nil {
		return "", err
	}
	return SHA256B64(t), nil
}
