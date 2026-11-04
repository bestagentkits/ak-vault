package akv1

// ChangesHead is the head a GET /changes response carries (spec §5).
type ChangesHead struct {
	LogSeq         int64
	LogHead        string
	MembershipSeq  int64
	MembershipHead string
	KeyEpoch       int64
	RekeyRequired  bool
}

// ChangesHeadTag is b64url(sha256(cjson(head))) over the six head fields. A client
// sends it as if_head; the server answers 304 while the head still has that tag.
func ChangesHeadTag(h ChangesHead) (string, error) {
	b, err := CJSON(map[string]any{
		"log_seq":         h.LogSeq,
		"log_head":        h.LogHead,
		"membership_seq":  h.MembershipSeq,
		"membership_head": h.MembershipHead,
		"key_epoch":       h.KeyEpoch,
		"rekey_required":  h.RekeyRequired,
	})
	if err != nil {
		return "", err
	}
	return SHA256B64(b), nil
}
