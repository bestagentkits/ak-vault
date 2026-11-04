package akv1

import "testing"

func checkChangesHeadTag(t *testing.T, f *rec, n *counter) {
	for _, c := range f.recs("cases") {
		h := c.obj("head")
		tag, err := ChangesHeadTag(ChangesHead{
			LogSeq: h.i64("log_seq"), LogHead: h.str("log_head"),
			MembershipSeq: h.i64("membership_seq"), MembershipHead: h.str("membership_head"),
			KeyEpoch: h.i64("key_epoch"), RekeyRequired: h.boolean("rekey_required"),
		})
		h.done()
		if err != nil || tag != c.str("tag") {
			t.Errorf("%s: tag = %q, %v", c.path, tag, err)
		}
		c.done()
		n.add(1)
	}
}
