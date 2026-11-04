package akv1

import "testing"

func checkVaultTokenLifetime(t *testing.T, f *rec, n *counter) {
	if f.i64("short_max_seconds") != VaultTokenShortMaxSeconds {
		t.Errorf("short_max_seconds mismatch")
	}
	for _, c := range f.recs("lifetime") {
		if got := IsShortLivedVaultToken(c.i64("iat"), c.i64("exp")); got != c.boolean("short") {
			t.Errorf("%s: short = %v", c.path, got)
		}
		c.done()
		n.add(1)
	}
	for _, c := range f.recs("usable") {
		if got := ShortLivedVaultTokenUsable(c.i64("iat"), c.i64("exp"), c.i64("now")); got != c.boolean("usable") {
			t.Errorf("%s: usable = %v", c.path, got)
		}
		c.done()
		n.add(1)
	}
}
