package akv1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The vector harness loads every file in protocol/v1/vectors and dispatches
// it to a handler. Each JSON object is wrapped in a rec that records which
// keys were read; a key nobody read fails the test, so new vector fields or
// case types can never be skipped silently.

// vectorsDir resolves protocol/v1/vectors relative to this source file, so
// the test works from any working directory.
func vectorsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	dir := filepath.Join(filepath.Dir(file), "..", "..", "protocol", "v1", "vectors")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("vectors directory not found at %s: %v", dir, err)
	}
	return dir
}

// loadVectorJSON decodes a vector file into the package value model. Numbers
// that are integers in [0, 2^53-1] become int64; any other number (negative,
// fractional, too large) stays a json.Number, which every validator and the
// cjson encoder reject, mirroring how the TypeScript reference treats them.
func loadVectorJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	m, ok := convertNumbers(raw).(map[string]any)
	if !ok {
		t.Fatalf("%s: top level is not an object", path)
	}
	return m
}

func convertNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		s := x.String()
		if s != "" && strings.Trim(s, "0123456789") == "" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n <= MaxSafeInteger {
				return n
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = convertNumbers(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = convertNumbers(x[k])
		}
		return x
	default:
		return v
	}
}

// rec wraps a vector object and tracks which keys were read.
type rec struct {
	t    *testing.T
	path string
	m    map[string]any
	used map[string]bool
}

func newRec(t *testing.T, path string, v any) *rec {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected an object, got %T", path, v)
	}
	return &rec{t: t, path: path, m: m, used: map[string]bool{}}
}

func (r *rec) has(k string) bool {
	_, ok := r.m[k]
	if ok {
		r.used[k] = true
	}
	return ok
}

func (r *rec) raw(k string) any {
	r.t.Helper()
	v, ok := r.m[k]
	if !ok {
		r.t.Fatalf("%s: missing key %q", r.path, k)
	}
	r.used[k] = true
	return v
}

func (r *rec) str(k string) string {
	r.t.Helper()
	s, ok := r.raw(k).(string)
	if !ok {
		r.t.Fatalf("%s.%s: expected a string", r.path, k)
	}
	return s
}

func (r *rec) i64(k string) int64 {
	r.t.Helper()
	n, ok := r.raw(k).(int64)
	if !ok {
		r.t.Fatalf("%s.%s: expected an integer", r.path, k)
	}
	return n
}

func (r *rec) boolean(k string) bool {
	r.t.Helper()
	b, ok := r.raw(k).(bool)
	if !ok {
		r.t.Fatalf("%s.%s: expected a boolean", r.path, k)
	}
	return b
}

func (r *rec) b64(k string) []byte {
	r.t.Helper()
	b, err := B64Decode(r.str(k))
	if err != nil {
		r.t.Fatalf("%s.%s: %v", r.path, k, err)
	}
	return b
}

func (r *rec) list(k string) []any {
	r.t.Helper()
	l, ok := r.raw(k).([]any)
	if !ok {
		r.t.Fatalf("%s.%s: expected an array", r.path, k)
	}
	return l
}

func (r *rec) obj(k string) *rec { return newRec(r.t, r.path+"."+k, r.raw(k)) }

func (r *rec) recs(k string) []*rec {
	r.t.Helper()
	l := r.list(k)
	out := make([]*rec, len(l))
	for i, v := range l {
		out[i] = newRec(r.t, r.path+"."+k+"["+strconv.Itoa(i)+"]", v)
		if out[i].has("name") {
			out[i].path = r.path + "." + k + "[" + out[i].m["name"].(string) + "]"
		}
	}
	return out
}

// done fails the test for every key that no check consumed.
func (r *rec) done() {
	r.t.Helper()
	var unused []string
	for k := range r.m {
		if !r.used[k] {
			unused = append(unused, k)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		r.t.Errorf("%s: unhandled vector keys %v", r.path, unused)
	}
}

// eqJSON compares the canonical encodings of got and want.
func eqJSON(t *testing.T, what string, got, want any) {
	t.Helper()
	g, err := CJSON(got)
	if err != nil {
		t.Errorf("%s: cannot encode result: %v", what, err)
		return
	}
	w, err := CJSON(want)
	if err != nil {
		t.Errorf("%s: cannot encode expected value: %v", what, err)
		return
	}
	if !bytes.Equal(g, w) {
		t.Errorf("%s mismatch\n got: %s\nwant: %s", what, g, w)
	}
}

func eqStr(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s mismatch\n got: %q\nwant: %q", what, got, want)
	}
}

// mustOK takes a (value, error) pair and returns a checker that fails the test
// on error, so calls read mustOK(F(x))(t, what).
func mustOK[T any](v T, err error) func(t *testing.T, what string) T {
	return func(t *testing.T, what string) T {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", what, err)
		}
		return v
	}
}

// expectCode asserts err is an *Error with code (taken from c.expect_error).
func expectCode(t *testing.T, c *rec, err error) {
	t.Helper()
	want := c.str("expect_error")
	if err == nil {
		t.Errorf("%s: expected error %s, got success", c.path, want)
		return
	}
	if got := CodeOf(err); got != want {
		t.Errorf("%s: expected error %s, got %q (%v)", c.path, want, got, err)
	}
}

// counter tallies verified vector cases per file.
type counter struct{ n int }

func (c *counter) add(k int) { c.n += k }

// fileHandler checks one vector file; it must consume every top-level key.
type fileHandler func(t *testing.T, f *rec, n *counter)

var vectorHandlers = map[string]fileHandler{
	"canonical-json.json":   checkCanonicalJSON,
	"kid.json":              checkKid,
	"aead.json":             checkAEAD,
	"item.json":             checkItem,
	"wrap-x25519.json":      checkWrapX25519,
	"wrap-password.json":    checkWrapPassword,
	"wrap-recovery.json":    checkWrapRecovery,
	"membership.json":       checkMembership,
	"records.json":          checkRecords,
	"checkpoints.json":      checkCheckpoints,
	"audit.json":            checkAudit,
	"policy.json":           checkPolicy,
	"policy-binding.json":   checkPolicyBinding,
	"proof.json":            checkProof,
	"recovery-bundle.json":  checkRecoveryBundle,
	"rekey-wraps.json":      checkRekeyWraps,
	"device-add-wraps.json": checkDeviceAddWraps,
	"removal-fence.json":    checkRemovalFence,
	"edge-cases.json":       checkEdgeCases,
}

// TestVectors verifies every vector file; an unknown file fails the test.
func TestVectors(t *testing.T) {
	dir := vectorsDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		seen++
		handler, ok := vectorHandlers[name]
		if !ok {
			t.Errorf("vector file %s has no Go handler", name)
			continue
		}
		n := &counter{}
		t.Run(name, func(t *testing.T) {
			f := newRec(t, name, loadVectorJSON(t, filepath.Join(dir, name)))
			if f.i64("version") != 1 {
				t.Fatalf("%s: unsupported vector version", name)
			}
			f.str("description")
			handler(t, f, n)
			f.done()
			if n.n == 0 {
				t.Errorf("%s: no cases verified", name)
			}
			t.Logf("%s: %d cases verified", name, n.n)
		})
		total += n.n
	}
	if seen != len(vectorHandlers) {
		t.Errorf("found %d vector files, %d handlers registered", seen, len(vectorHandlers))
	}
	t.Logf("total vector cases verified: %d across %d files", total, seen)
}
