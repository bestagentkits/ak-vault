# Review: sidecar self-heal (agentkit 55e8263f6, PR #2323)

Scope: commit 55e8263f6 only. Files: `apps/cli/internal/runtime/secrets/{index_sequence_sidecar.go, store_synced_writes.go, index_seq_test.go}` (+181/-50). Isolated reviewer, no implementation history.

## Evidence

- `cd apps/cli && go test -race -count=1 ./internal/runtime/secrets/...` at 55e8263f6: `ok ... 52.868s`.
- Mutation runs on a scratch `git archive` copy (worktree untouched, scratch deleted):

| Mutation | Result |
|---|---|
| Revert both prod files to parent | build fails (`RegenerationPending` undefined), so trivially red |
| M1 drop generation-mismatch clause in `regenerate` | FAIL `TestSidecarFromAnotherGeneration...` (caught) |
| M2 drop "no generation => missing" (`:73`) | **all pass** |
| M3 exhaustion back to `== MaxInt64` (`:165`) | **all pass** |
| M4 `RegenerationPending: false` | FAIL 2 tests (caught) |
| M5 regenerate ignores `mark.Seq` | FAIL (caught; pins max(index, foreign sidecar)) |
| M6 write index.json **before** the sidecar in `commitIndex` | **all pass** |

- Scratch probes (not committed):
  - Two `Store`s on the same path, 40 concurrent Sets over a corrupt sidecar, `-race`: one new generation, seq = before+40, no dup seqs. Cross-process lock (`lockhome.AcquirePath`) covers load+nextSeq+commit; IndexSnapshot also takes it. OK.
  - Crash after sidecar on a legacy index's first write (`{"generation":"G","seq":1}`, index without generation): next Set adopts G, seq 2. No rollback. OK.
  - Simulated crash mid-heal (sidecar `{G2, s+1}`, index still `{G1, s}`): next Set takes G3 at s+2. OK.
  - Sidecar `{"generation":<same or other>,"seq":9223372036854775806}`: **Set and Delete both fail** with `index sequence is exhausted: index file is corrupt`.
- `fsutil.WriteFileAtomicDurable` fsyncs temp + parent dir, so the sidecar-then-index order holds across power loss.

## BLOCKER

None.

## SHOULD-FIX

1. **A sidecar can still block Set/Delete when sync is off.** `index_sequence_sidecar.go:70` treats only `MaxInt64` as corrupt, but `:165` now refuses at `base >= MaxInt64-1`. A sidecar with seq `MaxInt64-1`, whether it is in the same generation or another one, parses as `present` and gets folded into `base` via `max(highestSeq, mark.Seq)`. Every write then returns ErrIndexCorrupt, and nothing heals it because a write is the only thing that heals. I reproduced this for both Set and Delete. The commit message says "a sidecar at the maximum is always damage", but the change only moved the poisoned value down by one. Since the mismatch branch also carries a foreign generation's seq forward (M5 shows the tests pin this), a sidecar that was "replaced from elsewhere" (the code comment names this case) can carry any near-max seq into index.json. Once it is there, the damage belongs to the index and the store is stuck for good. Writing a valid sidecar would normally take 2^63 writes, so in practice this needs a damaged or replaced file. It still breaks the stated invariant "Set/Delete never blocked by the sidecar".
   Fix: classify `mark.Seq >= math.MaxInt64-1` as `sidecarCorrupt` at `:70`, so the bound matches `nextSeq`. Then add an `"at the exhaustion bound"` case (`9223372036854775806`) to `TestCorruptSidecarHealsOnTheNextWrite`. Optionally, on a generation mismatch, do not trust a foreign `mark.Seq` beyond the index. A new generation already makes seq reuse safe, and this also matches the comment at `:110` ("rebuilt from index.json alone").

2. **The crash-ordering invariant is not tested.** Mutation M6 swaps `commitIndex` (`:181`) to write index.json first, and every test stays green. That order is the core property ("sidecar written before index.json", "a crash mid-heal must not let seq roll back"). `TestSidecarFromAnotherGeneration...` only hand-builds the after-crash state; it never checks that commitIndex produces that state. Add a fault-injection test: make the index write fail after the sidecar write succeeds (for example, a package-level `saveIndex` hook in the test or a read-only parent for the index temp only). Then assert that the sidecar holds the new generation/seq, the index is unchanged, and the next write goes above both.

## NIT

3. `index_sequence_sidecar.go:73` (no-generation sidecar treated as missing) is not tested on its own (M2 survives). When the index has a generation, the new mismatch clause already covers it. When the index has none, it decides whether `{"seq":50}` is discarded (my probe: the new generation starts at seq 1). Add one test for the legacy-index case so the intended behavior is pinned down.
4. M3 survives: no test hits the new `>= MaxInt64-1` bound. This is covered by the test in item 1.
5. `index_sequence_sidecar.go:110` comment says the mark is "rebuilt from index.json alone". On a generation mismatch, the code keeps `mark.Seq` (`:164`). Either the comment or the code is wrong (see item 1).
6. `store_synced_writes.go:79` says RegenerationPending covers an "unreadable" sidecar. An I/O read error still makes IndexSnapshot return an error (correct fail-closed, `TestUnreadableSidecarStillFailsClosed`). "Unreadable" here means "unparseable". Also, a legacy index with no generation plus a missing sidecar reports `false`, even though the next write assigns a generation. That is acceptable, but worth one clause in the comment.
7. The exhaustion error at `:166` says "index file is corrupt" even when the sidecar caused it, which misleads an operator. Moot if item 1 is fixed.

## Checked, no finding

- Fail-closed paths still hold: non-NotFound sidecar read errors propagate (`:63`), and `validateSequences` still rejects negative index seqs before the sidecar is read.
- A batch heal assigns one generation (`regenerate` is cleared on the first `nextSeq`). Expected-seq preconditions are all evaluated before `nextSeq` stamps entries (`store_synced_writes.go` ~296), and entry seqs survive a generation change, so ApplySynced CAS behaves the same across a heal.
- No file contents in errors. Errors carry only the path.
- Snapshot no longer refuses. No other non-test caller of `IndexSnapshot` exists in `apps/` or `tools/` that depended on the old ErrIndexCorrupt.

## Out of scope (pre-existing, not introduced here)

- `store.go` Set/Delete errors interpolate the ref name (`"secrets: set %s: ..."`, `"backend set %s"`). If ref names count as secret names under ak-vault's data classification, that needs its own issue.
- In `store.go` Set, the backend write happens before `commitIndex`. A crash between them changes a value without a seq bump, so sync readers cannot see it. Worth an `ai-handle` issue if not already tracked.

## Unresolved questions

- Should a foreign-generation sidecar's seq be trusted at all (tests currently require 21 from a foreign seq 20)? It is safe either way for monotonicity relative to the index. Trusting it is what lets item 1 spread into index.json.
