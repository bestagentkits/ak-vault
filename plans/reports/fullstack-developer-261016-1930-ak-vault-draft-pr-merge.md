# ak-vault draft PR merge pass (2026-10-16, 19:26 to 20:35 Asia/Saigon)

Status: DONE_WITH_CONCERNS
Summary: #86, #89 and #96 were reviewed in isolated subagents and squash-merged with hand-written messages that carry no AI attribution. #92 was skipped because #93 superseded its design. Exactly one Deploy run, for the newest main commit, passed staging and is waiting for production approval. I did not approve it.

## Per-PR outcome

| PR | Outcome | Merge sha |
|---|---|---|
| #86 docs(landing): ADR 0001 accepted | Merged | `a8a9866580cf0345634a2d30040ba02ab67a9b3f` |
| #89 docs(ops): registry request-rate alert | Merged after a fix commit | `ea0270f6be65c3718e2d1584fcbee0d0f9783388` |
| #96 docs(security): api-key device recovery decision | Merged | `cf96405ef8a5e0a76e762ce6164fde73c6117438` |
| #92 feat(protocol): witnessed-position check | Skipped, left as draft; reason commented on the PR | none |

**#86.** Last commit was at 10:16Z, and no "working on it" comment existed. The isolated review confirmed both claims against the ADR and release-gates: the ADR was accepted on 2026-10-16 and restore reconciliation is still open. It also confirmed that the md and html twins match and that the protocol status stays "proposed, in security review". The only blocker was the commit's Co-Authored-By and Claude-Session trailers. The hand-written squash message removed them, and the body carried no attribution. I rebased the branch onto main, waited for green CI, and squash-merged.

**#89.** Last commit was at 10:34Z, and no comment existed. The isolated review found one blocker: release-gates said the ceiling was "roughly 10 checks a second" while the cost model and runbook used 8 to 10 and 8. It also used the self-contradicting phrase "lab measurement suggests ... derived, not measured".
- I fixed it in a focused commit, which was also rebased onto main and force-pushed with a lease. The commit aligns the ceiling with the cost model and states that the 503 `unauthorized` signal can also mean a JWKS failure.
- The same commit points the operator at Workers Logs and not `wrangler tail`. I verified against release-gates that `wrangler tail` exposes `AKV-Proof`.
- CI was green and I squash-merged.

**Shared-doc conflict with the lab-measurement work.** The lab PR #98 (dd6696d) merged after #89 from another session. On main I checked that #98 kept #89's runbook section, its anchor links and my Workers Logs and JWKS wording. #98 replaced the derived 8 to 10 ceiling with the measured knee of about 1,000 checks a second and a 500 checks a second alert threshold. No content from either side was dropped.

**#96.** At 12:26Z the last commit was 12 minutes old, so I waited until 13:15Z and confirmed the head was unchanged with no comments.
- The isolated review was told that #87 and #94 had landed since the PR was written. It found no blockers: #87's `requireHumanSession` covers only non-enrolled recovery fetch and enrollment, and `worker/test/recovery-fetch.test.ts` pins that an approved owner-role `api_key_device` still reads the bundle. So "refusal not implemented yet" is still true.
- I stripped the "Generated with Claude Code" line, the session links and the footer from the PR body, then rebased, waited for green CI and squash-merged with a hand-written message.

**#92 (skipped).** It became quiet at 12:54Z with no comments. #93, merged after #92 was cut, landed the protocol side of #76 differently:
- `verifyChangeLog` checks `keptHeads`, the spec requires a peer-checkpoint digest comparison, and the `restored_regrown_*` vectors cover the case.
- A rebase conflicts in 9 files, including spec §6, the TS and Go checkpoint docstrings, the vector generator and `checkpoints.json`. Each conflict pits #92's "also run `checkWitnessedHistory`" MUST against #93's kept-head MUST.
- Keeping both would put two normative mechanisms in the spec, and choosing between them is a design decision, not a blocker fix. I did not run `pnpm vectors`, typecheck, the tests or the Go tests, because a resolution of my own would be that design choice.
- My comment on #92 (https://github.com/bestagentkits/ak-vault/pull/92#issuecomment-6215959495) suggests either narrowing the helper to the peer-checkpoint digest comparison or closing #92 as superseded by #93.

## Deploy

Waiting run: https://github.com/bestagentkits/ak-vault/actions/runs/38906854487 (cf96405, the main head). Its gate and staging jobs succeeded, and production is waiting. I did not approve it.

The Deploy workflow uses `concurrency: group: deploy, cancel-in-progress: false`. The older run 38897647073 (9e9cc02), waiting for production approval, held the group. Newer runs could only sit pending, and each new one replaced the previous pending run. The newest could therefore not pass staging until the older waiting run was cleared. I cancelled 38897647073 first. My fallback, had the newest failed staging, was to re-run that cancelled run. It was not needed. The older pending runs for a8a9866, ea0270f and dd6696d were superseded automatically. No other Deploy run is waiting or queued.

## Cleanup

- I removed my worktrees (`merge-pr-86/89/92/96`), their local branches and the temporary PR refs.
- GitHub deleted the merged PR head branches automatically. I left #92's branch and an unrelated `claude/tender-franklin-iv8b02` alone.
- No `.wrangler/` or dependency install was created, and the scratch body file is deleted.

## Concerns

- The deploy cancel order deviated from the instruction, because the concurrency group made the requested order impossible. See Deploy above.
- #96 is pure documentation. The recovery refusal it describes still has to be implemented on #90.
- #89's GraphQL query has still not been run live, and that is still open on #65.
- Owner decision needed on #92: rework it as a peer-checkpoint digest helper, or close it as superseded by #93.
- I did not review #98, which another session merged mid-pass. I checked only that #89's content survived it.
