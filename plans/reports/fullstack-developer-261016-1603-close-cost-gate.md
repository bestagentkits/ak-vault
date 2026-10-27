# Close the staging cost gate (#50), plus the owner decisions from 16:09 and beta.31

Date: 2026-10-16, Asia/Saigon. Repo: bestagentkits/ak-vault.

## Outcome

Three PRs merged to `main` by squash auto-merge, all with green CI (TypeScript, Go cross-verification, secret scan):

| PR | Merge | Scope |
|---|---|---|
| [#79](https://github.com/bestagentkits/ak-vault/pull/79) | `02748f4` | The staging cost gate is ticked as met by owner decision on the lab-Worker method. `Closes #50`. |
| [#81](https://github.com/bestagentkits/ak-vault/pull/81) | `c6c35d2` | Records the owner's confirmation that Workers Tail access is restricted, and that the review gate becomes a review by the owner. `Refs #8`. |
| [#82](https://github.com/bestagentkits/ak-vault/pull/82) | `84f58f0` | agentkit `v3.0.0-beta.31` ships the removal-fence client, so the beta.30 wording is updated. `Refs #8`. |

The coordinator's follow-ups arrived after #79 had already merged, and then after #81 had merged. Each follow-up therefore went into a new PR instead of "the same PR".

## Cost gate (#79)

- **Gate entry in `release-gates.md`:** ticked as "measured on a lab Worker running the staging commit and configuration, accepted by the owner in place of staging".
  - It links the [decision](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212027109), the options and the evidence (#75 and the cost-model section).
  - It states that this is a lab measurement of the staging build, not of staging traffic: the lab used a synthetic issuer, and device counts and pull rates are still assumptions.
  - It records that the evidence is pinned to `b49865c`. `6851b0b` has since changed the request path, so the measurement must be re-run on the release commit before GA.
- **Open-items summary in `release-gates.md`:** updated to match.
- **`cost-model.md`:** the "reducing them" pointer moved from #50 to #63.
- **Landing security page:** it does not list the cost gate, so it is unchanged.
- **Comments:**
  - On #8: the decision is recorded.
  - On #50: closing note saying the zero-write work is not done and continues as #63 item 1.
  - On #63: cross-reference to #50.
- **Labels on #50:** assigned to me, then `in progress`, then `in review`, then `done`. #50 is closed. #63 stays open.
- **Owner's chat said "option A", but it described option (b).** In #8 comment 6211030336, (a) is the temporary issuer on staging and (b) is the lab Worker. The owner's described decision (lab Worker, no staging re-measurement) is (b). I recorded the decision by its content and noted the lettering discrepancy in the #8 comment.

## Owner decisions from 16:09 (#81)

- **Recorded on #8:** [comment 6212137235](https://github.com/bestagentkits/ak-vault/issues/8#issuecomment-6212137235).
- **Tail access:** recorded as confirmed by the owner, dated, in the release-gates summary, the disclosure-scan gate and data classification. It notes that agents did not inspect the account. #61 stays open.
- **Review gate:**
  - The release-gates section is renamed "Review by the owner" (anchor `#review-by-the-owner`). The box stays unticked.
  - The docs state that this is not an independent third-party review. The owner posts the result on #8 personally; agents never post, attest or tick it.
  - An owner-decisions row was added, and the threat model has a new limitation: "No independent third-party review".
  - AGENTS.md, the ADR (status header plus a dated change note), the spec status line, README, design guidelines and red-team evidence no longer promise an independent reviewer.
  - The landing pages (index, security, faq, guide, how-it-works, llms.txt) no longer promise one either. Each md/html pair was edited identically, and the security page gained the limitation bullet.
- **Isolated review:** the first pass found one blocker (the landing hero still said "independent security review") and three should-fix items. All were fixed, and the re-review came back DONE.

## beta.31 (#82)

- **Verified:**
  - `v3.0.0-beta.31` is a prerelease published 2026-10-16 08:31 UTC.
  - Compare `67ff8e6...v3.0.0-beta.31` returns `ahead`, so the fence commit is included; beta.30 is `behind`.
  - agentkit#2469 is closed.
  - The sync commands are still `Hidden: true` at the tag.
- **Updated:** release gates, threat model, design guidelines and the landing pages (index, guide, security, llms.txt).
- **Kept:** the limitation for clients up to beta.30. Nothing claims that beta.31 was run against production.
- **Isolated review:** its should-fix (the guide's recovery step) was applied.

## Evidence

- `pnpm typecheck`: green on each branch.
- `git diff --check`: clean.
- Relative link and anchor check over `docs/`, AGENTS.md and README: no broken links. The one hit, `cost-model.md#levers-63`, is a false positive of the checker's slug rule.
- CI green on all three PRs.

## Deploy runs

Each run is waiting for, or will wait for, the owner's production approval. None was approved by an agent.

- [38878676975](https://github.com/bestagentkits/ak-vault/actions/runs/38878676975) (`02748f4`): staging succeeded; production is waiting.
- [38879658524](https://github.com/bestagentkits/ak-vault/actions/runs/38879658524) (`c6c35d2`): pending.
- [38880189455](https://github.com/bestagentkits/ak-vault/actions/runs/38880189455) (`84f58f0`): pending.

## Cleanup

All three worktrees and their local and remote branches are removed. No dev servers were started.

## Follow-ups

- [#78](https://github.com/bestagentkits/ak-vault/issues/78) (`ai-handle`) was opened for unrelated drift:
  - the landing gate-list line about ADR open items;
  - the "roughly 10 checks a second" line versus 8 to 10 in the cost model.
- The comment in `worker/wrangler.jsonc` still says "ahead of the external review". It was left alone because the file is code-owned by the owner and the text is only a comment.

## Unresolved questions

- Is the owner fine with the "option A" wording being recorded as the lab-Worker option (b)?
- Should the owner update the code-owned comment in `worker/wrangler.jsonc`?
