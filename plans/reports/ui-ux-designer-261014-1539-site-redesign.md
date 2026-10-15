# Site redesign: vault.agentkit.best

The redesign is shipped to production. PR #33 was squash-merged as `ed6d02d`, Deploy run 38545442312 succeeded (gate, staging, production), and issue #32 is closed with the `shipped` label.

## What changed and why

The old site read as a spec dump. The new one tells a single story: a secret is sealed on your device, relayed as ciphertext, then verified and decrypted on the next device. Every guarantee is shown next to its limitation.

- **Direction:** "Sealed ledger in motion." It has a blueprint grid, numbered chapter marks, and a hero specimen whose ciphertext decodes once.
- **Color meaning:** verdigris means sealed or guarantee, amber means visible, limitation or in review, sky blue means planned, and coral means adversary.
- **Fonts:** unchanged and self-hosted (Bricolage, IBM Plex Sans, JetBrains Mono).
- **Visuals:**
  - an animated 4-step sync flow (keyboard operable, autoplays only while visible, paused under reduced motion);
  - a "device vs server" table for one secret;
  - a key hierarchy diagram;
  - SAS enrollment with a staggered digit reveal;
  - conflict lanes (compare-and-swap, `409` branch, resolve);
  - tombstone and checkpoint ratchets;
  - an architecture diagram;
  - a threat map with pins that link to adversary cards;
  - a release-gate checklist.
- **Micro-interactions:** button lift with arrow nudge, copy-icon swap announced through `aria-live`, a theme-toggle spin, the FAQ plus icon, and scroll reveals. The content is complete without JS.
- **Content truth:**
  - Available today: the local `ak secrets` commands.
  - `ak login` exists for the account; using it for sync is marked planned.
  - Planned and badged: `sync enable`, SAS enrollment, `search`, `describe`, `request` and `run`.
  - The install step links to agentkit.best (closed beta).
  - There are no metrics, dates, customers or pricing.
- **Security page:** it now carries the full set of paired limitations from the threat model, including:
  - audit entries are not signed per author;
  - roles are enforced only by the Worker (#22);
  - the removal fence binds positions, not contents (#21);
  - the recovery bundle can be guessed offline.

## Pages

| Page | Notes |
|---|---|
| `/` | Rewritten. Problem, flow, two views, promises with fine print, quick start, status track, FAQ teaser |
| `/how-it-works/` | New. Keys, enrollment, conflicts, deletes and rollback, architecture, data classification |
| `/security/` | Rebuilt. Scope, threat map, 7 adversary cards, guarantees and limitations, release gate, disclosure |
| `/guide/` | New. 4 parts; each step is badged available or planned; HowTo JSON-LD |
| `/faq/` | New. 23 questions in 6 groups; FAQPage JSON-LD |
| `/404.html` | New header, next cards, `noindex` |

Every indexable page has a Markdown twin (`index.md`). `llms.txt` and `sitemap.xml` (5 URLs) are updated, and `og.png` was re-rendered from the site styles (57 KB). `docs/design-guidelines.md` is rewritten. `worker/src` is untouched. The only change in `worker/test/public-endpoints.test.ts` is that its path lists now include the new pages.

## Screenshots

`docs/wireframes/` holds 6 compressed PNGs that replace the old 5:

- `home-1440-dark.png`
- `home-360-light.png`
- `how-it-works-1440-dark.png`
- `security-1440-light.png`
- `guide-768-dark.png`
- `faq-360-dark.png`

## Evidence

- **Tests:** `pnpm --filter ak-vault-worker test` passed 15 files and 129 tests. After the review fixes, `public-endpoints.test.ts` passed 12/12.
- **Typecheck:** `pnpm typecheck` passed for the protocol and worker packages.
- **Render check:** I served the site locally behind the production CSP and checked all 6 pages at 360, 768, 1024 and 1440 px in both themes.
  - No overflow, no CSP violations, no off-origin requests, and all 3 fonts loaded.
  - The only console error was the expected 404 status on the 404 page.
  - The only contrast flag was the hero's redacted value, which is intentional.
  - I re-ran the check after the review fixes and the results were the same.
- **Keyboard:** Tab reaches the stepper, and the arrow keys move and select a step (`aria-current="step"`). Selecting a step pauses autoplay (`aria-pressed=true`), and the focus outline is 2px solid.
- **Structure:** one h1 per page, no `style` attributes, no inline scripts other than JSON-LD (which parses), no duplicate ids, and every anchor resolves.
- **Review:** an isolated code reviewer, checking against REVIEW.md, found 0 blockers and 6 should-fix items. All 6 are fixed:
  - the paired limitations on the security page;
  - the tombstone wording;
  - the recovery bundle contents;
  - the prompt-injection limitation;
  - light-theme `badge-ok` contrast, using a new `--accent-text` token;
  - the claim that "all cryptography is in clients".

  Most of its nits are fixed too: conflict source order, SAS `role="img"`, the transcript wording, and an unsourced dashboard claim.
- **CI on PR #33:** TypeScript, Go cross-verification and the secret scan all passed.

## PR, merge, deploy

- **PR:** https://github.com/bestagentkits/ak-vault/pull/33, branch commits `a359919` and `c8635bc`.
- **Merge:** squash commit `ed6d02d995ab706f03a20f69a5e4853fc05e07c4` on `main`.
- **Deploy:** run 38545442312 passed the gate and staging. I approved production through the pending-deployments API under the bootstrap exception, and production succeeded.

## Live checks

- `/`, `/how-it-works/`, `/security/`, `/guide/` and `/faq/` return 200 `text/html`.
- The `.md` twins return 200 `text/markdown; charset=utf-8`, and `llms.txt` returns `text/plain`.
- `sitemap.xml` and `og.png` return 200. `/nope` returns 404, `/guide` redirects 307 to `/guide/`, and `/healthz` returns 200.
- Headers are intact:
  - `content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; …`
  - `cache-control … no-transform`
  - HSTS, `nosniff` and `referrer-policy`
- A headless render of live `/security/` showed 0 errors and no off-origin requests.

## Cleanup

- Stopped the static server on 4417.
- Removed the worktree `wt-site-redesign` and the local branch; the remote branch was already deleted at merge.
- Removed the scratch generators and screenshots.
- A `__pycache__` folder is left in the session scratchpad because a hook blocks deleting it. It is harmless.

Status: DONE_WITH_CONCERNS
Summary: The redesigned 5-page site, its Markdown twins, the refreshed SEO and agent surfaces, and the new design guidelines are live on vault.agentkit.best with the CSP intact. PR #33 was merged as ed6d02d, Deploy run 38545442312 succeeded, and #32 is shipped.
Concerns:
- I kept these review nits deliberately:
  - planned-command terminals keep their copy buttons, and the copied text includes the `# PLANNED` comment;
  - `site.js` reads `prefers-reduced-motion` only at load;
  - the hero headline "The server only sees ciphertext" is unchanged from main, with the visible-metadata callout and specimen directly below it.
- Contrast was measured by the render check plus the reviewer's axe run, not by a manual audit with assistive technology.

Unresolved questions: should the hero headline be softened to "stores only ciphertext and minimal metadata"?
