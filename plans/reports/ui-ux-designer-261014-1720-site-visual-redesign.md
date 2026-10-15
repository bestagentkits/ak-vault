# Site visual redesign: vault.agentkit.best

The new light-first design is live on https://vault.agentkit.best.
- PR [#35](https://github.com/bestagentkits/ak-vault/pull/35) was squash-merged as `a94b1ba`.
- Deploy run `38557683274` passed the gate, staging and production; I approved production with the authorized API call.
- Issue [#34](https://github.com/bestagentkits/ak-vault/issues/34) is closed and labelled `shipped`.

## Visual system

- **Direction: light precision product.**
  - Whitespace and large Inter headlines replace bordered cards.
  - Surfaces use soft shadows and 1px translucent rings.
  - Heroes get a subtle mesh and a masked dot grid.
  - The header is sticky with backdrop blur.
  - Dark is a full secondary theme.
- **Color.**
  - Light: bg `#fcfcfd`, text `#0d1017`, indigo accent `#4f46e5`, sky link `#0369a1`, ok `#065f46`, warn `#974a00`, danger `#be123c`.
  - Dark: bg `#08090c`, accent `#a5b4fc`, link `#7dd3fc`.
  - Computed minimum contrast on all backgrounds is 5.49:1 in light and 6.25:1 in dark.
- **Type.** Inter 4.1 (wght and opsz axes) and Geist Mono 1.7.2.
  - Self-hosted latin and vietnamese woff2 subsets, about 116 KB total, with their OFL files.
  - Bricolage, Plex Sans and JetBrains Mono are removed.
- **Signature: the isometric hero stage.**
  - Device A seals a secret into a cube, the cube travels through the Worker (where a ledger row lands), and device B verifies it.
  - It is inline SVG with CSS keyframes on a 9s loop.
  - Without JS or under reduced motion it is static and complete.
  - It has a pause control and pauses itself while off screen.
- **Diagrams.** The sections are rebuilt around:
  - problem shards vs vault;
  - a segmented sync stepper (Arrow, Home and End keys) with a progress rail;
  - key hierarchy with dashed wires;
  - SAS devices (a container query);
  - conflict lanes;
  - ratchets;
  - architecture with moving link dots;
  - a threat-map zones-and-pins layout;
  - a release-gate checklist;
  - an FAQ with a sticky index.
- **Micro-interactions:** hover lift and spotlight, magnetic CTA, ripple, copy icon pop, a sun/moon toggle that cross-fades with a rotation, and staggered reveals.
- **Content:** the facts are unchanged and the headline is kept. Two captions now read "metadata *such as*". The Markdown twins and `llms.txt` were unchanged because no facts changed. `sitemap.xml` has no dates, so it was unchanged too.
- **Assets:** new `og.png` (1200×630, rendered from the site's CSS, fonts and static scene), `favicon.svg` (gradient cube) and `apple-touch-icon.png` (180px).
- **Docs:** `docs/design-guidelines.md` is rewritten, keeping its content rules and engineering constraints.

## Screenshots

`docs/wireframes/` at `a94b1ba` holds 6 PNGs, 1.1 MB total:
- `home-1440-light.png`
- `home-360-dark.png`
- `how-it-works-1440-dark.png`
- `security-1440-light.png`
- `guide-768-light.png`
- `faq-360-dark.png`

The "before" images are at `ed6d02d:docs/wireframes/`. The PR body has a before/after table.

## Evidence

All of this was run at the final head, before merge.

- **Playwright audit** against a local server with the production CSP: 6 pages × 360/768/1024/1440 × light and dark, 48 renders.
  - No overflow, no console or CSP errors, no external requests.
  - 0 raw `style=` attributes and 1 h1 per page.
  - Inter and Geist Mono loaded, and no target under 44px.
- **axe-core** (WCAG 2a, 2aa, 21aa plus best practice), 6 pages × 360/1440 × both themes: 0 violations.
- **Behaviour:**
  - Reduced motion: no animations and the pause control is hidden.
  - JavaScript off: all content visible.
  - Keyboard: the stepper and the pause control (`aria-pressed`) work.
  - Print: black text with the headline visible.
- **Tests:** `pnpm --filter ak-vault-worker test` passed 129 of 129 in 3 consecutive runs. One earlier run had a single failure that did not reproduce.
- **Types:** `pnpm typecheck` is clean.
- **CI on PR #35:** TypeScript, Go cross-verification and Secret scan all passed. CI on main for `a94b1ba` also passed.
- **Review:** I ran an isolated code-reviewer pass.
  - Round 1 found no blockers and 4 should-fixes: print hid the gradient headline, the conflict-lane actors were hidden from screen readers, the stored cube covered the ledger and the device B label was clipped, and the design doc had drifted from the code.
  - I fixed all four, plus the vault-key contrast, the caption wording, the dead selectors, the shard wrap and terminal print.
  - Round 2: DONE, nothing remaining.

## Live checks (production)

- **Status codes:** `/`, `/how-it-works/`, `/security/`, `/guide/`, `/faq/`, `/index.md`, `/llms.txt`, `/sitemap.xml`, `/og.png`, `/favicon.svg`, `/apple-touch-icon.png`, the fonts, `/styles.css` and `/site.js` all return 200. `/nope` returns 404 with "This page does not exist", and `/healthz` returns 200.
- **Headers:** the CSP is intact (`script-src 'self'; style-src 'self'; font-src 'self'; ...`), and HTML carries `Cache-Control: ... no-transform`.
- **CSS:** the live `styles.css` references Inter and Geist Mono and has no Bricolage. The home page serves `scene-svg`.
- **Live browser check** (Playwright on production, 5 pages × 360/1440 × both themes): no overflow, fonts loaded, no console errors and no external requests.

## Cleanup

- Stopped the static server on port 4418.
- Removed the worktree `wt-site-visual` and the local and remote `feat/site-visual-redesign` branches.
- Deleted the scratch build, tools and screenshots.

## Concerns

- **Flaky test:** one local test run showed a single failure that did not reproduce, and I did not capture its name. It touches no site code, since the static assets are the only change.
- **Not changed (reviewer nits):**
  - `site.js` reads reduced-motion once at load; CSS still stops the animations live.
  - At 360px the hero scene is small and decorative; the step list carries the text.
  - `theme-color` follows only the OS scheme. This was already the case before.
- **Hand-maintained chrome:** the shared header and footer are duplicated in all six HTML files. I assembled them with a scratch script that is not committed, because the project has no build step. Future edits must keep the six files in sync by hand.

Status: DONE
Summary: The light-first redesign shipped via PR #35 (`a94b1ba`) and Deploy run 38557683274. It is verified live (pages, CSP, new CSS, no external requests), and #34 is marked shipped.
Concerns: one non-reproducing test flake; minor reviewer nits left as documented.
