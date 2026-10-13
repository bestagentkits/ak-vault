# Journal: shipping the ak-vault bootstrap (2026-10-13)

## What shipped
Protocol v1 (TS + Go, cross-verified vectors), the sync Worker with a SQLite Durable Object per vault, and the landing page, live at https://vault.agentkit.best with the sync API switched off. Staging runs with sync on against a test-only issuer.

## What went wrong and what it taught us
- **Auto-merge refused while `main` was unprotected** ("unstable status"). A ruleset requiring the three CI checks fixed it and also made the "deploy only after green CI" rule enforceable. AGENTS.md now records the ruleset.
- **First production healthcheck failed on DNS** (`Could not resolve host`) because the custom domain was created by that same deploy. The Worker was healthy about two minutes later; re-running the failed job went green. A first deploy of a new hostname should expect propagation delay.
- **The zone's Web Analytics auto-install injected a beacon** into the landing HTML. CSP blocked it (no data left the page) but every load logged errors. Changing the zone would affect the main agentkit.best site, so the Worker now sends `Cache-Control: no-transform` on HTML. The isolated review caught that applying it to every asset also disables edge compression, so it was narrowed to HTML.
- **A rejected genesis used to leave storage behind.** The round-2 review found it; a storage-free genesis preflight now runs before the schema exists, with a mutation-checked test.
- **Browser checks in a hidden pane mislead.** With `visibilityState: hidden`, CSS transitions do not advance, so the hero looked blank (opacity 0) and preloaded fonts looked unused. Verify layout from a foreground tab or by computed state after the tab becomes visible.

## Still open
External cryptographic review, staging soak and rehearsals (#8); client-side work in agentkit#2298/#2299 (#6, #7); ak-web token issuer and revocation sender (ak-web#568); follow-ups #9, #13, #14. The bootstrap deploy exceptions expire before sync GA.
