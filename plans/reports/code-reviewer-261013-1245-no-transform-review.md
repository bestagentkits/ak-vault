# Review: no-transform on static asset responses (PR #15)

Scope: `worker/src/http/static-assets.ts`, `worker/test/public-endpoints.test.ts`, `docs/design-guidelines.md` (+14 LOC). Diff `origin/main...HEAD`, head 6fc37c9.

Evidence: `cd worker && npx vitest run test/public-endpoints.test.ts` -> 11/11 pass. No `.wrangler/` created; tree clean.

## Verdict

Correct and safely scoped. No blockers. One real trade-off (lost edge compression) is neither scoped down nor written down.

## Correctness checks

- **Header merge.** Reads the upstream `Cache-Control` and appends `, no-transform` only when it is missing. The regex is case-insensitive, matches only at directive boundaries and tolerates whitespace, so there are no duplicates. Existing directives (the assets default `public, max-age=0, must-revalidate`) are kept, so caching semantics do not change. `withSecurityHeaders` does not touch `Cache-Control`, so reading it from `response` instead of `out` is equivalent.
- **API paths unaffected.** `serveAsset` is only reached for `!isApiPath` (`worker/src/index.ts:45`), so `/healthz` and `/v1/*` keep `no-store`. The existing test still asserts that exact value.
- **307 `/security` -> `/security/`.** Adds `Cache-Control: no-transform` to the redirect. This is harmless: redirects are not cached any more or less than before.
- **304.** Same header on a not-modified response. It is valid and has no body, so the effect is nil. ETag revalidation still works.
- **404 page.** Gets `no-transform` too, which is wanted because the 404 page is HTML and would otherwise get the beacon. The test covers it.
- **Error path.** If `ASSETS.fetch` throws, behaviour is the same as before.

## Findings

### Medium: no-transform disables Cloudflare edge compression for every site asset

Cloudflare documents that origin `cache-control: no-transform` makes it skip compression, and Compression Rules cannot override that ([content compression](https://developers.cloudflare.com/speed/optimization/content/compression/)). Text assets now travel uncompressed:

| Asset | Size |
|---|---|
| `index.html` | 33.7 KB |
| `styles.css` | 31.2 KB |
| `security/index.html` | 20.1 KB |
| `index.md` | 8.6 KB |
| `security/index.md` | 5.5 KB |
| `site.js` | 4.4 KB |

A first visit to `/` costs about 70 KB instead of about 15-20 KB. Fonts (woff2) and PNGs are already compressed, so they don't matter. Repeat visits revalidate to 304, so the cost is mostly first-load bytes. For a small static site this is acceptable but not free.

Problems with the change as written:
- It is broader than needed. The beacon is only injected into HTML, but CSS, JS, Markdown and `llms.txt` lose compression for no benefit.
- The doc line states the benefit but not the cost. REVIEW.md says limitations should be stated alongside guarantees.

Fix options (pick one):
1. Apply `no-transform` only when the response `Content-Type` starts with `text/html`. This covers `/`, `/security/` and the 404 page, and keeps CSS/JS/MD compressed. Change the test to assert that HTML paths have the directive and `styles.css` does not.
2. Keep it blanket, and add a clause to the doc saying edge compression is intentionally disabled for site responses.
3. (Zone-level, outside the repo, complementary) Exclude `vault.agentkit.best` from automatic Web Analytics, either with a Configuration Rule that disables RUM or with a Web Analytics exclusion rule. That removes the injection at the source, and `no-transform` could then be narrowed or dropped. This needs zone access on a shared zone, so it is the lead's call.

### Low: other proxy features lost

Any HTML-rewriting or body-modifying feature is now suppressed for these responses: Rocket Loader, Email Obfuscation, Zaraz and other auto-injection, Mirage/Polish on `og.png`. None of these is wanted under the strict same-origin CSP, so this is a net positive and only worth mentioning in the PR. Security headers, TLS, HSTS, caching and Early Hints are unaffected.

### Low: test gaps

- The test checks that the directive is present but not that existing directives are kept. Add an assertion such as `max-age` or `must-revalidate` still present on `/`, so a future `set('Cache-Control','no-transform')` regression would be caught.
- The duplicate-avoidance branch of `withNoTransform` is not exercised. The assets binding never sends `no-transform`, so the branch is effectively dead today. It is acceptable as cheap defence, but either test it or simplify it.
- The 307 redirect is not in the path list. Optional.

### Low: post-deploy verification needed

The tests prove the header is set, not that Cloudflare honours it. After deploy, `curl -s https://vault.agentkit.best/ | grep -c beacon.min.js` should return 0, and response headers should show no `cf-` injected script. Record this as PR evidence.

## Checklist (REVIEW.md)

- No secrets or names in logs or errors: not applicable, nothing logged.
- Auth, data classification, kill switch, protocol and vectors: untouched.
- Docs point to the owner (`static-assets.ts`) rather than copying the value: yes. The limitation is missing (see Medium).

## Unresolved questions

- Is the zone owner willing to add a hostname-scoped RUM exclusion (option 3)? If so, `no-transform` could be narrowed to HTML or removed.
- Does Cloudflare's no-transform compression skip also cover Zstandard? The docs name Brotli and Gzip explicitly; assume yes until a live `curl -H 'Accept-Encoding: zstd'` check says otherwise.

Status: DONE_WITH_CONCERNS
Summary: Header merge is correct and safely scoped to non-API responses, including redirects, 304s and the 404 page. Blanket no-transform also disables Cloudflare compression for about 70 KB of text assets per first visit, which is broader than the HTML-only beacon threat and undocumented.
Blocking findings: none
