# ak-vault design guidelines

Design system for the static site at https://vault.agentkit.best (`worker/public/`).
The source of truth for token values is `worker/public/styles.css` and for behavior
`worker/public/site.js`; this file explains intent and rules. Screenshots live in
`docs/wireframes/`.

## Art direction

"Sealed ledger in motion": a precise, blueprint-like technical surface that tells one story,
plaintext becoming ciphertext and back, and is honest about what stays visible. It is
dark-first, with a warm "paper" light theme. Motifs:

- A faint measurement grid and a soft verdigris glow sit behind heroes and diagrams.
- Numbered chapter marks (`01 The problem`, `02 How sync works`, …) turn each page into a sequence.
- Monospace labels act as ledger annotations (chapter marks, `spec §n` refs, data tags).
- The signature moment is the hero "specimen": the same secret as device plaintext and as
  server ciphertext, with the illustrative base64 decoding in once.
- Status is always visible. A status badge sits on every page hero, and a callout states
  that sync is not generally available.

The brand ties to AgentKit (agentkit.best: near-black base, sky blue, coral). ak-vault gets
its own identity through a verdigris "seal" accent. AgentKit's sky blue is kept for links and
"planned", and its coral (lightened) marks threats.

## Pages

| Path | Role | Twin |
|---|---|---|
| `/` | The story: problem, sync flow, two views of one secret, promises with fine print, quick start, status, top questions | `index.md` |
| `/how-it-works/` | Deep dive with diagrams: keys, SAS enrollment, conflicts, tombstones and checkpoints, architecture, data classification | `how-it-works/index.md` |
| `/security/` | Threat map, adversary cards, guarantees and limitations, release gate, disclosure | `security/index.md` |
| `/guide/` | Step-by-step guide; available and planned steps are badged | `guide/index.md` |
| `/faq/` | Grouped FAQ with native `<details>` and FAQPage JSON-LD | `faq/index.md` |
| `/404.html` | Not-found page, `noindex` | none |

Every page shares the same header (How it works, Security, Guide, FAQ, GitHub, theme toggle;
a `details` menu below 64rem), footer, agent strip and `aria-current="page"` on its own links.
A new page needs a Markdown twin, a `sitemap.xml` entry, an `llms.txt` entry and nav links.

## Content rules (non-negotiable)

- Do not invent metrics, customers, testimonials, pricing, dates or benchmarks. The
  "about a minute" sync figure is always called a design target.
- Mark every unreleased command as **planned** (blue `badge-planned`, `# PLANNED` comment in
  terminals). Available today in the AgentKit CLI: the local `ak secrets` vault (`set`, `get`,
  `list`, `rotate`, `import-env`, `grant`, `grants`, `approve`, `revoke`, `audit`) and
  `${secret:NAME}` references. `ak login` exists for the AgentKit account; using it for sync is
  planned. Planned: `ak secrets sync enable`, SAS device enrollment, and
  `ak secrets search|describe|request|run`. AgentKit is in closed beta, so the site links to
  agentkit.best instead of printing an install command.
- Call guarantees "design properties of protocol v1 as proposed" until issue #8 signs off.
- Every guarantee sits next to its limitation: the vault-wide key, withheld updates (freeze
  attack), plaintext released to the child process on `run`, no claw-back, and visible metadata.
- Every edit to a page updates its Markdown twin and, if facts change, `llms.txt`.

## Typography

All fonts are self-hosted from `worker/public/fonts/` as woff2 variable fonts with
`latin` and `vietnamese` subsets. The site makes no third-party requests.

| Role | Family | Weights | Use |
|---|---|---|---|
| Display | Bricolage Grotesque | 650–750 | h1–h3, brand wordmark |
| Body | IBM Plex Sans | 400–600 | paragraphs, UI |
| Mono | JetBrains Mono | 400–600 | code, chapter marks, badges, data labels |

The type scale is fluid, using `clamp()`, from `--step--1` (13–14px) to `--step-4` (36–68px).
Body text uses line-height 1.6 and headings 1.08. Headings use negative tracking and
`text-wrap: balance`. Inline code inside h1/h2 is scaled to 0.78em.

## Color tokens

| Token | Dark (default) | Light | Role |
|---|---|---|---|
| `--bg` | `#07090c` | `#f5f3ec` | page |
| `--surface` / `--surface-2` | `#10161d` / `#151d26` | `#fffefb` / `#f3f0e7` | cards, code chips |
| `--line` / `--line-strong` | `#222d39` / `#34424f` | `#dcd6c8` / `#bfb7a5` | borders |
| `--text` | `#e9eef2` | `#12171d` | primary text |
| `--text-muted` | `#9aa8b5` | `#4b5661` | secondary text |
| `--text-faint` | `#808d9a` | `#616c77` | labels, captions |
| `--accent` | `#5fe3c0` | `#0a7a60` | seal / encrypted / guarantee / primary CTA |
| `--link` | `#8cc4ee` | `#24598a` | links, "planned" |
| `--warn` | `#f2b544` | `#8a5600` | status, limitations, visible metadata, residual risk |
| `--danger` | `#ff8b78` | `#ad3420` | threats on the security page |

Derived tokens (`--accent-line`, `--warn-line`, `--link-line`, `--link-wash`) are
`color-mix()` blends for borders and washes. Semantic mapping: **accent = sealed / guarantee**,
**warn = visible / limitation / in review**, **link = planned**, **danger = adversary**,
**neutral = never sent**. Keep this mapping consistent across pages and diagrams.

Contrast: every text token is at least 4.5:1 on `bg`, `surface` and `surface-2` in both
themes. Small accent text on a tinted wash (`badge-ok`, `vis-enc`) uses `--accent-text`, which
is the darker `#075c48` in light, because `#0a7a60` on a wash falls below 4.5:1. Accent text
inside diagram events sits on `--surface`, not `--bg-elev`, for the same reason.
Inactive diagram steps are never dimmed with opacity; only the active step is highlighted.

## Spacing, layout, shape

- Spacing: `--space-1…9`; sections use `--section-pad` (fluid 64–128px) and a 1px `--line` top border.
- Container: 72rem max width, fluid gutter of 16–32px.
- Grids always use `minmax(0, 1fr)` columns so code blocks cannot force horizontal scroll.
- Radii: 6px (controls), 10px (buttons, callouts, panels), 16px (cards, diagrams).
- Breakpoints, mobile-first: 48rem (two columns, tables unstack), 52–56rem (gate, threats,
  threat map), 62rem (split layout with a sticky diagram), 64rem (full nav, horizontal flow and status track).

## Components

- **Chapter**: `.chapter` with `.chapter-mark` (`<b>01</b>Label`), h2 and intro paragraph.
- **Badge**: mono pill. `badge-review` (amber, pulsing dot), `badge-planned` (blue), `badge-ok` (accent).
- **Buttons**: `btn-primary` and `btn-ghost`, at least 44px tall; hover lifts 1px and the arrow icon (`svg.nudge`) slides.
- **Callout**: icon plus text; amber by default, `is-info` for neutral notes. Use `role="note"`.
- **Specimen**: two-pane hero figure (plaintext, ciphertext) labelled "illustrative"; `[data-scramble]` spans decode once.
- **Problem panels**: scattered plaintext "shards" (before) beside a vault list (after).
- **Sync flow** (`figure[data-flow]`): four `li` nodes with icons, chips and connector packets.
  Vertical on mobile, horizontal at 64rem. Controls are `hidden` until JS runs.
- **Views table**: device vs server for one secret, with `vis-enc`, `vis-meta`, `vis-never` tags and a legend.
- **Pairs**: each guarantee rendered beside its limitation in one row.
- **Steps**: numbered vertical timeline (`ol.steps`); `li.is-planned` turns the counter blue.
- **Quick cards** and **terminal**: copy button with icon swap; `.p` prompts are excluded from copied text.
- **Status track**: `is-done`, `is-now`, `is-next` items with issue links; never dates.
- **Diagrams** (`.diagram`): key hierarchy (`.keys`), SAS enrollment (`.sas`), conflict lanes
  (`.lanes`), tombstone and checkpoint ratchets (`.ratchet`), architecture (`.arch`), threat map
  (`.tmap` zones with numbered `.pin` links to `.threat:target` cards).
- **Release gate**: `ul.gate` of open checkboxes; they stay open until evidence is on #8.
- **FAQ**: native `<details>`; groups (`.faq-group`) on `/faq/`, with a rotating plus icon.
- **Next cards**: "keep reading" links at the end of every deep page.
- **Agent strip**: "Copy page as Markdown" (same-origin fetch of the twin), "Open in ChatGPT", "Open in Claude".

## Motion

- Hero elements fade up on load (600ms, `--ease-out`, 60ms stagger). Other `.reveal` blocks
  fade up once when scrolled into view. Content is visible without JS: only `.js .reveal` is hidden,
  and `beforeprint` reveals everything.
- Sync flow: autoplays every 2.6s only while at least 35% visible; a packet travels along the
  connector into the active node.
- SAS digits reveal with a stagger when the diagram enters view.
- Micro-interactions: 140ms color and border transitions, button lift, theme-toggle spin, copy icon swap.
- `prefers-reduced-motion: reduce` collapses every animation and transition to its end state
  (reveals, pulse, packets, SAS stagger), disables smooth scroll and the ciphertext scramble,
  and the flow starts paused.

## Accessibility rules

- Landmarks: skip link, `header`, `nav[aria-label]`, `main#main`, `footer`. Each section is
  `aria-labelledby` its heading; one `h1` per page.
- Focus: 2px accent outline with 3px offset on `:focus-visible`. Never remove it.
- Touch targets are at least 44×44px for nav, menu, toggle, FAQ summaries, buttons, pins and
  footer links. Inline links inside prose are exempt.
- Flow stepper keyboard contract: step buttons carry `aria-current="step"`; Arrow keys move
  between steps and select; selecting a step pauses autoplay; the play button uses
  `aria-pressed` and a dynamic `aria-label`.
- Diagrams are `figure`s with a `figcaption`; meaning is always also carried by text, never by color alone.
- Theme toggle has a dynamic `aria-label`; copy results and theme changes are announced through
  `#live-region` (`aria-live="polite"`).
- External links opening a new tab carry hidden "(opens in a new tab)" text.
- The theme follows `prefers-color-scheme`; an explicit choice is stored under `akv-theme` and
  applied before first paint by the synchronous `site.js`.

## Engineering constraints

- Pure static HTML, one CSS file (`styles.css`) and one small vanilla JS file (`site.js`).
  No frameworks, no build step, no external JS, fonts or analytics. HTML responses carry
  `Cache-Control: no-transform` (`worker/src/http/static-assets.ts`) so the zone's automatic
  analytics beacon is never injected; CSS, JS and Markdown stay compressible.
- CSP (`worker/src/http/responses.ts`) has `script-src 'self'` and `style-src 'self'`: no inline
  executable scripts (JSON-LD only) and no `style` attributes.
- `/v1/*`, `/healthz` and `/internal/*` belong to the Worker. Never put static files under those paths.
- AX and SEO surfaces: canonical URL, OG and Twitter meta, `og.png` (1200×630, rendered from the
  site styles), `favicon.svg`, `apple-touch-icon.png`, `robots.txt`, `sitemap.xml`, `llms.txt`,
  Markdown twins and JSON-LD (WebSite, Organization, SoftwareApplication on `/`; TechArticle or
  HowTo plus BreadcrumbList on deep pages; FAQPage on `/faq/`).

## Verification checklist

Serve `worker/public` on a fixed port behind the production CSP. Check every page at 360, 768,
1024 and 1440px in both themes, confirming:

- no horizontal overflow
- no console errors or CSP violations
- no requests outside the origin
- all three font families loaded
- the flow stepper works with the keyboard alone

Run `pnpm --filter ak-vault-worker test`. Keep at most 6 compressed screenshots in `docs/wireframes/`.
