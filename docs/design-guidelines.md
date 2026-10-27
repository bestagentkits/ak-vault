# ak-vault design guidelines

Design system for the static site at https://vault.agentkit.best (`worker/public/`).
Token values live in `worker/public/styles.css` and behavior in `worker/public/site.js`;
this file explains intent and rules. Screenshots live in `docs/wireframes/`.

## Art direction

"Light precision product": a bright, quiet surface in the spirit of modern developer-tool
sites, where whitespace, large confident type and one well-made illustration carry the page
instead of borders. It is light-first, with an equally polished dark theme.

- **Signature element:** the home-page stage, an isometric scene in which device A seals a
  secret into a cube, the cube travels through the Worker (a stack of three slabs with a
  ciphertext ledger) and device B verifies and opens it. It is inline SVG animated by CSS
  keyframes only.
- **Surfaces:** soft layered shadows and 1px translucent rings (`box-shadow: 0 0 0 1px
  var(--ring)`) instead of hard borders. Alternate sections tint to `--bg-2`.
- **Atmosphere:** heroes carry a subtle radial mesh (`--mesh-1..3`) and a masked dot grid. Use
  no other decoration.
- **Gradient text:** reserve it for one phrase per hero (`.grad`, indigo to sky).
- **Status is always visible.** A badge on every page hero states it, and a callout says that
  sync is not generally available.

The brand ties to AgentKit through its sky-blue link color. ak-vault's own accent is indigo,
the color of the "sealed" state.

## Pages

| Path | Role | Twin |
|---|---|---|
| `/` | The story: hero stage, problem, sync stepper, two views of one secret, promises with fine print, quick start, status, top questions | `index.md` |
| `/how-it-works/` | Deep dive with diagrams: keys, SAS enrollment, conflicts, tombstones and checkpoints, architecture, data classification | `how-it-works/index.md` |
| `/security/` | Threat map, adversary cards, guarantees and limitations, release gate, disclosure | `security/index.md` |
| `/guide/` | Step-by-step guide; available, preview and planned steps are badged | `guide/index.md` |
| `/faq/` | Grouped FAQ with a sticky group index on desktop, native `<details>` and FAQPage JSON-LD | `faq/index.md` |
| `/404.html` | Not-found page, `noindex` | none |

**Shared chrome:**
- Every page has the same sticky translucent header (How it works, Security, Guide, FAQ,
  GitHub, theme toggle; a `details` menu below 60rem).
- Every page has the same footer, and every page except the 404 has the agent strip.
- Each page marks its own links with `aria-current="page"`.
- Header and footer markup is duplicated in each HTML file, so edit all six together.

**Adding a page:** it needs a Markdown twin, a `sitemap.xml` entry, an `llms.txt` entry and nav
links.

## Content rules (non-negotiable)

- **No invented facts.** Do not invent metrics, customers, testimonials, logos, pricing, dates
  or benchmarks. Always call the "about a minute" sync figure a design target.
- **Mark every command that is not a supported release.** Unreleased commands are *planned*
  (blue `badge-planned`, `# PLANNED` comment in terminals). Commands that ship hidden in a
  released CLI but are not a supported workflow are *preview*: the same blue
  `badge-planned` / `li.is-planned` styling with the label "preview" and a `# PREVIEW`
  comment. Reusing the planned style is intentional; the label carries the difference.
  - Available today in the AgentKit CLI: the local `ak secrets` vault (`set`, `get`, `list`,
    `rotate`, `import-env`, `grant`, `grants`, `approve`, `revoke`, `audit`) and
    `${secret:NAME}` references.
  - `ak login` exists for the AgentKit account; the preview sync commands use it.
  - Preview (hidden in `v3.0.0-beta.31`): `ak secrets sync enable`, SAS device enrollment,
    device removal and recovery, against the production sync API, which is live before
    the review. Say so wherever they appear.
  - Planned: `ak secrets search|describe|request|run`.
  - AgentKit is in closed beta, so the site links to agentkit.best instead of printing an
    install command.
- **Call guarantees "design properties of protocol v1 as proposed"** until every gate in issue #8 is met.
- **Every guarantee sits next to its limitation:** the vault-wide key, withheld updates (freeze
  attack), plaintext released to the child process on `run`, no claw-back, and visible
  metadata.
- **Keep the hero headline** "The server only sees ciphertext". The owner chose it.
- **Keep the twins in step.** Every edit to a page updates its Markdown twin and, if facts
  change, `llms.txt`.

## Typography

All fonts are self-hosted from `worker/public/fonts/` as variable woff2 files with `latin` and
`vietnamese` subsets. They were subset from the official releases (rsms/inter 4.1,
vercel/geist-font 1.7.2), and their OFL licenses ship next to them. The site makes no
third-party requests.

| Role | Family | Use |
|---|---|---|
| Sans | Inter Variable (wght and opsz) | headings, body, UI |
| Mono | Geist Mono Variable | code, terminals, ledger and data labels, `spec §n` refs |

- **Scale:** `--fs-xs` (13px) to `--fs-3xl` (fluid, 38–80px), set with `clamp()`. Use
  `--fs-3xl` only for the home h1; page heroes use their own clamp up to 68px.
- **Headings:** weight 650–720, line-height around 1.02–1.1, negative tracking (−0.02 to
  −0.045em) and `text-wrap: balance`.
- **Body:** line-height 1.6, with ledes at `--fs-xl`.
- **Inline code in h1 and h2** is scaled to 0.8em with a tight 0.2em pad.

## Color tokens

| Token | Light (default) | Dark | Role |
|---|---|---|---|
| `--bg` / `--bg-2` | `#fcfcfd` / `#f5f6f8` | `#08090c` / `#0c0e13` | page, alternate sections |
| `--surface` | `#ffffff` | `#111319` | cards, diagrams |
| `--ring` / `--ring-strong` | slate at 8% / 16% | white at 8% / 16% | hairlines and outlines |
| `--text` | `#0d1017` | `#eef0f4` | primary text |
| `--text-2` | `#454c5a` | `#aab1bf` | secondary text |
| `--text-3` | `#5d6473` | `#8f96a5` | labels, captions |
| `--accent` | `#4f46e5` | `#a5b4fc` | sealed, encrypted, guarantee, focus ring |
| `--link` | `#0369a1` | `#7dd3fc` | links, "planned" |
| `--ok` | `#065f46` | `#6ee7b7` | available, verified, never sent |
| `--warn` | `#974a00` | `#fcd34d` | status, limitation, visible metadata, residual risk |
| `--danger` | `#be123c` | `#fda4af` | adversaries, refused writes |
| `--ink` | near-black | near-white | primary button (inverts per theme) |

- **Washes:** `--wash-*` tokens are `color-mix()` tints for badges, callouts and chips.
- **Always-dark tokens:** terminals use `--term-*` and stay dark in both themes.
- **Scene tokens:** the isometric scene uses material tokens (`--dev-*`, `--wk-*`,
  `--screen`, `--iso-edge`) so that both themes render it natively.
- **Semantic mapping:** accent = sealed / guarantee, ok = available / verified,
  warn = visible / limitation / in review, link = planned, danger = adversary. Keep it
  consistent across pages and diagrams.
- **Contrast:** every text token is at least 4.5:1 on `--bg`, `--bg-2` and `--surface` in
  both themes. Check this by computing ratios against the token values: axe-core reports no
  violations, but it leaves many nodes "incomplete" over the mesh and `.spot` pseudo-element
  backgrounds. Do not dim text with opacity on tinted or gradient surfaces. `--ok` is the darker `#065f46` in light because
  `#047857` falls below 4.5:1 on tinted callouts.
- **Inactive diagram steps** are never dimmed with opacity; only the active step gains a ring
  and lift.

## Spacing, layout, shape

- **Spacing:** `--sp-1…10` (4–128px). Sections use `--section` (fluid 72–136px). There are no
  section borders; separate sections with `section-alt` tinting instead.
- **Container:** `--maxw` 76rem with a fluid `--gutter` of 20–40px.
- **Grids** always use `minmax(0, 1fr)` columns (one shared rule near the top of
  `styles.css`) so that code blocks cannot force horizontal scroll.
- **Radii:** 8px (buttons, controls), 12px (terminals, chips, small panels), 16px (cards), 20px (diagrams, stage), and
  pills for badges and table-of-contents links.
- **Breakpoints, mobile-first:**

  | Width | What changes |
  |---|---|
  | 30rem (max) | brand tag and stage title hidden |
  | 40rem | scene labels shown |
  | 48rem | stage steps in three columns, tables unstack |
  | 52–56rem | threat grid, threat map, lanes |
  | 60rem | full nav, two-view specimen, quick-start and guarantee grids |
  | 64rem | horizontal flow rail, sticky split diagrams, FAQ sidebar, horizontal status track |

- **Container queries:** the SAS diagram (`.sas-host`) uses a container query, so the two
  devices sit side by side only when the diagram is at least 40rem wide.

## Components

- **Header:** sticky with `backdrop-filter: blur`; `.is-scrolled` adds a hairline.
- **Badges:** pills.
  - `badge-review` is amber with a pinging dot.
  - `badge-planned` is blue.
  - `badge-ok` is green.
  - `badge-seal` is indigo.
- **Buttons:** `btn-primary` (ink) and `btn-ghost`, at least 44px tall; `btn-lg` for hero
  CTAs.
  - `.magnetic` drifts toward a fine pointer.
  - Every `.btn` gets a click ripple.
  - `svg.nudge` arrows slide on hover.
- **Callout:** icon plus text, with `role="note"`. Amber by default; `is-info` for neutral
  notes.
- **Stage** (home hero):
  - window bar, scene SVG, three stage steps with animated progress bars, and a caption;
  - the pause button (`.scene-toggle`, `aria-pressed`) stays `hidden` until JS runs and under
    reduced motion;
  - the scene pauses itself while it is off screen.
- **Problem panels:** rotated plaintext "shards" (before) beside a vault list with lock rows
  (after).
- **Sync stepper** (`figure[data-flow]`):
  - a segmented control of step buttons, a play/pause button, and four node cards with chips;
  - a progress rail (`.flow-rail`) shows from 64rem.
- **Two views:** specimen windows (device plaintext and server ciphertext) with
  `[data-scramble]`, plus a `table.stack` that stacks into labelled cards under 48rem.
- **Pairs:** each guarantee is rendered beside its limitation.
- **Steps:** a numbered vertical timeline (`ol.steps`, max 54rem wide). `li.is-planned` turns
  the counter blue.
- **Terminals:**
  - always dark, with a copy button (icon swap and `data-state` copied/failed);
  - `.p` prompts are excluded from the copied text;
  - `pre` has `tabindex="0"` so horizontally scrolling code is reachable by keyboard.
- **Diagrams** (`.diagram` cards):
  - key hierarchy (`.keys`, dashed wires);
  - SAS device frames (`.sas`);
  - conflict lanes (`.lanes`);
  - tombstone and checkpoint ratchets (`.ratchet`, with a "refused" label);
  - architecture (`.arch`, animated link dots);
  - threat map (`.tmap` zones with numbered `.pin` links to `.threat:target` cards).
- **Cards:** `.card` plus `.spot`, a cursor-following radial highlight driven by `--mx` and
  `--my`, and `.lift` (hover raise).
- **Release gate:** `ul.gate`, a list of empty checkboxes that stay open until evidence is on
  #8.
- **FAQ:** native `<details>` with a plus/minus icon, grouped with `.faq-group`. On `/faq/`, a
  sticky `.faq-aside` index appears at 64rem.
- **Next cards** and the **agent strip** ("Copy page as Markdown", "Open in ChatGPT", "Open in
  Claude") close every deep page.

## Motion

Animate only `transform` and `opacity`, apart from the SVG stroke-dash route flow.

- **Stage scene:** a 9s loop (`--scene-dur`).
  1. A plaintext chip appears on device A and collapses into a sealed cube.
  2. The cube travels along the iso routes to the Worker, where a ledger row lands.
  3. The cube continues to device B, where a check appears.
  - The static base state (no `.js`, or reduced motion) shows the whole story at once.
- **Reveals:** hero elements fade up on load with a 70ms stagger. Other `.reveal` blocks fade
  up once in view, and `[data-stagger]` children step 60ms apart.
- **Sync stepper:** autoplays every 2.8s only while at least 35% visible. Selecting a step
  pauses it.
- **SAS digits** reveal with a stagger. Architecture link dots travel along their wires.
- **Micro-interactions:**
  - hover lift and spotlight;
  - magnetic primary CTA;
  - click ripple;
  - theme toggle that cross-fades sun and moon with a rotation;
  - copy icon pop.
- **Reduced motion:** `prefers-reduced-motion: reduce` collapses every animation and transition
  to its end state. It disables the scene loop (and hides its pause button), the pointer
  effects, smooth scroll and the ciphertext scramble.
- **Without JS:** content is fully visible. Only `.js .reveal` is hidden before reveal, and
  `beforeprint` reveals everything.

## Accessibility rules

- **Landmarks:** skip link, `header`, `nav[aria-label]`, `main#main` and `footer`. Each section
  is `aria-labelledby` its heading, and each page has exactly one `h1`.
- **Focus:** a 2px `--accent` outline with a 3px offset on `:focus-visible`. Never remove it.
- **Hidden attribute:** `[hidden]` is forced to `display: none`, so component display rules
  cannot reveal hidden controls.
- **Touch targets** are at least 44×44px for nav, menu, toggles, FAQ summaries, buttons, pins,
  table-of-contents links and footer links. Inline links inside prose are exempt.
- **Stepper keyboard contract:**
  - step buttons carry `aria-current="step"`;
  - Arrow keys move between steps, and Home and End jump to the first and last;
  - selecting a step pauses autoplay;
  - the play button uses `aria-pressed` and a dynamic `aria-label`.
- **Diagrams** are `figure`s with a `figcaption`. Meaning is always carried by text as well,
  never by color alone. The SAS codes have `role="img"` with the code as their label.
- **Live updates:** the theme toggle has a dynamic `aria-label`, and copy results and theme
  changes are announced through `#live-region` (`aria-live="polite"`).
- **New-tab links** carry hidden "(opens in a new tab)" text.
- **Theme choice:** the theme follows `prefers-color-scheme`. An explicit choice is stored under
  `akv-theme` and applied before first paint by the synchronous `site.js`.

## Engineering constraints

- **Static only:** plain HTML, one CSS file (`styles.css`) and one small vanilla JS file
  (`site.js`). No frameworks, no build step, no external JS, fonts or analytics.
- **No transforms on HTML:** HTML responses carry `Cache-Control: no-transform`
  (`worker/src/http/static-assets.ts`) so that the zone's automatic analytics beacon is never
  injected. CSS, JS and Markdown stay compressible.
- **CSP** (`worker/src/http/responses.ts`) has `script-src 'self'` and `style-src 'self'`.
  - No inline executable scripts (JSON-LD only) and no `style` attributes in markup.
  - Runtime styling goes through CSSOM custom properties (`--d`, `--mx`, `--rx`), which the
    CSP allows.
  - SVG presentation attributes are fine.
- **Reserved paths:** `/v1/*`, `/healthz` and `/internal/*` belong to the Worker. Never put
  static files under them.
- **AX and SEO surfaces:**
  - canonical URL, plus OG and Twitter meta;
  - `og.png`, 1200×630, rendered from the site's own CSS, fonts and static scene; there is no
    generator in the repo, so when the hero badge text changes, redraw the badge in the image
    to match;
  - `favicon.svg`, the gradient cube mark;
  - `apple-touch-icon.png`, 180px full-bleed;
  - `robots.txt`, `sitemap.xml`, `llms.txt` and the Markdown twins;
  - JSON-LD: WebSite, Organization and SoftwareApplication on `/`; TechArticle or HowTo plus
    BreadcrumbList on deep pages; FAQPage on `/faq/`.

## Verification checklist

Serve `worker/public` on a fixed port behind the production CSP. Check every page at 360, 768,
1024 and 1440px in both themes, confirming:

- no horizontal overflow
- no console errors or CSP violations
- no requests outside the origin
- Inter and Geist Mono loaded
- zero raw `style=` attributes

Then check behavior:

- **Reduced motion:** the scene is static and complete and the pause control is hidden.
- **JavaScript off:** every page is fully visible.
- **Keyboard alone:** the stepper and the scene pause control both work.

Run axe-core in a separate pass, because it needs CSP bypass to inject. Run
`pnpm --filter ak-vault-worker test` and `pnpm typecheck`. Keep at most 6 compressed
screenshots in `docs/wireframes/`.
