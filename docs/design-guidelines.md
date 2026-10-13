# ak-vault design guidelines

Design system for the static site at https://vault.agentkit.best (`worker/public/`).
The source of truth for token values is `worker/public/styles.css`; this file explains
intent and rules. Screenshots live in `docs/wireframes/`.

## Art direction

"Sealed ledger": a precise, ink-dark technical surface where encrypted material is shown
honestly. It is dark-first, with a warm "paper" light theme. Motifs:

- A faint measurement grid and a soft verdigris glow sit behind the heroes.
- Monospace labels act as ledger annotations (eyebrows, `spec §n` refs, data tags).
- The "specimen" card shows the same secret as device plaintext and as server ciphertext.
- Status is always visible. The amber "Protocol v1 · in security review" badge appears on every page hero.

The brand ties to AgentKit (agentkit.best: near-black base, sky-blue `#7cb9ea`, coral
accent). ak-vault gets its own identity through a verdigris "seal" accent. AgentKit's
sky blue is kept for links, and its coral is lightened for danger states.

## Content rules (non-negotiable)

- Do not invent metrics, customers, testimonials, pricing, dates or benchmarks.
- Mark every unreleased command as **planned**. Today `ak login`, `ak secrets sync enable`
  and `ak secrets search|describe|request|run` are planned.
- Call guarantees "design properties of protocol v1 as proposed" until issue #8 signs off.
- Every guarantee section sits next to its limitations: the vault-wide key, withheld
  updates (freeze attack), plaintext released to the child process on `run`, no claw-back,
  and visible metadata.
- Every edit to `index.html` or `security/index.html` must also update its Markdown twin
  (`index.md`, `security/index.md`) and, if facts change, `llms.txt`.

## Typography

All fonts are self-hosted from `worker/public/fonts/` as woff2 variable fonts with
`latin` and `vietnamese` subsets. The site makes no third-party requests.

| Role | Family | Weights | Use |
|---|---|---|---|
| Display | Bricolage Grotesque | 650–750 | h1–h3, brand wordmark |
| Body | IBM Plex Sans | 400–600 | paragraphs, UI |
| Mono | JetBrains Mono | 400–600 | code, eyebrows, badges, data labels |

The type scale is fluid, using `clamp()`, from `--step--1` (13–14px) to `--step-4` (36–68px).
Body text uses line-height 1.6 and headings 1.08. Headings use negative tracking (−0.02 to
−0.035em) and `text-wrap: balance`. Mono labels are uppercase with +0.06–0.08em tracking.

## Color tokens

| Token | Dark (default) | Light | Role |
|---|---|---|---|
| `--bg` | `#07090c` | `#f5f3ec` | page |
| `--surface` / `--surface-2` | `#10161d` / `#151d26` | `#fffefb` / `#f3f0e7` | cards, code chips |
| `--line` / `--line-strong` | `#222d39` / `#34424f` | `#dcd6c8` / `#bfb7a5` | borders |
| `--text` | `#e9eef2` | `#12171d` | primary text |
| `--text-muted` | `#9aa8b5` | `#4b5661` | secondary text |
| `--text-faint` | `#808d9a` | `#616c77` | labels, captions |
| `--accent` | `#5fe3c0` | `#0a7a60` | seal / encrypted / primary CTA |
| `--link` | `#8cc4ee` | `#24598a` | links, "planned" |
| `--warn` | `#f2b544` | `#8a5600` | status, limitations, visible metadata |
| `--danger` | `#ff8b78` | `#ad3420` | errors (reserved) |

Semantic mapping: **accent = encrypted / guarantee**, **warn = visible / limitation /
in review**, **link = planned**, **neutral = never sent**. Keep this mapping consistent.

Measured contrast: every text token is at least 4.6:1 on `bg`, `surface` and `surface-2`
in both themes. The primary button reaches 11.9:1 in dark and 5.3:1 in light.

## Spacing, layout, shape

- Spacing: `--space-1…9` (4, 8, 12, 16, 24, 32, 48, 72, fluid 64–120px section padding).
- Container: 72rem max width, fluid gutter of 16–32px. Sections are separated by a 1px `--line` top border.
- Grids always use `minmax(0, 1fr)` columns so code blocks cannot force horizontal scroll.
- Radii: 6px (controls), 10px (buttons, callouts), 16px (cards).
- Breakpoints, mobile-first: 40rem (tables stack), 48rem (2 columns), 56–62rem (split
  layouts), 64rem (full nav), 70rem (4–6 columns).

## Components

- **Badge**: a mono pill. Variants are `badge-review` (amber, pulsing dot), `badge-planned`
  (link blue) and `badge-ok` (accent).
- **Buttons**: `btn-primary` (accent fill) and `btn-ghost` (outline). Minimum height is 48px (44px in the agent strip).
- **Status note / callout**: an amber-washed box or left-border callout for availability and risk.
- **Specimen card**: a two-pane `figure` with a plaintext pane and a ciphertext pane. It is labelled "illustrative".
- **Flow**: an ordered list of 4 steps. It is a joined strip with arrow connectors at 70rem and above.
- **Ledger**: guarantee and limitation columns. Item text is short: a bold claim and a muted explanation, plus an optional `spec §` ref.
- **Data table**: a real `<table>` with a caption. At 40rem and below, rows stack with `data-label` captions.
- **Terminal**: a code block with a copy button. `.p` prompts and `.c` comments are styled, and prompts are excluded from the copied text.
- **Roadmap item**: issue number, linked title and badges. Never add dates.
- **FAQ**: native `<details>` and `<summary>`.
- **Agent strip**: "Copy page as Markdown" (fetches the same-origin `.md` twin), plus "Open in ChatGPT" and "Open in Claude" links.

## Motion

- Hero elements fade up once on load (600ms, `cubic-bezier(.22,1,.36,1)`, 60ms stagger).
  The content stays visible without JS, because only the `.js .reveal` state is hidden.
- Micro-interactions are 140ms color and border transitions, and a 1px press on buttons.
- The pulsing status dot is the only looping animation.
- `prefers-reduced-motion: reduce` disables smooth scroll, the reveal and the pulse.

## Accessibility rules

- Landmarks: a skip link, `header`, `nav[aria-label]`, `main#main` and `footer`. Each section
  is `aria-labelledby` its heading, and each page has exactly one `h1`.
- Focus: a 2px accent outline with 3px offset on `:focus-visible`. Never remove it.
- Touch targets are at least 44×44px for nav, menu, theme toggle, FAQ summaries and buttons.
- The theme toggle has a dynamic `aria-label` ("Switch to light theme"). Copy results are announced through
  `#live-region` (`aria-live="polite"`).
- External links that open a new tab carry hidden "(opens in a new tab)" text.
- The theme follows `prefers-color-scheme` by default. An explicit choice is stored in `localStorage`
  under `akv-theme` and applied before first paint by the synchronous `site.js`.

## Engineering constraints

- Pure static HTML, one CSS file (`styles.css`) and one small vanilla JS file (`site.js`).
  No frameworks, no build step, no external JS, fonts or analytics.
- No inline executable scripts. JSON-LD data blocks are the only inline `<script>`, which keeps a strict
  `script-src 'self'` CSP possible.
- `/v1/*`, `/healthz` and `/internal/*` belong to the Worker. Never put static files under those paths.
- AX and SEO surfaces: canonical URL, OG and Twitter meta, `og.png` (1200×630), `favicon.svg`,
  `apple-touch-icon.png` (180), `robots.txt`, `sitemap.xml`, `llms.txt`, Markdown twins and
  JSON-LD (WebSite, Organization, SoftwareApplication; TechArticle and BreadcrumbList on /security/).

## Verification checklist

Serve `worker/public` on a fixed port. Then check `/` and `/security/` at 360, 375, 768, 1024
and 1440px in both themes, confirming:

- no horizontal overflow
- no console errors
- no requests outside the origin
- all three font families loaded

Save at most 6 compressed screenshots to `docs/wireframes/`.
