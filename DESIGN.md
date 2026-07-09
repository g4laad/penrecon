---
name: penrecon
description: Terminal-native recon console — dense, dark, monospace where the data lives.
colors:
  bg: "#0f1115"
  panel: "#181b22"
  line: "#262b34"
  row-hover: "#161a20"
  ink: "#d7dce3"
  muted: "#8b93a1"
  accent: "#5aa9e6"
  status-good-bg: "#226644"
  status-good-ink: "#bbffee"
  status-warn-bg: "#443322"
  status-warn-ink: "#ffddaa"
  status-danger-bg: "#662222"
  status-danger-ink: "#ffbbbb"
  tag-bg: "#224433"
  tag-ink: "#bbffee"
  diff-add: "#8fd88f"
  diff-chg: "#e7cf8f"
  diff-del: "#e79a9a"
typography:
  heading:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.3rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "normal"
  body:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
  data:
    fontFamily: "ui-monospace, SF Mono, JetBrains Mono, Menlo, Consolas, monospace"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tabular-nums"
  label:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 600
    letterSpacing: "0.02em"
rounded:
  sm: "3px"
  md: "5px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "5": "24px"
  "6": "32px"
  "8": "48px"
components:
  nav-link:
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    padding: "4px 0"
  button:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "8px 8px"
    height: "34px"
  input-field:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "8px 8px"
    height: "34px"
  port-chip:
    textColor: "{colors.ink}"
    typography: "{typography.data}"
  status-pill:
    backgroundColor: "{colors.status-good-bg}"
    textColor: "{colors.status-good-ink}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
  tag:
    backgroundColor: "{colors.tag-bg}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
---

# Design System: penrecon

## 1. Overview

**Creative North Star: "The Operator's Console"**

penrecon is an instrument, not an app. A single penetration tester sits in front
of it mid-engagement, terminal in one window and this in the next, scanning a lot
of hosts fast. The interface earns its keep by getting out of the way: dark
surface, high-contrast ink, and monospace exactly where the data lives — IPs,
ports, versions — so digits line up and the eye tracks columns instead of
re-reading them.

The system is **Restrained** in color and **dense** in space. One accent
(signal blue) marks links, focus, and the current section — nothing else.
Everything that isn't information is removed. Depth comes from three flat tonal
layers (background → panel → hairline border), never from shadow.

It explicitly rejects the generic SaaS dashboard: no card-grid-everything, no
gradient hero-metric tiles, no rounded pastel cards, no marketing chrome. It
also rejects the heavy enterprise-security console — cluttered toolbars and
hierarchy-less tiny tables. Decoration that doesn't carry information is noise.

**Key Characteristics:**
- Dark, flat, three tonal layers; zero shadow.
- Monospace + tabular figures for all machine data; sans for prose and chrome.
- One accent, used only for link / focus / current-state.
- 4pt spacing scale; tight groupings, generous breaks between them.
- Status and tags always pair color with a text label — never color alone.

## 2. Colors

A near-black slate carrying cool-grey ink, one signal-blue accent, and a small
semantic set of muted status hues.

### Primary
- **Signal Blue** (#5aa9e6): Links, keyboard focus ring, and the active-nav
  underline. The only saturated accent in the system; it means "interactive or
  current," nothing decorative.

### Neutral
- **Slate Base** (#0f1115): The page background — the console surface.
- **Panel** (#181b22): Second tonal layer for nav bar, inputs, buttons, and
  service panels.
- **Hairline** (#262b34): Borders and row dividers — the only separators used.
- **Row Hover** (#161a20): A one-step lift under the hovered table row.
- **Ink** (#d7dce3): Primary text (13.7:1 on base).
- **Muted** (#8b93a1): Secondary text — hostnames, column headers, service
  names, timestamps, placeholders (6.1:1 on base, 5.6:1 on panel; AA everywhere).

### Tertiary (semantic status)
- **Good** (ink #bbffee on bg #226644): `open` / `interesting`.
- **Warn** (ink #ffddaa on bg #443322): `closed` / `filtered`.
- **Danger** (ink #ffbbbb on bg #662222): `exploited`.
- **Tag** (ink #bbffee on bg #224433): user tags.

### Named Rules
**The One Accent Rule.** Signal Blue appears only on interactive-or-current
elements: links, `:focus-visible`, active nav. It is never used to decorate a
heading, border, or panel.

**The No-Color-Alone Rule.** Every status and tag renders its text label
alongside its color. A colorblind operator loses nothing.

## 3. Typography

**Body / Chrome Font:** system sans (`ui-sans-serif, system-ui`)
**Data Font:** system monospace (`ui-mono` stack), with `tabular-nums`

**Character:** One sans for all human-readable chrome; one monospace for all
machine data. The contrast axis is sans-vs-mono, not two similar sans families.
No display face, no web fonts — the OS stack loads instantly, which is the point
for a local tool.

### Hierarchy
- **Heading / h1** (600, 1.3rem, 1.3): Page title. Fixed rem, never fluid.
- **Title / h2** (600, 1.1rem): Section within a page (e.g. "Services").
- **Subtitle / h3** (mono, 1rem): Service identity headers like `443/tcp`.
- **Body** (400, 15px, 1.5): Prose, notes, labels. Prose capped 65–75ch.
- **Data** (mono, 15px, tabular-nums): IPs, port numbers, versions, diffs. The
  signature of the system.
- **Label** (600, 0.8rem, +0.02em): Table column headers, muted.

### Named Rules
**The Data-Is-Mono Rule.** Anything a scanner produced — IP, port, protocol,
version, timestamp — is set in the monospace stack with tabular figures so
columns align. Human writing (notes, labels, buttons) stays sans.

## 4. Elevation

Flat by doctrine. There are no shadows anywhere in the system. Depth is conveyed
entirely by three tonal layers — base (#0f1115) → panel (#181b22) → hairline
border (#262b34) — plus a single one-step row-hover tint. Interactive feedback is
carried by the focus ring and hover tint, not by lift.

### Named Rules
**The Flat-Console Rule.** Surfaces never cast shadows. If something needs to
feel raised, it gets a hairline border and the panel tone — not a blur.

## 5. Components

### Buttons
- **Shape:** gently rounded (5px).
- **Default:** panel background, ink text, hairline border, 8px padding, 34px min
  height.
- **Hover / Focus:** border shifts to Signal Blue on hover; `:focus-visible`
  draws a 2px accent outline offset 2px.

### Chips (ports & tags)
- **Port chip:** no background — monospace `port` bold in ink with the service
  name in muted at 0.85em beside it (`443 https`). Chips wrap densely; a host
  list caps at 12 with a muted `+N`.
- **Tag:** filled pill, tag-green bg/ink, 3px radius, 8px padding.

### Cards / Containers
- **Service panel:** the one container type. Panel background, hairline border,
  5px radius, 12–16px padding. Never nested. Used only on host detail to group a
  single service's data + annotation + attachments.

### Inputs / Fields
- **Style:** panel background, hairline border, 5px radius, ink text, 34px min
  height. Placeholder explicitly muted (never the browser default).
- **Focus:** 2px Signal Blue outline (`:focus-visible`), offset 2px.

### Navigation
- **Style:** flat top bar on panel tone. Sans links, ink default → accent on
  hover. Active section carries a 2px Signal Blue bottom border + `aria-current`.
  The `penrecon` wordmark sits right, in mono muted. On ≤640px the bar tightens;
  filter rows stack and dense tables scroll horizontally rather than break.

### Data Table (signature component)
- The core surface. Full-width, hairline row dividers, muted uppercase-ish
  column labels, dense 8/12px cell padding, one-step row-hover tint. IP column is
  a monospace accent link; the Open-ports column is the port-chip cluster.

## 6. Do's and Don'ts

### Do:
- **Do** set every scanner-produced value (IP, port, version, timestamp) in the
  monospace stack with `tabular-nums` so columns align.
- **Do** keep Signal Blue (#5aa9e6) to links, `:focus-visible`, and active nav.
- **Do** pair every status/tag color with a text label.
- **Do** convey depth with the three tonal layers + hairline borders.
- **Do** use the 4pt spacing scale (4/8/12/16/24/32/48) — no arbitrary values.

### Don't:
- **Don't** build a generic SaaS dashboard: no card-grid-everything, no gradient
  hero-metric tiles, no rounded pastel cards, no marketing chrome.
- **Don't** build the heavy enterprise-security console look (cluttered toolbars,
  hierarchy-less tiny tables).
- **Don't** add shadows or glassmorphism — the console is flat by rule.
- **Don't** use `border-left`/`border-right` >1px as a colored accent stripe.
- **Don't** use gradient text or `background-clip: text`.
- **Don't** set data in a proportional font — digits must align.
- **Don't** convey status by color alone.
