---
name: penrecon
description: Modern light recon console — clean, dense, monospace where the data lives, icons for wayfinding.
colors:
  bg: "#eef1f6"
  surface: "#ffffff"
  panel: "#f7f9fc"
  line: "#e2e6ee"
  line-strong: "#cdd4e0"
  row-hover: "#f4f7fb"
  ink: "#141a24"
  muted: "#586074"
  accent: "#2563eb"
  accent-ink: "#ffffff"
  accent-weak: "#e7effe"
  status-good-bg: "#dcf7e8"
  status-good-ink: "#0f6b3d"
  status-warn-bg: "#fdf0d5"
  status-warn-ink: "#8a5a00"
  status-danger-bg: "#fde7e7"
  status-danger-ink: "#c02626"
  status-new-bg: "#e7effe"
  status-new-ink: "#1d4ed8"
  tag-bg: "#f7f9fc"
  tag-ink: "#3a4456"
  diff-add: "#0f7a45"
  diff-chg: "#8a5a00"
  diff-del: "#c0392b"
typography:
  heading:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.35rem"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.01em"
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
    fontSize: "0.78rem"
    fontWeight: 600
    letterSpacing: "0.03em"
rounded:
  sm: "6px"
  md: "8px"
  lg: "12px"
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
    textColor: "{colors.muted}"
    rounded: "{rounded.sm}"
    padding: "8px 12px"
  nav-link-active:
    backgroundColor: "{colors.accent-weak}"
    textColor: "{colors.accent}"
    rounded: "{rounded.sm}"
    padding: "8px 12px"
  icon:
    size: "16px"
  button:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.sm}"
    padding: "8px 12px"
    height: "38px"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    height: "38px"
  input-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    height: "38px"
  port-chip:
    textColor: "{colors.ink}"
    typography: "{typography.data}"
  status-pill:
    backgroundColor: "{colors.status-good-bg}"
    textColor: "{colors.status-good-ink}"
    rounded: "{rounded.sm}"
    padding: "1px 8px"
  tag:
    backgroundColor: "{colors.tag-bg}"
    textColor: "{colors.tag-ink}"
    rounded: "{rounded.sm}"
    padding: "1px 8px"
---

# Design System: penrecon

## 1. Overview

**Creative North Star: "The Operator's Console, in daylight"**

penrecon is an instrument, not an app. A single penetration tester sits in front
of it mid-engagement, terminal in one window and this in the next, scanning a lot
of hosts fast. The interface earns its keep by getting out of the way: a clean
light surface, high-contrast ink, and monospace exactly where the data lives —
IPs, ports, versions — so digits line up and the eye tracks columns instead of
re-reading them. A small, consistent icon set carries wayfinding (nav, actions,
change markers) so the operator reads the shape of the UI before the words.

The system is **Restrained** in color and **dense** in space. One blue accent
marks links, focus, primary actions, and the current section — nothing else.
Everything that isn't information is removed. Depth comes from a light neutral
canvas, white data surfaces, hairline borders, and *soft* shadow — data sits on
crisp white cards that lift a step off the page.

It explicitly rejects the generic SaaS dashboard: no gradient hero-metric tiles,
no pastel card-grid-everything, no marketing chrome. It also rejects the heavy
enterprise-security console — cluttered toolbars and hierarchy-less tiny tables.
Cards, elevation, and icons are used only where they aid triage. Decoration that
doesn't carry information is noise.

**Key Characteristics:**
- Light, clean; cool near-white canvas → white data surfaces → hairline borders
  → soft shadow.
- Monospace + tabular figures for all machine data; sans for prose and chrome.
- One blue accent for link / focus / primary action / current-state.
- Consistent inline-SVG icon set (Lucide-style, 2px stroke) for nav, actions,
  and change markers.
- 4pt spacing scale; tight groupings, generous breaks between them.
- Status, tags, and change markers always pair color with text (and often an
  icon) — never color alone.

## 2. Colors

A cool near-white canvas carrying near-black ink, one blue accent, and a small
semantic set of soft-tinted status hues.

### Primary
- **Accent Blue** (#2563eb): Links, keyboard focus ring, primary buttons, and
  the active-nav pill. The only saturated accent; it means "interactive, primary,
  or current," nothing decorative. 5.1:1 on white.

### Neutral
- **Canvas** (#eef1f6): The page background — the cool light surface everything
  sits on.
- **Surface** (#ffffff): Data surfaces — tables, cards, inputs, service panels.
- **Panel** (#f7f9fc): Subtle secondary fill — table headers, tag pills, kbd.
- **Hairline** (#e2e6ee) / **Hairline-strong** (#cdd4e0): Borders and dividers;
  the strong step edges inputs and secondary buttons.
- **Row Hover** (#f4f7fb): A one-step tint under the hovered table row.
- **Ink** (#141a24): Primary text (15.5:1 on white).
- **Muted** (#586074): Secondary text — hostnames, column headers, service names,
  timestamps, placeholders. AA on white, panel, and canvas.

### Tertiary (semantic status, soft tint + dark ink)
- **Good** (ink #0f6b3d on bg #dcf7e8): `open` / `interesting`.
- **Warn** (ink #8a5a00 on bg #fdf0d5): `closed` / `filtered`.
- **Danger** (ink #c02626 on bg #fde7e7): `exploited`.
- **New** (ink #1d4ed8 on bg #e7effe): `new` status — flagged, needs review.
- **Reviewed** (ink #475069 on bg #eef1f6): settled, recedes.
- **Tag** (ink #3a4456 on bg #f7f9fc, hairline border): user tags.

### Change / diff vocabulary (AA text-on-white)
- **Add** (#0f7a45): new host / added service — the `new` marker.
- **Changed** (#8a5a00): altered service — the `chg` marker.
- **Removed** (#c0392b): dropped service (diff view).

### Named Rules
**The One Accent Rule.** Accent Blue appears only on interactive-or-current
elements: links, `:focus-visible`, primary actions, active nav. It is never used
to decorate a heading, border, or panel.

**The No-Color-Alone Rule.** Every status, tag, and change marker renders a text
label (and usually an icon) alongside its color. A colorblind operator loses
nothing.

## 3. Typography

**Body / Chrome Font:** system sans (`ui-sans-serif, system-ui`)
**Data Font:** system monospace (`ui-mono` stack), with `tabular-nums`

**Character:** One sans for all human-readable chrome; one monospace for all
machine data. The contrast axis is sans-vs-mono, not two similar sans families.
No display face, no web fonts — the OS stack loads instantly, which is the point
for a local tool.

### Hierarchy
- **Heading / h1** (650, 1.35rem, -0.01em): Page title. Fixed rem, never fluid.
- **Title / h2** (600, 1.1rem): Section within a page (e.g. "Services").
- **Subtitle / h3** (mono, 1rem): Service identity headers like `443/tcp`.
- **Body** (400, 15px, 1.5): Prose, notes, labels. Prose capped 65–75ch.
- **Data** (mono, 15px, tabular-nums): IPs, port numbers, versions, diffs. The
  signature of the system.
- **Label** (600, 0.78rem, +0.03em, uppercase): Table column headers, field
  labels, muted.

### Named Rules
**The Data-Is-Mono Rule.** Anything a scanner produced — IP, port, protocol,
version, timestamp — is set in the monospace stack with tabular figures so
columns align. Human writing (notes, labels, buttons) stays sans.

## 4. Elevation

Soft, sparing elevation. The light canvas frames white data surfaces that lift a
single step: a hairline border plus a low-spread shadow (`0 1px 3px`). The order
is canvas (#eef1f6) → surface card (#ffffff, hairline + shadow-sm) → row-hover
tint. Sticky nav carries only shadow-sm. Focus is a soft 3px accent ring on
fields; `:focus-visible` draws a 2px accent outline everywhere.

### Named Rules
**The One-Step Rule.** Surfaces lift at most one step. No stacked shadows, no
nested cards, no glassmorphism. If something needs to feel raised, it gets a
hairline border, white fill, and shadow-sm — not a heavier blur.

## 5. Components

### Icons
- **Style:** inline SVG, Lucide-family, 24 grid, 2px stroke, round caps/joins,
  `currentColor` — no icon library (local, no-build tool). Defined once in
  `_icons.html` as an `icon(name, cls)` macro.
- **Size:** 16px default; 13px (`.icon-sm`) in dense slots (change markers, sort
  carets). Always `aria-hidden` — paired with a visible or SR text label.
- **Vocabulary:** nav (server / scan-reticle / git-compare, shield wordmark),
  actions (search, plus, filter, upload, x), change markers (plus-circle = new,
  triangle = changed), sort (chevron up/down).

### Buttons
- **Primary** (submit / new-host / apply): accent fill, white text+icon,
  shadow-sm, 38px height, 6px radius; hover darkens to #1d4fd0.
- **Secondary:** white fill, hairline-strong border, ink text; hover accent
  border + panel fill.
- **Danger:** white fill, danger-red text + border; hover red border + faint red
  fill.
- Icon + label sit in a flex row with an 8px gap.

### Chips (ports & tags)
- **Port chip:** no background — monospace `port` bold in ink with the service
  name in muted at 0.85em beside it (`443 https`). Chips wrap densely; a host
  list caps at 12 with a muted `+N`.
- **Tag:** soft panel fill, hairline border, cool ink, 6px radius.

### Change marker
- Its own tight leading **Change** column (shrink-to-content). Icon + short
  label + color: `⊕ new` (add-green), `△ chg` (changed-amber), with a
  visually-hidden long description. Empty cell for unchanged rows — the flagged
  ones pop, the rest recede. The change filter covers all three states (new /
  changed / unchanged).

### Cards / Containers
- **Table card (`.table-wrap`):** every data table sits in a white card —
  hairline border, 12px radius, shadow-sm, overflow-hidden so rows clip to the
  radius. The signature container.
- **Service panel:** white `<details>`, hairline border, 8px radius, shadow-sm.
  Never nested. Groups one service's data + annotation + attachments on host
  detail.

### Inputs / Fields
- **Style:** white fill, hairline-strong border, 6px radius, ink text, 38px min
  height. Placeholder explicitly muted (never the browser default). Persistent
  small-caps field label above the control.
- **Focus:** border shifts to accent + soft 3px accent ring; `:focus-visible`
  outline for keyboard.
- **Search field:** search icon inset left inside the input.

### Navigation
- **Style:** white sticky top bar with shadow-sm and a hairline bottom. Links are
  icon + label, muted → ink on hover (panel fill). Active section is an
  accent-weak pill with accent text/icon + `aria-current`. The `penrecon`
  wordmark sits right with a shield icon, in mono. On ≤640px labels collapse to
  icons, filter rows stack, and dense tables scroll horizontally within their
  card rather than break.

### Data Table (signature component)
- The core surface, framed in a `.table-wrap` card. Full-width, hairline row
  dividers (last row borderless), panel-tinted uppercase column labels, dense
  12/16px cell padding, one-step row-hover tint. IP column is a monospace accent
  link; sortable headers are full-cell links with a chevron on the active column.

## 6. Do's and Don'ts

### Do:
- **Do** set every scanner-produced value (IP, port, version, timestamp) in the
  monospace stack with `tabular-nums` so columns align.
- **Do** keep Accent Blue (#2563eb) to links, `:focus-visible`, primary actions,
  and active nav.
- **Do** pair every status / tag / change marker color with a text label (and an
  icon where it aids scanning).
- **Do** frame data tables in a white `.table-wrap` card; lift at most one step.
- **Do** use the shared `_icons.html` macro for all icons — one stroke style, one
  grid.
- **Do** use the 4pt spacing scale (4/8/12/16/24/32/48) — no arbitrary values.

### Don't:
- **Don't** build a generic SaaS dashboard: no gradient hero-metric tiles, no
  pastel card-grid-everything, no marketing chrome.
- **Don't** build the heavy enterprise-security console look (cluttered toolbars,
  hierarchy-less tiny tables).
- **Don't** stack shadows, nest cards, or use glassmorphism — one step only.
- **Don't** use `border-left`/`border-right` >1px as a colored accent stripe.
- **Don't** use gradient text or `background-clip: text`.
- **Don't** set data in a proportional font — digits must align.
- **Don't** ship an icon without a paired text/SR label, or convey status by
  color alone.
