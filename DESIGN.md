# penrecon design system

## Stack and ownership

React, TypeScript, Tailwind CSS 4, and shadcn/ui's `base-nova` style with
**Base UI**, not Radix. `frontend/components.json` configures component generation.
Components live in `frontend/src/components/ui`; shared application behavior
lives in `common.tsx`, pages in `pages/`, and the shell/inventory/search in
`App.tsx`. Theme tokens and application layout are in `frontend/src/index.css`.
Build assets with `npm --prefix frontend run build`; FastAPI serves them locally.
Geist Variable fonts are bundled locally, with system monospace for technical data.

## Character

Modern, light, dense operator workspace. Data and changes lead; navigation and
actions stay quiet. No marketing metrics, decorative gradients, or filler cards.
Use bordered sections only to group related work. Keep inventory and comparison
results in tables, not card grids. See `PRODUCT.md` for product principles.

## Tokens

Use shadcn semantic tokens (`background`, `foreground`, `muted`, `primary`,
`border`, `destructive`, `ring`) through Tailwind utilities. The light neutral
canvas with **Blue action** emphasis is authoritative; dark tokens are inherited
component defaults, not an exposed product theme. Primary actions and text links
use blue (`#1d4ed8`), selected navigation and workbench items use a light blue
tint, and keyboard focus uses the blue ring token. Muted foreground is darkened
for legibility. Status and diff badges remain neutral and always include text;
destructive actions retain red.

Use `.mono` for IPs, ports, protocol/version strings, timestamps, commands,
output, and secrets. Body text is 14px; headings distinguish page and section
hierarchy without oversized chrome. Layout has a maximum width of 1440px,
responsive gutters, compact actions, and two-column forms collapsing on mobile.
Tables scroll horizontally rather than crushing technical content.

## Components and interactions

- Buttons, inputs, textareas, badges, tables, native selects, separators, and
  dialogs come from the committed shadcn components. Interactive button/dialog
  behavior uses `@base-ui/react`.
- `Modal` composes Base UI dialogs with a labeled title, focus trapping, Escape
  dismissal, focus restoration, scrollable content, and an accessible close button.
- `MutationForm` posts real multipart form data, disables duplicate submissions,
  surfaces errors, refreshes page data, and closes its modal on success.
- Operation timestamps use shadcn Calendar/Popover date pickers; selecting a day
  closes the calendar, and Clear date omits the timestamp. Time uses shadcn
  Input with `type="time"`; the browser/system chooses 12- or 24-hour display.
  No custom hour/minute selectors or forced time format.
- Inventory/service filters, sorting, pagination, scan comparison, and search
  use addressable query parameters. Page URLs can be bookmarked and reloaded.
  Pagination buttons bottom-align with the rows selector and page input, not
  with the combined height of their labels and controls.
  Inventory and host-service filters use outline Apply and Reset buttons with
  filter and rotate-back icons. Reset clears filters; host-service reset keeps
  the current rows-per-page setting.
- Destructive actions require confirmation. Host deletion states that credential
  links are deleted, not the credentials themselves.
- Notes and scan-derived text render as escaped React text. Notes retain their
  Markdown source; arbitrary HTML is not executed.
- Credentials use the approved identity-first workbench: a compact selectable
  list beside the selected credential's secret, full discovery notes, and
  host/service link management. The list stacks above details on small screens.
  Selected identity uses `#credential-ID`; text/kind/association filters use
  query parameters. Text filtering excludes secrets.
  Host/service link columns top-align and size independently so linked chips
  stay compact when the adjacent column has a taller picker.
  Unlink actions use compact ghost icon buttons with the unlink symbol,
  target-specific accessible labels, and hover titles.
- Secrets start concealed, with reveal/copy actions, and conceal again when
  switching identities or changing the secret. Delete is a secondary footer
  action with confirmation. Associations do not imply verified access.
- Design reference: `prototype/credential-views` at `b564842` preserves the
  workbench, ledger, and target-grouped comparison. The user approved Workbench;
  production contains only that view, with real mutations and no switcher.
- Host details use the approved **D / Tabbed Workbench** layout: Services,
  Host notes, and Credentials tabs, each with a 240px selectable list beside
  the selected item's details. Lists stack above details on small screens.
  Active tabs use `#services`, `#notes`, and `#credentials` and survive reloads
  and browser history. Selection stays intact across tab changes; deletion or
  filtering falls back to the first available item.
- Host identity, status, tags, hostnames, and observation dates stay above the
  workbench. Host triage and host management are secondary dialog actions;
  management contains rename, hostname links, and confirmed deletion.
  Service editing/reset/deletion, note creation/editing/deletion, and linked
  credential editing retain the existing mutation and validation contracts.
  Service filtering, sorting, and pagination remain server-side and addressable
  through query parameters. No full-dataset counts are inferred from loaded rows.
- Host-linked secrets conceal on identity changes, secret updates, and leaving
  the Credentials tab. Credential association does not imply verified access.
- Host design reference: `prototype/host-detail-views` at `4b88008` preserves
  A/B/C/D comparisons. The user approved D with split-pane notes and credentials;
  production contains only that layout, real mutations, and no variant controls.
- Global search is always reachable. `/` focuses a search field outside text
  entry. A skip link, visible focus, text labels, and semantic table structure
  support keyboard use. Reduced-motion preferences disable transitions/animations.
- Links underline only on hover, including navigation and linked service chips.
  Table-header links retain neutral text and never underline. Button-styled links
  keep button emphasis rather than text-link decoration. Inventory creation is
  a filled primary action; export, filtering, and management stay secondary.
- Color design reference: `prototype/color-emphasis` at `1f8be95` preserves the
  original and A/B/C comparisons. The user approved **A / Blue action**, with
  hover-only underlines and neutral, undecorated table headers. Production
  contains only the approved treatment, with real mutations and no switcher.

## Runtime boundary

FastAPI embeds escaped initial page context in a non-executable JSON script.
Requests with `Accept: application/json` retrieve the same context for mutation
refreshes. Forms preserve existing backend validation and immutable-ingest/user-data
rules; the browser never writes SQLite directly. No remote scripts, fonts, CDN
stylesheets, or Node server are required at runtime.
