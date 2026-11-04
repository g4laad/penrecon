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
palette is authoritative; dark tokens are inherited component defaults, not an
exposed product theme. Muted foreground is darkened for legibility. Global focus
outlines use the ring token. Status and diff badges always include text.

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
- Inventory/service filters, sorting, pagination, scan comparison, and search
  use addressable query parameters. Page URLs can be bookmarked and reloaded.
  Pagination buttons bottom-align with the rows selector and page input, not
  with the combined height of their labels and controls.
- Destructive actions require confirmation. Host deletion states that credential
  links are deleted, not the credentials themselves.
- Notes and scan-derived text render as escaped React text. Notes retain their
  Markdown source; arbitrary HTML is not executed.
- Credential secrets are concealed on the global list until revealed, with a
  copy action. Credential table fields share a 28px first-line alignment with
  their controls; multiline notes and revealed secrets expand below that line.
  Credential rows omit internal numeric IDs. Host detail shows linked evidence
  directly.
- Global search is always reachable. `/` focuses a search field outside text
  entry. A skip link, visible focus, text labels, and semantic table structure
  support keyboard use. Reduced-motion preferences disable transitions/animations.

## Runtime boundary

FastAPI embeds escaped initial page context in a non-executable JSON script.
Requests with `Accept: application/json` retrieve the same context for mutation
refreshes. Forms preserve existing backend validation and immutable-ingest/user-data
rules; the browser never writes SQLite directly. No remote scripts, fonts, CDN
stylesheets, or Node server are required at runtime.
