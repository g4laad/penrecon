# penrecon design system

## Stack and ownership

React, TypeScript, Tailwind CSS 4, and shadcn/ui's `base-nova` style with
**Base UI**, not Radix. `frontend/components.json` configures component generation.
Components live in `frontend/src/components/ui`; shared application behavior
lives in `common.tsx`, pages in `pages/`, inventory/search in `App.tsx`, and the
application shell in `components/app-shell.tsx`. Theme tokens and application
layout are in `frontend/src/index.css`.
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
Input boundaries use a separate `input` token (`oklch(0.65 0 0)` in light mode),
measuring 3.23:1 against white; structural dividers keep the lighter `border` token.


Use `.mono` for IPs, ports, protocol/version strings, timestamps, commands,
output, and secrets. Body text uses `.875rem` (14px at the default root size),
so browser font preferences scale it; form text remains 14px on desktop and
16px on mobile. Data is 13px, and secondary metadata/table headings are 12px.
Page titles and descriptions are screen-reader
only; visible page-level rows contain actions, without an empty row on pages
without actions. Browser titles include the current engagement name; navigation
and search stay within that engagement.
Compact section, navigation, pagination, and row spacing prioritize visible records.
Layout has a maximum width of 1440px, responsive gutters, compact actions, and
two-column forms collapsing on mobile. Except for the viewport-fitted Hosts
inventory, tables scroll horizontally rather than crushing technical content.
Page-data table density overrides component utility defaults outside the
component layer, without changing dialog/form typography.
Inventory combines linked hostnames and omits unassigned triage placeholders;
search displays populated result categories or one meaningful no-results state.
The Hosts inventory stays within the viewport with no document or table scroll.
Its 56px summary rows use fixed-width columns, ellipsized hostnames, and bounded
service/tag previews; the complete record remains reachable through host links,
with full summary values in hover titles and explicit open-service counts.
On narrow screens, change/tags columns and service names give way to host identity,
port previews, and triage. At widths up to 480px, each 104px row places host identity
above services and triage; a 64px header preserves complete column labels.
Filters open in a dialog; Reset stays beside the filter trigger, while export
and creation right-align in the same wrapping toolbar. Filtered-empty results
direct the operator to Reset; an empty inventory points to import or New host.
Load failures replace the loading summary and offer Retry. Sortable headers
expose their active direction with `aria-sort`.
Pagination stays visible and automatically fits 1–50 rows to the available height.
The `fit` query parameter supplies that bounded server-side page size, overriding
manual `per` choices; filtering/sorting still apply before pagination. Resizing
retains the first visible host on the resized page, with ordinary server clamping.
The shared application footer is omitted on all pages to preserve content space.
Credentials retain full discovery notes and association controls, but omit empty
notes and zero-count scope metadata. Operations omit absent metadata while
retaining Start/End and From/To labels, commands, tags, and attachment access.
The Scans view fits the viewport: import controls stay above a bounded history
table with internal scrolling and sticky column headings. On compact screens,
the import section scrolls independently when needed. The scan import-safety
description remains available to screen readers; comparisons group the difference
count with the result heading and display filenames as secondary metadata.

## Components and interactions

- Buttons, inputs, textareas, badges, tables, native selects, separators, and
  dialogs come from the committed shadcn components. Interactive button/dialog
  behavior uses `@base-ui/react`.
  Buttons respond instantly rather than applying broad property transitions.
- `/engagements` fits the viewport with a dense, internally scrolling workspace
  table and sticky column headings. Names link directly to their workspaces;
  Name and Created headings toggle URL-backed ascending/descending sorting,
  defaulting to newest first. Long names/descriptions wrap within bounded
  columns; names retain a 10rem minimum width on narrow screens, with horizontal
  table scrolling rather than squeezed identity text. A single top-right Create
  engagement button opens a modal with a
  required name and optional description. An empty catalog points to that action.
  Each row has a right-aligned, labeled pencil action opening a prefilled edit
  modal for name and description. Saving preserves workspace identity and creation
  time, refreshes the current sorted catalog, and closes the modal on success.
  Scoped pages show a labeled engagement selector in the header; the penrecon
  brand links back to the catalog. Switching opens the destination host inventory with a full navigation,
  never reusing entity IDs or page state from another engagement.
- Global search uses matching default-height input and Find button controls.
- Navigation uses approved **A / Classic sidebar**: a 224px left navigation,
  collapsing to a 56px labeled-accessible icon rail. Bottom-left chevrons toggle
  it; desktop collapse preference survives navigation and reload in tab-local
  session storage. Engagement selection and scoped search remain above the page.
  The catalog has no sidebar. Active host-detail pages highlight Hosts.
- At widths up to 700px the sidebar starts collapsed; expanding overlays the page
  without squeezing its content. The mobile overlay traps keyboard focus, makes
  the underlying page inert, closes on Escape or outside click, and restores
  focus to the toggle. Resizing back to desktop restores its separate preference.
- Navigation reference: `prototype/navbar-choices` at `2ae1d65` preserves the
  A/B/C sidebar comparison. The user approved A; production has only the classic
  sidebar, normal scoped links, and no variant parameters or comparison controls.
- `Modal` composes Base UI dialogs with a labeled title, focus trapping, Escape
  dismissal, focus restoration, scrollable content, and an accessible close button.
  Dialogs use an unblurred dim backdrop and a 75 ms opacity-only entrance, with
  no zoom or exit animation. Reduced-motion preferences disable the entrance fade.
- `MutationForm` posts real multipart form data, disables duplicate submissions,
  surfaces errors, refreshes page data, and closes its modal on success.
  Engagement-name and host-IP validation return `field_errors` keyed by input name; shared
  fields render associated inline errors, expose invalid state, and receive focus
  after submission is re-enabled. Network errors and unstructured HTTP failures
  retain the draft and explain how to check the local server and connection before
  retrying, without claiming the save definitely failed. Structured validation
  messages remain available beside the fields.
- Operation timestamps use shadcn Calendar/Popover date pickers; selecting a day
  closes the calendar, and Clear date omits the timestamp. Time uses shadcn
  Input with `type="time"`; the browser/system chooses 12- or 24-hour display.
  No custom hour/minute selectors or forced time format.
- Inventory/service filters, sorting, pagination, scan comparison, and search
  use addressable query parameters. Page URLs can be bookmarked and reloaded.
  Inventory uses automatic viewport-sized pagination with Previous/Next controls.
  Other pagination buttons bottom-align with their rows selector and page input,
  not with the combined height of their labels and controls.
  Inventory and host-service filters use outline Apply and Reset buttons with
  filter and rotate-back icons. Reset clears filters; host-service reset keeps
  the current rows-per-page setting.
- Destructive actions require confirmation. Host deletion states that credential
  links are deleted, not the credentials themselves.
- Host notes retain exact Markdown source and render through a shared
  `react-markdown`/GFM viewer in both saved details and editor previews. HTML is
  displayed as escaped text, unsafe URL schemes are blocked, and images render
  as source links rather than fetching remote resources. Scan-derived text
  remains escaped React text.
- Note creation/editing uses CodeMirror with syntax highlighting, formatting
  actions, undo/redo, and Write/Preview/Split modes in a wider, expandable dialog.
  Split panes stack on narrow screens; tables and fenced code scroll horizontally.
  Fenced code has a copy action with visible success/failure feedback. Tab leaves
  the editor rather than inserting indentation. Notes use URL-encoded submission
  to avoid multipart newline normalization; other forms retain multipart encoding.
  The editor loads only when an Add/Edit note dialog opens; reading notes does
  not download CodeMirror. A dialog-level loading state withholds the entire
  form until the editor is ready, preserving initial draft-state detection.
  Strict entry signatures keep lazy chunks from importing unversioned `app.js`
  alongside the cache-versioned entry script and initializing React twice.
- Note dialogs warn before discarding changed title/source or leaving the page.
  Failed saves keep drafts intact; saving disables editing and dismissal until
  completion. Successful mutations close without a discard prompt.
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
- Operations use the approved **A / Workbench**: a compact selectable list
  beside the selected operation's full command, output, metadata, tags, notes,
  and attachment download. Reading evidence does not open an edit form.
  Add and Edit retain the existing forms; confirmed deletion remains in Edit.
  Commands can be copied, with visible success or failure feedback.
  Search and Add operation share a bottom-aligned toolbar without the standalone
  filter/header margins offsetting their controls.
- The operations list and details scroll independently within the viewport,
  stacking on narrow screens. Selection uses `#operation-ID`, survives reload
  and browser history, and falls back to the first available record after
  filtering or deletion. Search and pagination remain server-side with
  addressable query parameters; the page-size control appears only in pagination.
- Operations design reference: `prototype/operation-views` at `989d855`
  preserves A / Workbench, B / Journal, and C / Target dossier. The user approved
  A; production contains only the workbench, real mutations, and no switcher.
- Credential creation uses approved **A / Compact dialog**: kind, identity,
  concealed kind-aware secret entry, and discovery notes appear first; optional
  host/service associations expand below. Search filters hosts without clearing
  selections. Unchecking a host clears its selected services.
  Association controls mount only on first expansion, then remain mounted while
  collapsed so selected hosts/services stay in the submitted form until dismissal.
  Host results use 50-row pagination; changing the search resets to the first page.
  Only current-page and selected host rows remain mounted. Selected off-page rows
  are hidden but retain service loads, retry state, and submitted associations.
  A username or secret is required. Credential and selected links save in one
  transaction; invalid or out-of-scope targets create nothing. Service-loading
  failures remain visible with retry, and saving waits for selected hosts to load.
  Reopening the dialog starts a fresh, concealed draft.
  Design reference: `prototype/credential-entry` at `199ec06` preserves A/B/C.
  The user approved A; production has real persistence and no prototype controls.
- Host details use the approved **D / Tabbed Workbench** layout: Services,
  Host notes, and Credentials tabs, each with a 240px selectable list beside
  the selected item's details. Lists stack above details on small screens.
  All workbenches stay within the viewport: item lists and selected details
  scroll independently rather than growing with their contents. Neither the
  document nor the outer workspace scrolls. On narrow or short screens,
  navigation and host metadata have bounded, independently scrollable regions
  to preserve space for the item and detail panes.
  Active tabs use `#services`, `#notes`, and `#credentials` and survive reloads
  and browser history. Selection stays intact across tab changes; deletion or
  filtering falls back to the first available item.
- Host identity remains visible as 13px data, with status, linked hostnames, and
  tags in a compact wrapping row; its page heading is screen-reader only.
  Observation dates live in Manage host rather than the
  main header; absent hostnames do not create a placeholder row.
  Service data uses 13px text and 12px secondary metadata, compact two-line list
  entries where content fits, and reduced pane padding. State and assigned triage
  remain visible; missing product/version, dates, and triage omit placeholder text.
  The selected service combines its identity and badges in one header; credential
  links appear only when present. Forms retain their existing typography.
  Service count, filter toggle, and creation share a wrapping toolbar; active
  filters are labeled and initially expanded, with addressable query parameters.
  Host triage and host management right-align on the host identity row, wrapping
  when needed on narrow screens. Both open secondary dialogs; management contains
  observation dates, rename, hostname links, and confirmed deletion.
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
  The engagement selector retains its accessible label when compact chrome hides
  the visible label; native selects use 16px text on mobile like other form inputs.
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
