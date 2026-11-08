# penrecon UI contract

## Foundations

A light, dense operator workspace: data and changes lead; navigation and actions
stay quiet. Use bordered sections to group work, tables rather than card grids
for inventory/comparisons, and no marketing metrics, decorative gradients, or
filler cards. Product priorities live in `PRODUCT.md`; setup/build commands in
`README.md`.

React, TypeScript, Tailwind CSS 4, and shadcn/ui `base-nova` use **Base UI, not
Radix**. `frontend/components.json` configures generation; committed primitives
live in `frontend/src/components/ui`, shared behavior in `common.tsx`, pages in
`pages/`, inventory/search in `App.tsx`, and chrome in `components/app-shell.tsx`.
`frontend/src/index.css` owns tokens, density, layout, and responsive rules;
consult it and the relevant component for breakpoints not specified below.
Geist Variable fonts are bundled locally; technical data uses system monospace.

### Color and type

- Use semantic Tailwind tokens (`background`, `foreground`, `muted`, `primary`,
  `border`, `destructive`, `ring`). **Blue action** on a light neutral canvas is
  the product theme; inherited dark defaults are not an exposed theme.
- Primary actions/text links use `#1d4ed8`; selected navigation/workbench items
  use light blue, with blue focus rings. Muted text remains legible. Status/diff
  badges are neutral and text-labeled; destructive actions remain red.
- Preserve these token/contrast constraints:

  | Treatment | Value / contrast |
  | --- | --- |
  | Solid `primary-hover`, not opacity | Light `#1340ca`, 8.03:1 with white; inherited dark `oklch(0.87 0 0)`, 12.10:1 with primary foreground |
  | Inherited dark destructive | sRGB-safe `oklch(0.704 0.185 22.216)`; hover pair 4.65:1 against card |
  | Destructive button tints | 10% default, 20% hover in both appearances |
  | Light destructive text | `oklch(0.50 0.20 27.325)`; 5.52:1 on default tint, 4.57:1 on hover tint |
  | Light input boundary | Separate `input` token `oklch(0.65 0 0)`, 3.23:1 against white; structural dividers use lighter `border` |

- `.mono` covers IPs, ports, protocols/versions, timestamps, commands, output,
  and secrets. Body text is `.875rem` (14px at the default root), respecting
  browser font preferences; forms are 14px desktop/16px mobile, data 13px, and
  secondary metadata/table headings 12px. Page-table density overrides do not
  alter dialog/form typography.
- Links underline only on hover, including navigation and service chips.
  Table-header links stay neutral and never underline; button-styled links keep
  button emphasis. Inventory creation is primary; export/filter/manage are secondary.

### Layout, keyboard, and motion

- Maximum content width is 1440px, with responsive gutters, compact spacing and
  actions, and two-column forms collapsing on mobile. Tables scroll horizontally
  rather than crush technical content, except the viewport-fitted Hosts inventory.
- Page titles/descriptions are screen-reader only. Visible page-level rows hold
  actions and disappear when there are none. No shared application footer.
- Workbenches fit the viewport: lists and details scroll independently, without
  document/outer-workspace scrolling; lists stack above details on small screens.
  Compact/short layouts bound navigation, metadata, and toolbars independently to
  preserve working space.
- Provide a skip link, visible focus, text labels, semantic tables, WCAG AA
  contrast, and full keyboard access; status never depends on color alone.
  Global search remains reachable, and `/` focuses search outside text entry.
  Compact engagement selectors retain their accessible label; native selects
  use the same 16px mobile type as other inputs.
- Buttons respond immediately, without broad property transitions.
  `prefers-reduced-motion` disables transitions/animations.

## Shared dialogs, forms, and data loading

- Use committed buttons, inputs, textareas, badges, tables, native selects,
  separators, and dialogs; interactive button/dialog behavior is Base UI.
- `Modal` supplies a labeled title, focus trap/restoration, scrollable content,
  and accessible close button. Its dim backdrop is unblurred; entrance is a
  75ms opacity-only fade, with no zoom/exit animation and no reduced-motion fade.
  Escape normally dismisses, **subject to the same dirty-draft confirmation and
  saving-time block as every other dismissal path**.
- Changed drafts warn before dismissal or leaving the page; cancelling preserves
  values. This includes note title/source, credential associations, and operation
  calendar-only or attachment-only changes. Saving disables editing/dismissal;
  successful saves close without a discard prompt. Reopening a dismissed
  credential dialog starts a fresh, concealed draft.
- `MutationForm` submits real **multipart** data, except note creation/editing,
  which is **URL-encoded** to preserve exact Markdown newlines. It prevents
  duplicate submissions, exposes save status/errors, and refreshes page data or
  follows the mutation's destination before closing on success.
- Engagement-name/host-IP `field_errors` are keyed by input name, rendered inline
  with associated invalid state, and focused after submission is re-enabled.
  Rejected saves retain drafts and field messages. Unconfirmed saves (network,
  server, or invalid confirmation responses) must not claim failure or invite
  immediate resubmission: retain the draft, disable editing, offer **Check current
  data**, and require explicit duplicate-risk confirmation to return to editing.
  If saving succeeded but refresh failed, offer **Refresh view**, never resubmit.
- Destructive actions require confirmation. Host deletion removes credential
  links, not credentials themselves. Existing backend validation and immutable
  ingest/user-data boundaries apply to every form.
- Filters, sorts, pagination, scan comparisons, and search use bookmarkable,
  reloadable query parameters. Non-inventory pagination buttons bottom-align
  with the rows selector/page input, not the labels above them. Inventory/service
  filters use outline Apply/Reset with filter/rotate-back icons; service Reset
  retains rows-per-page.
- Query updates announce pending work, support Back/Forward, abort superseded
  requests, preserve focus/scroll where applicable, and retain existing results
  with a focus-preserving Retry on failure. If the focused pagination link
  disappears, focus moves to main without scrolling. Detail loads invalidate on
  selection or list refresh, withhold obsolete detail, and expose loading/error/
  Retry states; late responses must not overwrite current selection or drafts.
- Credentials and Operations page components ship in the application entry,
  avoiding a post-list-request module fetch and Suspense reveal delay before
  selected details can load. Summary/detail API reads remain separate.

## Engagement catalog and shell

- `/engagements` has no sidebar. Its dense workspace table fits the viewport,
  scrolls internally, and has sticky headings. Names link to workspaces; Name
  and Created toggle URL-backed ascending/descending sort, newest first by default.
  Names/descriptions wrap in bounded columns; names keep a 10rem minimum on
  narrow screens, allowing horizontal scrolling instead of squeezed identity.
- One top-right Create engagement action opens required-name/optional-description
  fields; the empty state points there. Each row has a right-aligned, labeled
  pencil action for prefilled editing. Saving retains identity/creation time,
  refreshes the current sorted catalog, and closes on success.
- Scoped pages show a labeled engagement selector and scoped search above the
  page; browser titles include the engagement name. The brand returns to the
  catalog. Switching engagements fully navigates to the destination Hosts
  inventory, never reusing another engagement's entity IDs or page state.
- Use only the classic sidebar: 224px expanded, 56px accessible icon rail,
  bottom-left chevron toggle. Desktop collapse preference survives navigation/
  reload in tab-local session storage. Host details highlight Hosts. Selected
  navigation uses light blue fill/blue text, without a darker left stripe.
- At widths up to 700px, start collapsed; expansion overlays rather than squeezes
  the page, traps focus, makes underlying content inert, dismisses on Escape or
  outside click, and restores toggle focus. Returning to desktop restores its
  separate preference. Search input and Find button have matching default height.

## Hosts inventory and search

- Inventory combines linked hostnames and omits unassigned triage placeholders.
  Search shows populated categories or one meaningful no-results state.
- Hosts has no document/table scrolling. Fixed columns and 56px summary rows use
  ellipsized hostnames, bounded service/tag previews, hover titles for full summary
  values, explicit open-service counts, and host links to the complete record.
- Narrow layouts drop change/tags columns and service names before host identity,
  port previews, or triage. At widths up to 480px, 104px rows put identity above
  services/triage; a 64px header preserves complete labels.
- Filters open in a dialog, with Reset beside the trigger and export/creation
  right-aligned in the wrapping toolbar. Filtered-empty results point to Reset;
  empty inventory points to import/New host. Load failures replace the loading
  summary and offer Retry. Sortable headers expose direction through `aria-sort`.
- Always-visible Previous/Next pagination fits 1–50 rows to available height.
  `fit` is the bounded server-side page size, overriding manual `per`; filtering/
  sorting precede pagination. Resizing retains the first visible host on its
  resized page, subject to ordinary server clamping.

## Host details

- Use a tabbed workbench: Services, Host notes, Credentials, and Timeline.
  The item tabs have 240px selectable lists beside details; narrow layouts stack
  them. `#services`, `#notes`, `#credentials`, and `#timeline` preserve the tab on
  reload/Back/Forward. Item selections persist across tab changes; deletion or
  filtering commits a fallback to the first available item rather than reviving
  the removed selection later.
- Identity remains visible as 13px data with status, linked hostnames, and tags
  in a compact wrapping row; omit absent hostname rows. Triage and Manage host
  right-align/wrap there and open secondary dialogs. Management holds observation
  dates, rename, hostname links, and confirmed deletion; dates stay out of the
  main header.
- Services use compact two-line entries where content fits, 13px data/12px
  metadata, and reduced pane padding. State/assigned triage stay visible; absent
  product/version, dates, or triage do not create placeholders. Selected service
  identity/badges share one header; credential links appear only when present.
- Service count, filter toggle, and creation share a wrapping toolbar. Active
  filters are labeled and initially expanded. Filtering/sorting/pagination are
  server-side and URL-backed; never infer full-dataset counts from loaded rows.
  Editing/reset/deletion, note mutations, and linked-credential editing retain
  shared validation/mutation rules and normal form typography.
- Timeline reserves a stable scrollbar gutter and 12px inline-end padding around
  the unchanged-scans toggle/evidence. Filtering, pagination, and latest-change
  links fetch page data without document navigation. Preserve checkbox focus and
  timeline scroll, URL state, pending announcements, stale-request cancellation,
  and failure/Retry behavior described above.

## Notes

- Preserve exact Markdown source. Saved notes and editor previews share the
  `react-markdown`/GFM viewer: HTML is escaped text, unsafe URL schemes are blocked,
  and images become source links instead of remote fetches. Scan-derived content
  remains escaped React text.
- Add/Edit uses CodeMirror syntax highlighting, formatting actions, undo/redo,
  and Write/Preview/Split in a wider, expandable dialog. Split panes stack on
  narrow screens; tables/fenced code scroll horizontally. Code blocks offer copy
  with visible success/failure feedback. Tab leaves the editor, not indentation.
- Load the editor only when opening Add/Edit, not when reading notes. Withhold
  the entire form behind a dialog loading state until ready so dirty-state
  detection starts from the real draft. Lazy chunks must share the versioned
  entry without loading a second, unversioned `app.js`/React initialization.
  Submission encoding and dirty/save guards are defined with shared forms above.

## Credentials

- Use an identity-first workbench: compact selectable list beside secret, full
  discovery notes, and host/service links. Omit empty notes/zero-count scope
  metadata. `#credential-ID` is selection; text/kind/association filters are query
  parameters, and text search excludes secrets. Without explicit selection use
  the first result; a valid off-page ID loads separately without changing filters,
  with Clear selection/Clear filters recovery. Invalid links show recovery rather
  than silently selecting a different credential.
- Secrets start concealed with reveal/copy actions. Conceal on identity changes,
  secret updates, and leaving the host Credentials tab. Create/Edit use concealed,
  kind-aware secret entry; changing kind conceals without clearing. Associations
  do not establish verified access. Delete is a secondary, confirmed footer action.
- Host/service link columns top-align and size independently. Long identities
  wrap within chips/pickers. Unlink is a compact ghost icon with unlink symbol,
  target-specific accessible label, and hover title. Linking requires a selected,
  available target using native validation/selection guards; errors explain how
  to select another target or reload stale choices.
- Creation is a compact dialog: kind, identity, concealed secret, and discovery
  notes first; optional associations expand below. Require a username or secret.
  Save credential and links transactionally: invalid/out-of-scope targets create
  nothing. Apply shared dirty/save guards to both Create and Edit.
- Association controls mount on first expansion and stay mounted when collapsed,
  preserving submitted choices. Host search retains selections and resets its
  50-row pagination to page one. Unchecking a host clears its selected services.
  Mount only current-page and selected host rows; hidden selected off-page rows
  retain service loads, retry state, and submitted links.
- Saving waits for selected hosts' services. Loading can be cancelled; failures/
  cancellations remain visible with Retry or deselect recovery. Stale loads cannot
  repopulate removed/retried targets or overwrite the current attempt.

## Operations

- Use a compact-list workbench beside full command, output, metadata, tags,
  notes, and attachment download; reading evidence does not open editing. Omit
  absent metadata but keep Start/End and From/To labels, commands, tags, and
  attachment access. Command copy gives visible success/failure feedback.
- Search and Add operation share a bottom-aligned toolbar without standalone
  filter/header margin offsets. Add/Edit keep their forms; confirmed deletion
  remains in Edit. Both protect changed drafts, including calendar/attachment
  changes, through the shared dirty/save guards.
- `#operation-ID` survives reload/history. With no explicit selection, choose the
  first record; an explicit selection absent after filtering, paging, or deletion
  shows unavailable guidance to select a record or adjust search/page, rather than
  silently substituting another operation. Search/pagination remain server-side,
  URL-backed; the page-size control appears only in pagination.
- Timestamps use shadcn Calendar/Popover: day selection closes the calendar;
  Clear date omits the timestamp. Time is shadcn Input `type="time"`, letting
  browser/system choose 12/24-hour display, without custom hour/minute selectors.
  Date/time stack below 640px to contain selected dates/calendar icons. Date
  buttons expose visible text as their accessible name in Started/Ended fieldsets.

## Scans

- Import controls sit above a bounded, internally scrolling history table with
  sticky headings; compact layouts scroll import controls independently as needed.
  Keep import-safety guidance available to screen readers. Comparisons group the
  difference count with the result heading and use filenames as secondary metadata.
- History filenames wrap in a minimum 12rem column; narrow screens retain table
  horizontal scrolling without text painting over adjacent values. Invalid nmap/
  Amass content returns HTTP 400 with format-specific correction guidance; retain
  the selected file for correction/replacement and retry.
- History and comparison results use the shared URL-backed Rows/Page and
  Previous/Next controls, defaulting to 25 rows. History keeps pagination outside
  the internally scrolling table. Counts describe the entire result, not the
  current page. Comparing a new pair resets to page one and retains Rows;
  paging retains the selected pair. Both scan selectors include all imports.

## Runtime boundary

FastAPI document routes return the HTML shell regardless of `Accept`, embedding
only escaped engagement ID/name navigation bootstrap in a non-executable JSON
script. Domain reads, refreshes, and mutations use `/api`; there is no bootstrap
endpoint. The browser never writes SQLite directly. No remote scripts/fonts/CDN
stylesheets or Node server are required at runtime.
