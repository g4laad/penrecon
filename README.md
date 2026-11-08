# penrecon

Single-user, local pentest recon manager. Ingest nmap XML and Amass exports,
browse hosts/services, diff two scans, keep your own notes/tags, and manually
record the commands and actions behind an engagement. FastAPI + React +
shadcn/ui (Base UI), SQLite, no auth — binds to `127.0.0.1`.

## Run

```sh
uv sync
npm --prefix frontend ci
npm --prefix frontend run build
uv run penrecon serve          # http://127.0.0.1:8000
uv run penrecon engagements create "Example engagement"
uv run penrecon engagements list
uv run penrecon ingest scan.xml --tool nmap --engagement <uuid>
```

Data (SQLite db + attachments) lives under `./data` — override with
`PENRECON_DATA=/path`.

Open `/engagements` to create or select an engagement. The header selector switches
to the selected engagement's host inventory. Browser workspace URLs start with
`/<uuid>/`; API requests use `?engagement_id=<uuid>` instead. Separate tabs can
work on different engagements independently.
Upload files from the selected engagement's Scans page. Use the sidebar's
Scans and Scan diff entries to switch between import history and comparisons.

Scan parsing, database writes, retained-file I/O, and projection maintenance run
in a worker-owned session, not on the HTTP event loop. Request cancellation waits
for commit or rollback/cleanup rather than abandoning an import in progress.
Uploads remain bounded; disk-backed request spooling also runs off the event loop.
SQLite uses WAL mode, FULL synchronous durability, and a 30-second lock timeout.
Readers can retain their snapshots during imports; writes are still serialized.
WAL is enabled during initialization, not on each request connection. Use local
storage compatible with SQLite WAL and back up the entire data directory with
the app stopped, including any `-wal` and `-shm` files.

Hosts pagination updates the inventory in place without reloading the page.
The URL tracks the current page, including browser Back and Forward navigation.

One shared SQLite database stores all engagements. Hosts, hostnames, services,
scans, notes, triage, credentials, and operations are engagement-owned; the same
IP or hostname can exist independently in multiple engagements. Search, exports,
and scan comparisons are restricted to the engagement selected in the request. Composite
foreign keys reject relationships between engagements.

Retained files live under `data/engagements/<uuid>/scans/` and
`data/engagements/<uuid>/operation-attachments/`; stored paths are relative to
the data directory. Credentials are not shared across engagements.

**Development schema reset:** no migrations or database portability work is
included. An existing pre-engagement database is incompatible. Stop the app and
choose a fresh `PENRECON_DATA` directory, or back up the existing directory and
manually reset its database. Re-ingesting scans does **not** restore notes,
credentials, manual edits, or operation logs. Startup never deletes or migrates
your data automatically.

Host timelines and inventory projections add tables on startup; existing
engagement-aware databases do not need a reset. Startup backfills missing
scan-state and per-host scan-difference projections from retained evidence,
including legacy raw scans, without rewriting original records. Effective
services, host summaries, and exact tag membership are then materialized from
that state. Indexed timeline metadata is backfilled from existing scan deltas
and immutable manual events without replaying complete scan history. Adding these
read-model tables never alters existing tables or source records. The first startup
after upgrading may take longer; complete projections are not rebuilt on later startups.

Evidence writes replay affected hosts' scan histories in the same transaction,
including when older scans arrive or scans are deleted. Replay batches source
reads once per engagement; unrelated hosts keep their persisted deltas. The
engagement-relative "new" marker is refreshed separately. Legacy scan changes
and host identity changes can still require an engagement-wide replay.
Completed imports record an additive evidence-completeness marker: absent hosts
are not recovered from their retained raw bytes, including after a host is
deleted and recreated. Unmarked legacy scans retain raw recovery.
Inventory projections are rebuilt in the same transaction; manual service edits,
triage, and hostname changes rebuild only inventory, not scan history.
This deliberately spends more work on writes: host and service tables filter,
sort, count, and paginate in SQLite before loading page payloads.
Steady host/service table reads do not decode observation snapshots or replay history.
Manual service overrides remain separate and take precedence over scan state;
notes, triage, and credentials are never rewritten by projection maintenance.
Manual service actions are recorded going forward, not reconstructed from
existing inventory.
Timeline ordering timestamps and change visibility are maintained transactionally
in `host_timeline_entry`, with separate indexes for all events and changes only.
Manual actions refresh timeline metadata without rebuilding inventory or replaying
scan history. Scan differences and manual snapshots remain the authoritative payloads.

Requires Node.js 22.12+ for the frontend build. FastAPI serves the generated
assets locally from `src/penrecon/web/static/ui`; no CDN or separate Node
server is needed at runtime. Rebuild before serving or packaging a wheel.
Host details, credentials, scans/diffs, and operations load their JavaScript
on demand; the navigation shell stays visible while a page loads.
The Markdown renderer loads when a saved note is displayed; opening a host's
Services tab does not download it. The note editor loads when its form opens.

## Nix

With flakes enabled, build the application or run it directly:

```sh
nix build
PENRECON_DATA="$HOME/.local/share/penrecon" nix run . -- serve --port 8765
```

Open `http://127.0.0.1:8765`. The package includes the built frontend and
Python 3.14 environment; Node.js and uv are not needed at runtime.
`flake.lock`, `uv.lock`, and `frontend/package-lock.json` pin the build inputs.
Nixpkgs follows the stable NixOS 26.05 release.
Supported systems are `x86_64-linux` and `aarch64-linux`.
When building a Git checkout, new Nix files must be tracked by Git.

For development, `nix develop` provides Python 3.14, uv, and Node.js 24.
Then use the commands in **Run** above. After changing frontend dependencies,
update `npmDepsHash` in `flake.nix` to the hash reported by Nix when rebuilding.
Use `nix flake update` to update the Nix inputs deliberately.

### NixOS service

Add this repository to your system flake's inputs:

```nix
inputs.penrecon.url = "github:g4laad/penrecon";
```

Include its module in your `nixosSystem` configuration:

```nix
modules = [
  inputs.penrecon.nixosModules.default
  {
    services.penrecon = {
      enable = true;
      port = 8765;
    };
  }
];
```

Apply with `sudo nixos-rebuild switch`, then inspect
`systemctl status penrecon` or `journalctl -u penrecon`.
The service runs as a dynamic unprivileged user, retains its database and
attachments in `/var/lib/penrecon`, and listens only on loopback. No firewall
port is opened. Stop the service before backing up the entire state directory;
do not copy only the SQLite file. Removing the service does not remove its data.

There is no authentication. For remote access, use an SSH tunnel instead of
exposing the service:

```sh
ssh -N -L 8765:127.0.0.1:8765 user@server
```

## Docker (distroless)

Docker Engine with the Compose plugin is sufficient. A Nix builder uses the
locked flake to build both the frontend and Python environment; no host Nix
installation or `dockerTools` is required:

Base image references are registry-qualified so Podman does not need
short-name aliases or an unqualified-search registry configuration.

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f penrecon
```

Open `http://127.0.0.1:8000`. To use another host port:

```sh
PENRECON_PORT=8765 docker compose up --build -d
```

The final `distroless/base-debian13:nonroot` image contains the Nix application's
runtime closure under `/nix/store`, exposed at `/app`, and runs as UID/GID
`65532:65532`. Nix, its database, Node.js, npm, uv, and compilers stay in the
builder. This is not a shell-free image: Nix's Python runtime depends on Bash,
which is retained in the closure even though it is not on `PATH`.
Compose drops all capabilities, prevents privilege escalation, and makes the
root filesystem read-only; `/tmp` is a temporary writable filesystem.

The app listens on all interfaces **inside** the container; Compose publishes
it only on host loopback. There is no authentication: do not change the host
binding to `0.0.0.0` or expose it through an unauthenticated proxy. Forwarded
proxy headers are disabled in the container command.

The `penrecon-data` named volume stores the database, retained scans, and
attachments under `/data` (`PENRECON_DATA` in the image). It survives container
rebuilds and `docker compose down`. **`docker compose down --volumes` deletes
this data.** Local `./data` is neither copied into the image nor automatically
imported. If replacing the volume with a bind mount, make the directory
writable by UID/GID `65532:65532` first.

Upload scans through an engagement's Scans page, or run the CLI without a shell:

```sh
docker compose run --rm -v "$PWD/scan.xml:/input/scan.xml:ro" \
  penrecon -m penrecon ingest /input/scan.xml --tool nmap --engagement <uuid>
docker compose exec penrecon /app/bin/python3.14 -m penrecon --help
```

For a consistent backup, stop the app before copying the entire data directory
(not just the SQLite file), then restart it:

```sh
docker compose stop penrecon
docker compose cp penrecon:/data ./penrecon-backup
docker compose start penrecon
```

Without Compose:

```sh
docker build -t penrecon:local .
docker run -d --name penrecon -p 127.0.0.1:8000:8000 \
  --mount source=penrecon-data,target=/data \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true penrecon:local
```

## Mock-data test mode

Create a separate test database, then serve it using the same data directory:

```sh
PENRECON_DATA=./data-test uv run penrecon seed
PENRECON_DATA=./data-test uv run penrecon serve --port 8765
```

Open `http://127.0.0.1:8765` and select one of the ten generated engagements,
named **Mock engagement 01** through **Mock engagement 10**. Each receives at
least 100 hosts, hostnames, services, scans, observations, notes, credentials,
operation logs, and their relationships. Every host and service
has a triage annotation. Each scan has retained nmap XML, and each operation
has a downloadable text attachment.
Manual-service events start empty until services are changed through the UI.

The first host, `198.18.0.1` (`host-00001.mock.test`), has five open ports:
TCP 22 (SSH), 80 (HTTP), 443 (HTTPS), 5432 (PostgreSQL), and UDP 53 (DNS).
Other hosts vary in status, service state, product, and credential kind.

Open that host's **Timeline** tab for four change groups across 28 daily scan
snapshots: an initial HTTP/HTTPS baseline, HTTP closing, HTTP reopening with a
version change while HTTPS becomes filtered and SSH appears, then the final
five-open-port snapshot. Enable **Show unchanged scans** to exercise two pages
of history, including a 443-only partial scan, a zero-port sighting, and repeated
unchanged results. Missing ports never become closed solely because they were
omitted. Mock XML and stored evidence use the same realistic scan timestamps.
Existing mock engagements are not modified; run `seed` again to create new
engagements with these timelines.

Use `seed --count 250` for a larger dataset (minimum 100, maximum 131070 per
type **per engagement**). Every invocation creates ten new engagements with
fresh IDs; it never clears, merges, or populates existing engagements. The command
prints each new engagement's UUID and row counts. It does not accept an
`--engagement` argument. Normal `serve` does not generate data.

All records are synthetic: IPs use the benchmark-only `198.18.0.0/15` range,
hostnames end in `.mock.test`, and secrets are labeled as mock values.
Displayed commands are examples only; seeding executes no scans or network
requests. Omit `PENRECON_DATA` when returning to your normal `./data` database.

## What it does

- **Ingest** nmap `-oX` XML and Amass hostname/IP exports via web upload or CLI.
  Each ingest retains the original file; service observations are immutable.
- **Merge, latest-wins**: current host/service state is the newest observation
  per `(host, port, proto)`; a web-tool scan never erases port data. Hosts are
  keyed by IP, with hostnames linked.
- **CSV export** streams engagement-scoped current inventory from the maintained
  host/service projections, with bounded database fetches and roughly 64 KiB
  output chunks (a single large row can exceed that). Hosts without services
  remain included; manual overrides, visible hostnames, host triage, and
  spreadsheet-formula escaping are preserved.
- **Diff** any two scans: added / removed / changed ports and versions.
- **Host timeline**: open a host's Timeline tab (`#timeline`) for newest-first
  scan groups and manual service actions, expandable before/after changes, and a latest-change
  link beside the host heading. Changes are shown by default; include unchanged
  scans or page through history without changing service filters.
  Timeline controls refresh JSON in place without reloading the page. The
  unchanged-scans toggle retains focus and scroll position; pagination and browser
  Back/Forward keep the URL and displayed history synchronized. Failed updates
  retain existing results and offer Retry.
  SQLite filters, counts, orders, and paginates indexed timeline metadata before
  loading at most 20 entry payloads plus the latest changed entry. Reads do not
  decode JSON timestamps, sort the entire history, or load current observation
  snapshots. Existing databases receive an additive table and automatic backfill.
  Scan execution time orders history when available; otherwise import time is
  explicitly labeled. Current service state uses the same ordering, so importing
  an older scan does not overwrite newer scan evidence. Host first/last-seen
  timestamps retain their existing import-time meaning.
  Missing ports are “not reported,” never assumed closed. Explicit states and
  unambiguous nmap coverage/aggregate results can establish closure or filtering;
  ambiguous results remain unknown. TCP and UDP are separate identities.
  Manual additions, edits, removals, and setting/resetting overrides are explicitly
  labeled with action timestamps. Removal retains history and means removed from
  inventory, not a confirmed closed port. Effective values and override changes
  are recorded atomically with each action, including when setting an override
  leaves the effective value unchanged. No-op saves and annotation-only edits
  produce no service events. Manual events remain visible with unchanged scans
  hidden. Earlier manual actions cannot be reconstructed; notes, triage, and
  credentials are not service-history events.
  Legacy raw files recover scan time, coverage, and zero-port sightings where
  available; missing/corrupt raw falls back to existing observations with unknown
  coverage and import time. Unrecoverable zero-port sightings cannot be reconstructed.
  Scan diff “removed” still means absent from that scan, not confirmed closed.
- **Annotate**: host notes use a syntax-highlighted Markdown editor with formatting
  shortcuts, Write/Preview/Split views, and an expandable workspace. Saved notes
  render tables, task lists, and copyable code blocks using the same preview.
  Unsaved notes warn before dismissal or leaving the page; failed saves retain
  the draft. HTML displays as text, unsafe links are blocked, and images appear
  as source links without automatic remote fetching. Markdown source, status,
  and tags persist across re-scans; ingest never touches them.
- **Manual services**: manually edited services show a “Manual” pill to the right
  of the service name in the host's services table.
- **Credentials**: store secrets and link them to hosts and services. Secrets
  start masked on both the credentials and host pages, with eye and copy icons
  to reveal/hide or copy them. Linked credentials show username and secret side
  by side on the host page. Unlinking a host also unlinks that credential from
  all services on that host; the credential and its links to other hosts remain
  intact.
  The credentials page uses a searchable identity list with a detail pane for
  the selected secret, full notes, and link management. Filter by username,
  notes, IP/service, kind, or linked/unlinked scope; secret values are excluded.
  Filters, pagination, and selection are bookmarkable. Lists default to 25 rows;
  choose 10, 25, 50, or all. SQL filtering and pagination precede summary loading,
  and association counts are loaded only for the selected page. List responses
  contain at most 160 characters of notes; search still checks full notes and
  linked host/service data, never secrets, with Unicode substring matching.
  Full notes, secrets, and linked associations load for the selected credential.
  Host and service choices load only when their link controls open; service
  choices have their own filter and pagination. Off-page credential bookmarks
  load detail independently without changing the list filters.
  Engagement-wide search matches credential usernames and notes, but returns only
  credential IDs, kinds, usernames, and linked-host IDs/IPs. Secrets, full notes,
  timestamps, service associations, and service-picker data stay out of search
  responses, including the initial HTML page data.
  During creation, selecting a host loads its services. A failed load blocks
  saving until you retry successfully or deselect the host; retrying clears the
  error and shows loading while saving remains disabled.
- **Operation log**: manually create, review, edit, search, and delete timeline
  entries for commands and operator actions, with one replaceable attachment
  per entry. penrecon does not execute commands or capture terminal history.
  Start and end timestamps use shadcn calendar popovers and styled native time
  inputs; the browser/system chooses 12- or 24-hour display. A selected date
  defaults to midnight; use Clear date to omit that timestamp.
  Pages contain operation summaries; selecting an entry loads its full output,
  comments, timestamps, and attachment metadata separately. Search still matches
  full output and comments without including those bodies in list responses.
  Filtering, counts, ordering, and pagination run in SQLite before summaries are
  loaded. Pages clamp to the matching range; `per=all` returns all matches.

## Workflow guarantees

- **Mutation outcomes:** forms distinguish rejected input, an unconfirmed save,
  confirmed save/reconciliation, and a confirmed save whose view refresh failed.
  Confirmed-save recovery only refreshes the view; it never repeats the mutation.
  Unconfirmed requests keep the draft locked until you check current data or
  explicitly return to editing, because the earlier request may have committed.
- **Drafts:** editing modals protect unsaved changes by default, including
  incomplete timestamp drafts and attachment choices. Closing is blocked during
  submission/reconciliation. Intentional filter navigation is not a draft save.
  Successful reconciliation commits the new page data before resetting forms.
  Failed saves and failed refreshes do not reset drafts.
  Credential and operation editors keep their own draft snapshots while recovery
  reloads lists and read-only details, even if the edited record leaves the
  current filter. Checking current data preserves the locked draft and never
  repeats its mutation; returning to editing remains an explicit decision.
- **Request ownership:** query navigation, viewport-sized host loading,
  credential service loading, selected credential/operation details, and clipboard
  feedback reject stale completions. New navigation supersedes older requests.
  Detail failures offer Retry; successful mutations invalidate and reload the
  selected detail. JavaScript lazy-load failures offer page reload.
- **Selections:** unavailable credential/operation hashes show recovery instead
  of another record. Host inspectors commit their fallback selection, so an old
  selection does not reappear unexpectedly when filters or pages change.
  Empty timeline pages retain the filter and offer navigation back to page one.
- **Credential associations:** selected hosts/services survive filtering,
  pagination, and closing the association disclosure. Each selected host has an
  explicit loading/ready/error/cancelled lifecycle with retry or deselection.
  Submission checks readiness as well as a nonempty username or secret.
  Create and edit enforce the same identity requirement on the server. Linking a
  service without its host link is rejected; unlinking a host removes dependent
  service links without deleting the credential.
- **Import persistence:** parsing and staging precede raw-file retention and
  commit. Pre-commit failure rolls back inventory and removes partial raw files;
  cleanup failures preserve the original error. Unique retained filenames avoid
  overwriting earlier bytes. Duplicate hosts in one import merge deterministically;
  conflicting coverage does not invent closure. All six nmap port states survive
  in both stored observations and current/history views.
- **Operation attachments:** keep, replace, and remove are distinct intents.
  Cancelling removal restores the previous replacement choice. New files are
  compensated on rollback; old files are removed only after metadata commits.
  If obsolete-file cleanup fails after commit, the operation remains saved and
  the interface reports cleanup pending instead of offering to save again.
  Mixed timezone-aware/naive timestamp pairs are rejected; aware pairs are
  normalized to UTC for storage.

These workflows do not change the evidence rules: omitted ports retain their
last known state indefinitely, manual overrides take precedence until reset,
hidden hostname associations stay hidden, and later explicit scans can recreate
deleted services. Status and credential-kind labels remain freely editable
classifications, not required progressions. Operation logs record commands;
they do not execute them.

## Amass imports

For Amass v5 (including v5.1.3), export discovered names with their IP addresses
from an existing enumeration database:

```sh
amass subs -d example.com -names -ip -nocolor -o amass.txt
uv run penrecon ingest amass.txt --tool amass --engagement <uuid>
```

Alternatively, upload the export on the engagement's Scans page with **amass** selected.
The text format is one hostname followed by comma-separated IPv4/IPv6 addresses:

```text
www.example.com 192.0.2.10,2001:db8::10
api.example.com 192.0.2.10
```

Legacy Amass `enum -json` output is also supported: JSONL, a single JSON object,
or an array of objects containing `name` and `addresses: [{"ip": "..."}]`.
Duplicate IPs and names are merged; IPv6 addresses and hostname case/trailing
dots are normalized. Imports add no services and preserve existing port data,
notes, and credentials. No DNS lookups are performed.

Names-only text files and files with no IP mappings are rejected because hosts
are keyed by IP. Unresolved JSON records are skipped when other records contain
IP mappings. Amass graph/OAM exports and summary/log output are not supported;
use the export command above rather than `-show` or `-summary`.

## Adding a parser

Parsers live in `src/penrecon/parsers/` and register in `PARSERS`. Each is a
`fn(bytes) -> ScanResult`. Only nmap and Amass are currently supported. To add
another tool, implement its parser in a new module and register it in `PARSERS`.

## Dev

```sh
uv run pytest
uv run mypy src/penrecon
```

For frontend work, run `npm --prefix frontend run dev` alongside FastAPI.
This watches and rebuilds the local bundle; refresh the browser after changes.
Bundle URLs are versioned on rebuild so a normal refresh loads the updated
layout instead of reusing stale JavaScript or CSS.
`npm --prefix frontend run build` checks TypeScript and produces release assets.

GitHub Actions runs on pushes, pull requests, and manual dispatches. The workflow
in `.github/workflows/ci.yml` installs locked dependencies, runs pytest and mypy,
checks TypeScript and builds the frontend, then packages a wheel and smoke-tests
its installed CLI. CI uses Python from `.python-version` and Node.js 22.
A separate Ubuntu job builds the Nix package from the locked flake inputs and
smoke-tests its CLI.

React source lives in `frontend/src`. Shared components are shadcn/ui's
`base-nova` style, backed by `@base-ui/react`, with Tailwind CSS 4 and Lucide
icons. Add components with `npx shadcn@latest add <component> -c frontend`.
Browser URLs return only the React shell and a slim ID/name navigation bootstrap.
This navigation data is embedded only in HTML; there is no `/api/bootstrap`
endpoint. API clients can list engagements through `GET /api/engagements`.
Domain reads and mutations live exclusively under `/api`, independently of
`Accept`; the old browser URLs no longer accept mutations or return JSON.
The frontend loads initial data from the API, then refreshes affected resources.
Successful mutations return `{"ok": true}`, plus a **document** `redirect_to`
when navigation is needed. No API mutation issues an HTTP redirect. A failed
refresh never repeats an already committed mutation; attachment cleanup failures
retain their committed-success notice.

Scoped endpoints take the required `engagement_id` **query parameter**, never a
path segment: `/api/hosts/12?engagement_id=UUID`. Missing or empty scope returns
422; an unknown engagement returns 404. The query selects the scope for reads,
mutations, and downloads; body fields cannot override it. Engagement metadata
edits use `PUT /api/engagements?engagement_id=UUID`; catalog listing and
creation remain unscoped. Browser navigation uses `/UUID/...` URLs so each tab
retains its own engagement. Old `/api/e/...` and redundant `/api/data/...`
endpoints are removed, not aliased.

### Mutation methods

`POST` creates resources or imports scans. `PUT` replaces the complete editable
record: omitted optional form fields reset to their documented defaults, rather
than retaining old values. Immutable evidence, identities, and separately linked
resources are not replaced. `PATCH` changes only the specified part; `DELETE`
removes a resource or association. The HTTP verb is `PATCH`, not `PATH`.
Action suffixes (`/edit`, `/delete`, `/link`, `/unlink`) are no longer API routes.

| Method | API resource | Behavior |
| --- | --- | --- |
| `PUT` | `/engagements` | Replace name and description |
| `PUT` | `/services/{id}` | Replace all editable overrides, status, and tags; blank overrides restore scan values |
| `PUT` | `/credentials/{id}` | Replace kind, username, secret, and notes; links are separate resources |
| `PUT` | `/notes/{id}` | Replace title and Markdown body |
| `PUT` | `/operations/{id}` | Replace editable log fields; attachment uses explicit keep/replace/remove intent |
| `PUT` | `/annotation` | Replace host status and tags; `host_id` identifies the annotation |
| `PATCH` | `/hosts/{id}` | Rename the IP without changing notes, services, or triage |
| `PATCH` | `/credentials/{id}/hosts`, `/credentials/{id}/services` | Add the selected association without replacing existing links |
| `DELETE` | `/hosts/{id}`, `/services/{id}`, `/credentials/{id}`, `/notes/{id}`, `/operations/{id}` | Delete the selected resource |
| `DELETE` | `/hosts/{id}/hostnames/{hostname_id}` | Hide this host's hostname association |
| `DELETE` | `/credentials/{id}/hosts/{host_id}`, `/credentials/{id}/services/{service_id}` | Remove the selected association |

All rows require the `engagement_id` query parameter and mutation request header.

### OpenAPI and local security

`GET /openapi.json` describes the complete API, including nested response models,
form inputs, validation/domain errors, upload fields, and download media types.
Swagger UI is at `/docs` and ReDoc at `/redoc` (their UI assets require internet
access). In Swagger's Authorize dialog, set `LocalRequest` to `1`.

Keep the server on loopback. This remains a single-user local application, **not
an authenticated multi-user or network service**. The custom request header is
browser request protection, not a password. Exposing the server requires an
authenticating reverse proxy and an explicit deployment/security review.

- Accepted Host names: `localhost`, `127.0.0.1`, `[::1]`; `testserver` is reserved
  for the test client. Arbitrary DNS names are rejected to resist DNS rebinding.
- All mutations require `X-Penrecon-Request: 1`. Browser cross-origin API requests
  are rejected; no permissive CORS policy is installed. CLI clients may omit Origin.
- Every resource lookup and association validates engagement ownership; foreign
  IDs return 404. Import never changes operator notes, triage, or credentials.
- API and HTML responses use `Cache-Control: no-store`; validation errors omit
  raw inputs. Downloaded attachments are inert `application/octet-stream` with
  attachment disposition and `nosniff`; stored paths never leave the API.
- Uploads are limited to 32 MiB each and total bodies to 33 MiB, including
  chunked requests before form parsing. Attachment transactions retain rollback
  cleanup and never report an already committed edit as an uncommitted failure.

Inputs intentionally remain standard URL-encoded forms, or multipart forms for
uploads. This keeps the existing human-readable contract without custom request
decoding. For example:

```sh
curl -H 'X-Penrecon-Request: 1' -d 'name=Example' \
  http://127.0.0.1:8000/api/engagements
curl -H 'X-Penrecon-Request: 1' -F 'tool=nmap' -F 'file=@scan.xml' \
  'http://127.0.0.1:8000/api/scans?engagement_id=ENGAGEMENT_ID'
```

The API composition and error policy live in `web/app.py`; shared contracts and
engagement validation in `web/common.py`; HTTP protections in `web/security.py`.
Domain routers are `web/engagements.py`, `web/inventory.py`,
`web/credentials.py`, `web/evidence.py`, and `web/operations.py`.
`web/pages.py` owns only HTML delivery. Persistence and domain transitions stay
in the query package, command, ingestion, history, and projection modules.
Scoped JSON reads use these resource URLs; append `engagement_id=UUID` to every
request (alongside any filter or pagination parameters):

| URL below `/api` | Response |
| --- | --- |
| `/hosts` | Inventory rows, counts, pagination, filters, sort state, and statuses |
| `/hosts/{host_id}/services` | Service rows and service-table state |
| `/hosts/{host_id}/timeline` | Host timeline only |
| `/operations` | Paginated operation summaries and query state |
| `/credentials?filter=…&kind=…&scope=…&page=…&per=…` | Credential summaries, total/matched counts, pagination, and filter state |
| `/credentials/{cred_id}` | Selected credential, including secret, full notes, and linked associations |
| `/credentials/{cred_id}/options/services?q=…&page=…&per=…` | Available services on linked hosts, excluding existing links, with count and pagination |
| `/operations/{operation_id}` | Selected operation, including output, comments, and attachment metadata |
| `/options/hosts` | Host ID/address pairs |
| `/options/hosts/{host_id}/services` | Service ID, port, protocol, and name |

Credential detail, list, and service-option responses, and operation detail
responses, are engagement-scoped JSON with `Cache-Control: no-store`; missing
or foreign-engagement detail/option IDs return 404. Credential pagination
defaults to 25 rows and accepts 10, 25, 50, or `all`; out-of-range pages clamp.
Credential list `total` counts all engagement credentials and `matched` counts
the filtered set. Service-option `total` counts matching available services.

Query navigation keeps document URLs in browser history and merges resource
responses into existing state, preserving unrelated host sections and navigation.
Back/Forward restores the affected sections; failed requests retain the previous
view and offer Retry. Mutation refreshes still reload full page context once.
HTML contains no inventory rows, notes, or secrets; initial API loading precedes
page rendering. Credential selectors load host options separately and service
options only for selected hosts, with cancellation and retry.
Page-data responses project only consumer-facing fields: storage paths,
engagement ownership columns, and query-only filtering metadata stay server-side.
Row-count choices live in the frontend; responses do not include
`per_page_choices`. Host selectors use ID/address pairs, and host credential
responses include only associations for that host. Database models retain their
full metadata for internal queries and persistence.

### Backend module layout

Backend modules live under `src/penrecon/`. Query callers import the responsible
submodule directly; `queries/__init__.py` intentionally exports nothing.

| Module | Responsibility |
| --- | --- |
| `queries/inventory.py` | Effective host/service views, filtering, sorting, and inventory pagination |
| `queries/credentials.py` | Credential summaries, details, associations, and service options |
| `queries/annotations.py` | Triage annotations, host notes, and note search |
| `queries/operations.py` | Operation-log search and pagination |
| `queries/diff.py` | Immutable scan comparisons |
| `queries/search.py` | Engagement-wide search composition |
| `queries/export.py` | Streaming CSV rows and spreadsheet-formula protection |
| `queries/ownership.py` | Engagement-scoped entity lookup |
| `queries/pagination.py` | Shared page bounds, row limits, and sort defaults |
| `projections.py` | Transaction hooks, invalidation, read preparation, and startup backfill |
| `scan_projection.py` | Affected-host scan-state and delta rebuilding |
| `inventory_projection.py` | Effective service, host-summary, and tag rebuilding |
| `timeline_projection.py` | Indexed timeline ordering and visibility metadata |
| `history.py` | Scan-evidence replay and unified scan/manual timelines |
| `models.py`, `db.py` | SQLModel tables, engine configuration, and initialization |
| `ingest.py`, `parsers/` | Scan ingestion and tool-specific parsing |
| `inventory.py`, `commands.py` | Identity/link transitions and validated operator mutations |
| `web/` | HTTP routing, request/response contracts, and local security |

Projection rebuilding remains part of the source-write transaction. These module
changes do not alter database tables, endpoint contracts, or stored data.

### Shared feature seams

- `inventory.py` owns canonical identity lookup and hostname-link transitions for
  ingestion and manual edits. Existing primary identities and hidden links survive
  normalization; callers own commits.
- `commands.py` owns validated service override/removal and credential association
  transitions. `history.py` owns explicit/missing/covered scan-evidence replay.
- Inventory and CSV export share the maintained `HostSummary`/`CurrentService`
  projections. Credential queries join narrow `CurrentService` columns directly,
  without decoding scan state or querying once per linked host. Host detail uses
  a host-scoped credential projection, never other-host links or picker pools.
- The web layer binds service-table state for reads and operation input once for
  create/edit. Operation validation remains inside the handler, after ownership
  and attachment-conflict checks.
- `components/credential-fields.tsx` supplies both credential editors, including
  masked, kind-aware secret controls and multiline notes.
- Frontend page workflow modules own host selection/commands, credential
  association readiness, and operation timestamp/attachment transitions.
  `common.tsx` owns modal and mutation outcomes; `App.tsx` owns query/request
  reconciliation and viewport inventory loading. Shared clipboard ownership
  lives in `components/use-clipboard.ts`.
