# penrecon

Single-user, local pentest recon manager: import nmap XML and Amass exports,
browse and search hosts/services, compare scans, keep notes/tags and linked
credentials, and manually log engagement commands/actions. FastAPI serves a
React + shadcn/ui (Base UI) frontend over SQLite. There is **no authentication**;
keep access on loopback. penrecon does not run scans, execute logged commands,
or capture terminal history.

## Run locally

Requires Python 3.14+ and Node.js 22.12+ for the frontend build:

```sh
uv sync
npm --prefix frontend ci
npm --prefix frontend run build
uv run penrecon serve                         # http://127.0.0.1:8000
```

In another terminal, create an engagement and import evidence (replace `UUID`
with the printed engagement ID):

```sh
uv run penrecon engagements create "Example engagement"
uv run penrecon engagements list
uv run penrecon ingest scan.xml --tool nmap --engagement UUID
```

Open `/engagements` to create/select an engagement; upload evidence from its
**Scans** page and compare imports through **Scan diff**. Browser workspace URLs
start with `/UUID/`, so separate tabs can use different engagements. API scope
instead uses `?engagement_id=UUID`.

`serve` binds to `127.0.0.1`; use `--port 8765` for another port and `--reload`
for backend development. FastAPI serves generated assets from
`src/penrecon/web/static/ui`; no Node server or CDN is needed at runtime.
Rebuild the frontend before serving changed UI or packaging a wheel.

## Data, backups, and compatibility

`PENRECON_DATA=/path` overrides the default `./data`. This directory contains
`penrecon.db` and retained files under `engagements/UUID/scans/` and
`engagements/UUID/operation-attachments/`. Stored paths are relative to it.
One database holds all engagements, but hosts, hostnames, services, scans,
notes, triage, credentials, and operations are engagement-owned. The same IP
or hostname can exist independently in different engagements; composite foreign
keys reject cross-engagement relationships. Search, export, and diff are scoped.

SQLite uses WAL, FULL synchronous durability, and a 30-second lock timeout.
Readers can keep their snapshots during imports; writes remain serialized.
Use local storage compatible with SQLite WAL. **Stop every process using the
data directory before backing up the entire directory**, including any `-wal`
and `-shm` files; copying only the database is not a complete backup.

General schema migration/database portability is unsupported. In particular,
a pre-engagement database is incompatible: stop the app and choose a fresh
`PENRECON_DATA` directory, or back up the old directory before manually resetting
its database. Reimporting scans does **not** restore notes, credentials, manual
edits, or operation logs. Startup never deletes data or alters existing tables.

Supported additive upgrades are different: startup creates missing scan-state,
inventory, and timeline projection tables and backfills them from existing
evidence/events without rewriting source records. Compatible engagement-aware
databases need no reset for these upgrades. First startup may take longer;
complete projections are not rebuilt on subsequent startups.

## Deployment

### Nix

With flakes enabled:

```sh
nix build
PENRECON_DATA="$HOME/.local/share/penrecon" nix run . -- serve --port 8765
```

Open `http://127.0.0.1:8765`. The package includes built frontend assets and
Python 3.14; Node.js and uv are unnecessary at runtime. `flake.lock`, `uv.lock`,
and `frontend/package-lock.json` pin inputs. The flake uses NixOS 26.05 nixpkgs
and supports `x86_64-linux` and `aarch64-linux`. New Nix files in a Git checkout
must be tracked to enter the build.

`nix develop` supplies Python 3.14, uv, and Node.js 24; then follow the local
commands. After frontend dependency changes, update `npmDepsHash` in `flake.nix`
using the hash reported by Nix on rebuild. Update flake inputs deliberately with
`nix flake update`.

### NixOS service

Add the flake input and module to your system configuration:

```nix
inputs.penrecon.url = "github:g4laad/penrecon";

# In nixosSystem:
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

Apply with `sudo nixos-rebuild switch`; inspect `systemctl status penrecon` or
`journalctl -u penrecon`. The service runs as a dynamic unprivileged user,
stores state in `/var/lib/penrecon`, listens only on loopback, and opens no
firewall port. Removing the service preserves its data. For backups, use
`sudo systemctl stop penrecon`, copy the entire state directory, then
`sudo systemctl start penrecon`.

For remote access, use an SSH tunnel rather than exposing the service:

```sh
ssh -N -L 8765:127.0.0.1:8765 user@server
```

### Docker

Docker Engine plus the Compose plugin is sufficient; the Nix builder builds
both frontend and Python environment without host Nix or `dockerTools`:

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f penrecon
# Alternative host port:
PENRECON_PORT=8765 docker compose up --build -d
```

Open `http://127.0.0.1:8000` (or the chosen port). The app listens on all
interfaces **inside** the container; Compose publishes only on host loopback
and disables forwarded proxy headers. Do not publish on `0.0.0.0` or place it
behind an unauthenticated proxy.

The registry-qualified `gcr.io/distroless/base-debian13:nonroot` runtime runs as
UID/GID `65532:65532`, with the application at `/app` and its runtime closure in
`/nix/store`. Build tools stay in the builder. It is **not shell-free**: Bash is
a Python runtime dependency in that closure, although not on `PATH`. Compose
uses a read-only root, temporary writable `/tmp`, no capabilities, and no
privilege escalation. Registry-qualified base images also avoid Podman
short-name configuration.

The `penrecon-data` volume stores the entire data directory at `/data`. It
survives rebuilds and `docker compose down`; **`docker compose down --volumes`
deletes it**. Local `./data` is neither copied into the image nor imported.
A replacement bind mount must be writable by `65532:65532`.

Upload through Scans, or run the CLI directly without a shell:

```sh
docker compose run --rm -v "$PWD/scan.xml:/input/scan.xml:ro" \
  penrecon -m penrecon ingest /input/scan.xml --tool nmap --engagement UUID
docker compose exec penrecon /app/bin/python3.14 -m penrecon --help
```

Stop the app for a consistent full-directory backup:

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

## Imports, evidence, and export

### Formats

Import nmap `-oX` XML with `--tool nmap`. For Amass v5 (including v5.1.3),
export hostname/IP mappings from an existing enumeration database:

```sh
amass subs -d example.com -names -ip -nocolor -o amass.txt
uv run penrecon ingest amass.txt --tool amass --engagement UUID
```

The Scans upload form supports both tools. Amass text is one hostname followed
by comma-separated IPv4/IPv6 addresses:

```text
www.example.com 192.0.2.10,2001:db8::10
api.example.com 192.0.2.10
```

Legacy Amass `enum -json` output is accepted as JSONL, one object, or an array
with `name` and `addresses: [{"ip": "..."}]`. Imports normalize IPs and hostname
case/trailing dots, merge duplicates, perform no DNS lookups, and add no
services. Names-only text or files without IP mappings are rejected; unresolved
JSON records are skipped if other records contain mappings. Graph/OAM exports,
logs, `-show`, and `-summary` output are unsupported.

### State and history rules

- Hosts are keyed by IP with linked hostnames; service identity is
  `(host, port, protocol)`, so TCP and UDP are distinct. Original files are
  retained and service observations are immutable.
- Scan execution time orders evidence when available; otherwise import time is
  used and labeled. Importing an older scan does not overwrite newer evidence.
  Host first/last-seen timestamps still describe import time.
- Omission alone means **not reported**, not closed: retain the last known port
  state unless explicit evidence or unambiguous nmap coverage/aggregate results
  establish closure/filtering. Ambiguous or conflicting coverage does not
  invent closure. All six nmap port states survive storage and display.
  Amass imports never erase existing ports. Diff **removed** means absent from
  the compared scan, not confirmed closed.
- Manual overrides win until reset; blank overrides restore scan values.
  Removal preserves service history and means removed from inventory, not
  closed. Later explicit scans can recreate deleted services. Hidden hostname
  associations stay hidden. Ingest/projection maintenance never rewrites notes,
  triage, or credentials; status and credential-kind labels are classifications,
  not required progressions.
- The host **Timeline** tab (`#timeline`) shows newest-first scan groups and
  manual service actions with expandable before/after changes. Changes-only is
  the default; **Show unchanged scans** includes partial/zero-port sightings.
  Setting/resetting an override is an event even if its effective value stays
  the same; no-op saves and annotation-only edits are not. Manual events remain
  visible with unchanged scans hidden. Earlier manual actions cannot be
  reconstructed; notes, triage, and credentials are not service-history events.
- Legacy raw scans can recover execution time, coverage, and zero-port sightings.
  Missing/corrupt raw falls back to observations with unknown coverage and
  import time; lost zero-port sightings cannot be reconstructed. Completed
  imports have an evidence-completeness marker: hosts absent from stored
  evidence are not recovered from raw bytes, even after deletion/recreation.
  Unmarked legacy scans retain raw recovery.

Imports parse/stage before raw-file retention and commit. Pre-commit failure
rolls back inventory and removes partial files; cleanup failures preserve the
original error, and unique filenames prevent overwriting retained bytes.
Duplicate hosts merge deterministically. HTTP import work uses a worker-owned
session; cancellation waits for commit or rollback/cleanup rather than
abandoning the transaction. Request spooling also avoids blocking the event loop.

CSV export streams current engagement inventory, including hosts without
services, effective manual overrides, visible hostnames, and host triage.
Spreadsheet formulas are escaped. Database fetches are bounded; output chunks
are roughly 64 KiB, except that a single larger row can exceed that size:

```sh
curl -o hosts.csv \
  'http://127.0.0.1:8000/api/export/hosts.csv?engagement_id=UUID'
```

## Operator workflows

- **Notes:** Markdown Write/Preview/Split editor with formatting shortcuts and
  expandable workspace; saved rendering supports tables, tasks, and copyable
  code. HTML is text, unsafe links are blocked, and images become source links
  rather than automatic remote fetches.
- **Credentials:** masked by default, with reveal/hide and copy controls;
  searchable identity list plus separately loaded secret/full notes/links.
  Search covers username, full notes, linked IP/service, kind, and linked scope,
  never secrets. List notes are at most 160 characters. Engagement-wide search
  returns only credential ID/kind/username and linked host IDs/IPs, not secrets,
  full notes, timestamps, or service associations. Pagination defaults to 25;
  choices are 10, 25, 50, or all, with out-of-range pages clamped. Off-page
  bookmarks can load detail without changing filters.
- **Credential links:** username or secret is required. Service links require
  their host link; unlinking a host removes its dependent service links, not
  the credential or other-host links. Deleting hosts/services likewise preserves
  credentials. Selected associations survive filtering/pagination/disclosure
  closure. A failed host-service choice load blocks saving until retry succeeds
  or that host is deselected.
- **Operations:** manually record/search/edit/delete commands, output, comments,
  and optional start/end times, with one replaceable attachment. Lists contain
  summaries; detail loads full bodies separately, while search still matches
  full output/comments. Pages clamp; `per=all` returns all matches. A selected
  date defaults to midnight; Clear date omits it. Browser/system settings choose
  12/24-hour display. Mixed aware/naive timestamp pairs are rejected; aware
  pairs normalize to UTC for storage.
- **Attachments:** keep, replace, and remove are distinct intents; cancelling
  removal restores the previous replacement choice. New files are compensated
  on rollback; obsolete files are removed only after metadata commits. Failed
  post-commit cleanup means **saved/deleted, cleanup pending**, not save failure.
- **Recovery:** dirty editors warn before dismissal/navigation and block closure
  while submitting/reconciling. Failed saves/refreshes preserve drafts. An
  unconfirmed request locks the draft until checking current data or explicitly
  returning to editing: the request may already have committed. Checking data
  never repeats the mutation. Confirmed-save refresh failures offer refresh,
  never resubmission; reconciliation commits page data before resetting forms.
  Credential/operation drafts survive recovery even if a record leaves filters.
- **Navigation:** filters/pagination/selections use bookmarkable URLs and support
  Back/Forward without full reloads; stale requests cannot replace newer results.
  Failed query/detail loads retain previous results and offer Retry. Unavailable
  credential/operation selections show recovery rather than a different record;
  host fallback selections are committed. Empty timeline pages retain filters
  and offer page one. Lazy-load failures offer page reload.

Detailed committed UI and accessibility behavior is in [DESIGN.md](DESIGN.md);
product priorities and non-goals are in [PRODUCT.md](PRODUCT.md).

## Mock data

Use an isolated data directory, then serve the same directory:

```sh
PENRECON_DATA=./data-test uv run penrecon seed
PENRECON_DATA=./data-test uv run penrecon serve --port 8765
```

Select **Mock engagement 01** through **Mock engagement 10**. Every invocation
creates ten new engagements with fresh IDs; it never clears, merges, or fills
existing engagements and accepts no `--engagement`. `seed --count 250` increases
rows per type **per engagement** (default/minimum 100, maximum 131070). Output
includes each UUID and row counts; normal `serve` never seeds.

Data includes linked hosts, hostnames, services, scans/observations, notes,
credentials, operations, triage for every host/service, retained nmap XML, and
one downloadable text attachment per operation. Manual-service events start
empty. IPs use benchmark-only `198.18.0.0/15`, names end in `.mock.test`, and
secrets are labeled mock; seeding executes no scans/network requests.

Host `198.18.0.1` (`host-00001.mock.test`) ends with TCP 22/80/443/5432 and UDP 53
open. Its Timeline has four change groups across 28 daily snapshots: initial
HTTP/HTTPS, HTTP closing, HTTP reopening/version change with HTTPS filtered and
SSH appearing, then the final five-port snapshot. Show unchanged scans to see
two pages including partial, zero-port, and repeated results. XML/evidence share
scan timestamps. Rerun seed for new mock engagements rather than modifying old
ones; omit `PENRECON_DATA` to return to the normal `./data` directory.

## API reference

`GET /openapi.json` is the complete route/input/response/error/download reference.
Swagger UI at `/docs` and ReDoc at `/redoc` require internet for their UI assets;
set Swagger's `LocalRequest` authorization value to `1` for mutations.

Browser URLs return only the React shell and engagement ID/name navigation
bootstrap, never inventory rows, notes, or secrets. There is no `/api/bootstrap`;
use `GET /api/engagements`. Domain JSON reads/mutations live exclusively under
`/api`, regardless of `Accept`. Browser URLs do not return JSON or accept
mutations. Removed `/api/e/...`, `/api/data/...`, and `/edit`, `/delete`, `/link`,
`/unlink` action routes have no aliases.

Every scoped read, mutation, and download requires the **query** parameter
`engagement_id=UUID`, e.g. `/api/hosts/12?engagement_id=UUID`; body fields cannot
override it. Missing/empty scope returns 422; unknown engagements and missing or
foreign-engagement resource IDs return 404. Only engagement catalog listing and
creation are unscoped; metadata editing is `PUT /api/engagements?engagement_id=UUID`.

### Requests and results

Mutations require `X-Penrecon-Request: 1` and documented form bodies, not JSON.
The browser sends notes URL-encoded to preserve Markdown newlines; other forms
are multipart, including uploads. Non-file form fields also accept standard
URL encoding:

```sh
curl -H 'X-Penrecon-Request: 1' -d 'name=Example' \
  http://127.0.0.1:8000/api/engagements
curl -H 'X-Penrecon-Request: 1' -F 'tool=nmap' -F 'file=@scan.xml' \
  'http://127.0.0.1:8000/api/scans?engagement_id=UUID'
```

`POST` creates/imports; `PUT` replaces the complete editable record (omitted
optional fields reset to defaults), not immutable evidence/identities or
separately linked resources. `PATCH` changes the specified part; `DELETE`
removes a resource/link. All paths below are relative to `/api` and scoped:

| Method | Resource | Meaning |
| --- | --- | --- |
| `PUT` | `/engagements` | Name and description |
| `PUT` | `/services/{id}` | All overrides, status, tags; blank overrides reset |
| `PUT` | `/credentials/{id}` | Kind, username, secret, notes; links separate |
| `PUT` | `/notes/{id}` | Title and Markdown body |
| `PUT` | `/operations/{id}` | Editable log fields; explicit attachment intent |
| `PUT` | `/annotation` | Host status/tags, identified by form `host_id` |
| `PATCH` | `/hosts/{id}` | Rename IP, preserving notes/services/triage |
| `PATCH` | `/credentials/{id}/hosts`, `/credentials/{id}/services` | Add association, preserving other links |
| `DELETE` | `/hosts/{id}`, `/services/{id}`, `/credentials/{id}`, `/notes/{id}`, `/operations/{id}` | Delete resource |
| `DELETE` | `/hosts/{id}/hostnames/{hostname_id}` | Hide hostname association |
| `DELETE` | `/credentials/{id}/hosts/{host_id}`, `/credentials/{id}/services/{service_id}` | Remove association |

Success returns `{"ok": true}` with optional **document URL** `redirect_to`,
never an HTTP redirect. An operation saved/deleted with obsolete-file cleanup
failure additionally returns `committed: true`, `cleanup_pending: true`, and
`detail`; do not repeat the mutation.

Errors use `{"detail": "..."}` with optional `field_errors` mapping field names
to messages. Validation returns 422 without Pydantic's raw input echo. Other
expected statuses are 400 (invalid domain input/import/Host), 403 (request
protection), 404 (missing/foreign resource), 409 (identity conflict), and 413
(upload/body limit). A transport error, 5xx, or missing success confirmation
may leave a mutation's outcome unknown; inspect current data before retrying.

Credential-link IDs must be positive ASCII decimals at most
`9223372036854775807`; surrounding whitespace is ignored. Malformed, empty,
nonpositive, or oversized IDs return 422; valid but absent/foreign IDs return
404. Server-side credential creation/editing enforces username-or-secret and
host-before-service linking.

### Read resources

Append `engagement_id=UUID` to every path below (plus desired filters):

| GET path below `/api` | Result |
| --- | --- |
| `/hosts`, `/hosts/{id}` | Inventory/table state; selected host detail |
| `/hosts/{id}/services`, `/hosts/{id}/timeline` | Service table; host timeline |
| `/scans`, `/diff?a=ID&b=ID` | Import history; two-scan comparison |
| `/search?q=...`, `/export/hosts.csv` | Engagement search; streamed CSV |
| `/annotation?host_id=ID` | Host triage annotation and status choices |
| `/credentials?filter=...&kind=...&scope=...&page=...&per=...` | Summaries, total/matched counts, filter/page state |
| `/credentials/{id}` | Secret, full notes, linked associations |
| `/credentials/{id}/options/services?q=...&page=...&per=...` | Matching available services on linked hosts, excluding existing links |
| `/operations?q=...&page=...&per=...`, `/operations/{id}` | Summaries/query state; full selected detail |
| `/operations/{id}/attachment` | Inert attachment download |
| `/options/hosts`, `/options/hosts/{id}/services` | Host ID/address pairs; service ID/port/protocol/name |

Credential list `total` counts all engagement credentials; `matched` counts
filtered credentials. Service-option `total` counts matching available services.
Filtering/counting/sorting/pagination happen in SQLite before page payloads
load. Detail and choice data load separately. Responses expose consumer fields,
not stored paths, ownership columns, query-only metadata, or `per_page_choices`;
host credential detail excludes other-host links and picker pools.

### Local security and limits

- This is not an authenticated multi-user/network service. The custom header
  protects browser requests; it is not a password. Prefer SSH tunnels. Network
  exposure requires an authenticating reverse proxy and explicit security review;
  a proxy must preserve the original Host.
- Accepted Host names are `localhost`, `127.0.0.1`, and `[::1]`; `testserver`
  exists for tests. Arbitrary DNS names are rejected against DNS rebinding.
  Cross-origin browser API requests are rejected; there is no permissive CORS.
  CLI clients may omit Origin.
- API/HTML responses use `Cache-Control: no-store`. Attachments download as
  `application/octet-stream` with attachment disposition and `nosniff`; stored
  paths are never exposed.
- **32 MiB per upload, 33 MiB total request body**, including chunked bodies
  before form parsing. Ownership checks apply to every lookup/link/download.

## Development

```sh
uv sync --locked --group dev
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv run --locked pytest
uv run --locked mypy src/penrecon
npm --prefix frontend run build
npm --prefix frontend test
```

For frontend work run `npm --prefix frontend run dev` alongside FastAPI: it
watches/rebuilds assets, not a separate development server. Refresh the browser;
versioned bundle URLs avoid stale assets. `build` checks TypeScript and emits
release assets; `npm --prefix frontend run typecheck` checks types alone.
For preview/test servers, use a port other than 8000 (reserved for the user's
dev server), and rebuild UI before browser verification.

Ruff is pinned in `uv.lock`; rules live in `pyproject.toml`. Apply safe fixes
with `uv run --locked ruff check --fix src tests` and format with
`uv run --locked ruff format src tests`. Preserve the narrow SQLAlchemy
expression and model-initialization import exceptions.

Test observable security/isolation, preservation, rollback, and search/pagination
boundaries rather than repeating happy paths at every layer or mirroring schemas.
Delete/reimport regressions need separate sessions: close the deletion session
before upload because database cascades do not mark loaded ORM children deleted.
Optional coverage is diagnostic, not a 100% target:

```sh
uv run --with pytest-cov pytest --cov=penrecon --cov-branch --cov-report=term-missing
```

`.github/workflows/ci.yml` runs locked Python lint/format/tests/types, frontend
TypeScript/build, wheel packaging/installed-CLI smoke, and a separate locked Nix
build/CLI smoke on push, PR, and manual dispatch. It uses `.python-version`
and Node.js 22; frontend workflow tests are available through the command above.

### Module seams

Backend paths below are under `src/penrecon/`. Import query submodules directly;
`queries/__init__.py` intentionally exports nothing.

| Area | Ownership |
| --- | --- |
| `models.py`, `db.py` | Tables, engine/storage configuration, initialization |
| `ingest.py`, `parsers/` | Shared web/CLI ingestion; `PARSERS` registry of `fn(bytes) -> ScanResult` (nmap/Amass) |
| `inventory.py` | Canonical identity/hostname-link transitions; preserve existing identities/hidden links; callers commit |
| `commands.py` | Validated manual service overrides/removal and credential associations |
| `history.py` | Explicit/missing/covered evidence replay and scan/manual timelines |
| `projections.py` | Transaction hooks, invalidation, startup backfill |
| `scan_projection.py`, `inventory_projection.py`, `timeline_projection.py` | Scan state/deltas; effective service/host/tag inventory; indexed timeline order/visibility |
| `queries/` | Inventory, credentials, annotations, operations, diff, search, export, ownership, pagination in named submodules |
| `web/app.py`, `web/common.py`, `web/security.py` | Composition/errors; HTTP schemas/ownership/navigation; local protections |
| `web/{engagements,inventory,credentials,evidence,operations}.py` | Domain routers; `web/pages.py` owns HTML delivery only |

Source writes maintain projections transactionally. Older imports/deletions
replay affected hosts; legacy/identity changes may require engagement-wide
replay. Manual inventory edits do not replay scan history; manual events update
timeline metadata independently. Inventory and CSV share maintained projections;
steady table reads do not decode observation snapshots or replay history.
Timeline SQL filters/orders/pages metadata before loading at most 20 payloads
plus the latest changed entry; deltas/manual snapshots remain authoritative.

Frontend source is `frontend/src/`, using shadcn/ui `base-nova`, Base UI,
Tailwind 4, and Lucide. Add components with
`npx shadcn@latest add <component> -c frontend`. `App.tsx` owns request/query
reconciliation and viewport inventory loading; `common.tsx` owns modal/mutation
outcomes. Page workflow modules own selection, association readiness, and
operation timestamp/attachment transitions. Shared credential controls are in
`components/credential-fields.tsx`; clipboard ownership is in
`components/use-clipboard.ts`. Feature/editor/Markdown bundles load on demand.
