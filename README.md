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
to the selected engagement's host inventory. Every domain URL starts with
`/e/<uuid>/`; separate tabs can work on different engagements independently.
Upload files from the selected engagement's Scans page. Use the sidebar's
Scans and Scan diff entries to switch between import history and comparisons.

One shared SQLite database stores all engagements. Hosts, hostnames, services,
scans, notes, triage, credentials, and operations are engagement-owned; the same
IP or hostname can exist independently in multiple engagements. Search, exports,
and scan comparisons are restricted to the engagement in the URL. Composite
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

Requires Node.js 22.12+ for the frontend build. FastAPI serves the generated
assets locally from `src/penrecon/web/static/ui`; no CDN or separate Node
server is needed at runtime. Rebuild before serving or packaging a wheel.
Host details, credentials, scans/diffs, and operations load their JavaScript
on demand; the navigation shell stays visible while a page loads.
The Markdown renderer loads when a saved note is displayed; opening a host's
Services tab does not download it. The note editor loads when its form opens.

## Docker (distroless)

Docker Engine with the Compose plugin is sufficient; Python and Node.js are
only used in build stages:

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f penrecon
```

Open `http://127.0.0.1:8000`. To use another host port:

```sh
PENRECON_PORT=8765 docker compose up --build -d
```

The image builds the frontend with `npm ci` and installs locked Python 3.14
dependencies with `uv`. The final `distroless/base-debian13:nonroot` image
contains Python, its native libraries, and the installed app/assets, but no
shell, pip, uv, npm, or OS package manager. It runs as UID/GID `65532:65532`.
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
docker compose exec penrecon /usr/local/bin/python3.14 -m penrecon --help
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
least 100 rows per domain table, including hosts, hostnames, services, scans,
observations, notes,
credentials, operation logs, and their relationships. Every host and service
has a triage annotation. Each scan has retained nmap XML, and each operation
has a downloadable text attachment.

The first host, `198.18.0.1` (`host-00001.mock.test`), has five open ports:
TCP 22 (SSH), 80 (HTTP), 443 (HTTPS), 5432 (PostgreSQL), and UDP 53 (DNS).
Other hosts vary in status, service state, product, and credential kind.

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
- **Diff** any two scans: added / removed / changed ports and versions.
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
  Filters and selection are bookmarkable. The layout stacks on narrow screens.
  During creation, selecting a host loads its services. A failed load blocks
  saving until you retry successfully or deselect the host; retrying clears the
  error and shows loading while saving remains disabled.
- **Operation log**: manually create, review, edit, search, and delete timeline
  entries for commands and operator actions, with one replaceable attachment
  per entry. penrecon does not execute commands or capture terminal history.
  Start and end timestamps use shadcn calendar popovers and styled native time
  inputs; the browser/system chooses 12- or 24-hour display. A selected date
  defaults to midnight; use Clear date to omit that timestamp.

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

React source lives in `frontend/src`. Shared components are shadcn/ui's
`base-nova` style, backed by `@base-ui/react`, with Tailwind CSS 4 and Lucide
icons. Add components with `npx shadcn@latest add <component> -c frontend`.
Existing page URLs return the React shell, or the same page context as JSON
with `Accept: application/json`. Mutations retain their form endpoints and
refresh page data after success.

### Shared feature seams

- `inventory.py` owns hostname/link persistence for both ingestion and manual
  edits. Callers normalize inputs and commit; existing hidden links stay hidden.
- `queries.latest_observations()` and the shared service-name resolver keep
  inventory, exports, and credential associations on the same current state.
  Credential assembly reuses each host's observation map.
- The web layer binds service-table state once for query/form inputs, and
  operation input once for create/edit. Operation validation remains inside the
  handler, after ownership and attachment-conflict checks.
- `components/credential-fields.tsx` supplies both credential editors, including
  masked, kind-aware secret controls and multiline notes.

The [before wiring report](reports/untangle-before.html) records the ranked
knots with original file/line anchors. The [after report](reports/untangle-after.html)
and [comparison image](reports/untangle-comparison.png) show the cutover.
