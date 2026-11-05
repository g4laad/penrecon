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
uv run penrecon ingest scan.xml --tool nmap   # or upload on the /scans page
```

Data (SQLite db + attachments) lives under `./data` — override with
`PENRECON_DATA=/path`.

Requires Node.js 22.12+ for the frontend build. FastAPI serves the generated
assets locally from `src/penrecon/web/static/ui`; no CDN or separate Node
server is needed at runtime. Rebuild before serving or packaging a wheel.

## Mock-data test mode

Create a separate test database, then serve it using the same data directory:

```sh
PENRECON_DATA=./data-test uv run penrecon seed
PENRECON_DATA=./data-test uv run penrecon serve --port 8765
```

Open `http://127.0.0.1:8765`. Seeding creates at least 100 rows per database
table, including hosts, hostnames, services, scans, observations, notes,
credentials, operation logs, and their relationships. Every host and service
has a triage annotation. Each scan has retained nmap XML, and each operation
has a downloadable text attachment.

The first host, `198.18.0.1` (`host-00001.mock.test`), has five open ports:
TCP 22 (SSH), 80 (HTTP), 443 (HTTPS), 5432 (PostgreSQL), and UDP 53 (DNS).
Other hosts vary in status, service state, product, and credential kind.

Use `seed --count 250` for a larger dataset (minimum 100, maximum 131070 per
type). The command refuses a nonempty database: it never clears or merges
existing recon data. To start another dataset, choose a fresh `PENRECON_DATA`
directory. Normal `serve` does not generate data.

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
- **Annotate**: markdown notes, status, and tags on findings persist across
  re-scans; ingest never touches them.
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
uv run penrecon ingest amass.txt --tool amass
```

Alternatively, upload the export on `/scans` with **amass** selected.
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
