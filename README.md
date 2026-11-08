# penrecon

Single-user, local pentest recon manager. Import nmap XML and Amass exports,
browse hosts/services, compare scans, and keep notes, tags, credentials, and
manual operation logs. Built with FastAPI, React + shadcn/ui (Base UI), and SQLite.

**No authentication: keep access on loopback.** penrecon does not run scans,
execute logged commands, or capture terminal history.

## Quick start

Requires Python 3.14+, uv, and Node.js 22.12+ to build the frontend:

```sh
uv sync
npm --prefix frontend ci
npm --prefix frontend run build
uv run penrecon serve
```

Open <http://127.0.0.1:8000/engagements>, create an engagement, and upload evidence
from **Scans**. Use **Scan diff** to compare imports.

Or create and import from another terminal, replacing `UUID` with the printed ID:

```sh
uv run penrecon engagements create "Example engagement"
uv run penrecon engagements list
uv run penrecon ingest scan.xml --tool nmap --engagement UUID
```

`serve` binds to `127.0.0.1`. Use `--port 8765` for another port and `--reload`
for backend development. FastAPI serves built frontend assets; no Node server
or CDN is needed at runtime. Rebuild after frontend changes and before packaging.

Browser workspaces use `/UUID/`; API requests use `?engagement_id=UUID`.
Separate tabs can use different engagements.

Scans history and Scan diff results use URL-backed `page` and `per` parameters
(25 rows by default; `per=10`, `25`, `50`, or `all`). API responses include
`total`, `page`, `pages`, and normalized `per`; out-of-range pages clamp to the
available range. History is newest-import-first, breaking ties by descending
scan ID. Diff pages preserve the selected `a`/`b` pair and order added, removed,
then changed entries, each by IP, port, and protocol. Diff scan selectors still
include all imports in the engagement. Counts and paging run in SQLite before
loading displayed rows; `per=all` explicitly requests the complete result.

## Data and backups

`PENRECON_DATA=/path` overrides the default `./data`. It contains `penrecon.db`
and retained files under `engagements/UUID/scans/` and
`engagements/UUID/operation-attachments/`.

- All inventory, evidence, notes, credentials, and operations are engagement-scoped.
  The same IP or hostname can exist independently in different engagements.
- SQLite uses WAL, FULL synchronous durability, and a 30-second lock timeout.
  Use local storage compatible with SQLite WAL; writes are serialized.
- **Stop every process using the directory before backing up the entire
  directory**, including any `-wal` and `-shm` files. The database alone is not
  a complete backup.
- General schema migration/database portability is unsupported. Pre-engagement
  databases require a fresh data directory or a backup before manual reset.
  Reimporting scans does **not** restore notes, credentials, manual edits, or logs.
- Startup never deletes data or alters existing tables. Supported additive
  upgrades create/backfill missing scan-state, inventory, and timeline
  projections without resetting compatible engagement-aware databases. First
  startup may take longer; complete projections are not rebuilt each time.

## Imports and export

### Supported formats

- **nmap:** XML produced by `-oX`; import with `--tool nmap`.
- **Amass v5:** export hostname/IP mappings from an existing enumeration database:

  ```sh
  amass subs -d example.com -names -ip -nocolor -o amass.txt
  uv run penrecon ingest amass.txt --tool amass --engagement UUID
  ```

  Each line contains a hostname followed by comma-separated IPv4/IPv6 addresses:

  ```text
  www.example.com 192.0.2.10,2001:db8::10
  api.example.com 192.0.2.10
  ```

  Legacy `enum -json` output is also accepted as JSONL, one object, or an array
  with `name` and `addresses: [{"ip": "..."}]`. Names-only text and files without
  IP mappings are rejected; unresolved JSON records are skipped when other
  records contain mappings. Graph/OAM exports, logs, `-show`, and `-summary`
  output are unsupported.

Both tools work through the Scans upload form. Amass imports normalize IPs and
hostname case/trailing dots, merge duplicates, perform no DNS lookups, and add
no services.

### Evidence rules

- Hosts are identified by IP; services by `(host, port, protocol)`. Original
  files are retained and scan observations are immutable.
- Scan execution time orders evidence when available; otherwise labeled import
  time is used. Older imports do not overwrite newer evidence. Host first/last
  seen describes import time.
- Missing ports mean **not reported**, not closed. Only explicit evidence or
  unambiguous nmap coverage establishes closure/filtering. All six nmap states
  are preserved. Amass never erases ports. Diff **removed** means absent from
  that scan, not confirmed closed.
- Manual overrides win until reset; blank overrides restore scan values.
  Removing a service preserves history and does not mean closed. Later explicit
  scans can recreate it. Hidden hostname associations stay hidden.
- Imports preserve notes, triage, credentials, and overrides. Deleting hosts or
  services removes credential links, not credentials.
- Host **Timeline** shows scan and manual-service changes, newest first.
  **Show unchanged scans** includes partial/zero-port sightings. Notes, triage,
  and credentials are not service-history events.
- Legacy scans can recover execution time, coverage, and zero-port sightings
  from retained files. Missing/corrupt files fall back to observations with
  unknown coverage and import time. Completed, marked imports use stored evidence
  rather than recovering deleted hosts from raw files.

Imports stage before committing; pre-commit failures roll back inventory and
remove partial files. Request cancellation waits for commit or rollback/cleanup.

### CSV export

Exports include hosts without services, effective overrides, visible hostnames,
and host triage. Output is streamed and spreadsheet formulas are escaped.

```sh
curl -o hosts.csv \
  'http://127.0.0.1:8000/api/export/hosts.csv?engagement_id=UUID'
```

## Working with records

- **Notes:** Markdown Write/Preview/Split editor. HTML is rendered as text,
  unsafe links are blocked, and images become links rather than remote fetches.
- **Credentials:** masked by default, with reveal and copy controls. Search
  covers identity, notes, and linked hosts/services, never secrets. A username
  or secret is required. Service links require their host link.
- **Operations:** manually record commands, output, comments, optional times,
  and one replaceable attachment. Aware timestamp pairs normalize to UTC;
  mixed aware/naive pairs are rejected.
- **Recovery:** failed saves preserve drafts. An unconfirmed request may have
  committed: check current data before retrying. Attachment cleanup failures
  after commit mean **saved/deleted, cleanup pending**, not a failed mutation.
- **Navigation:** filters, pages, and selections use bookmarkable URLs with
  Back/Forward support. Failed loads retain previous results and offer recovery.

See [DESIGN.md](DESIGN.md) for detailed UI/accessibility contracts and
[PRODUCT.md](PRODUCT.md) for priorities and non-goals.

## Deployment

Keep the service on loopback. For remote access, prefer an SSH tunnel:

```sh
ssh -N -L 8765:127.0.0.1:8765 user@server
```

### Nix

With flakes enabled:

```sh
nix build
PENRECON_DATA="$HOME/.local/share/penrecon" nix run . -- serve --port 8765
```

The package includes Python 3.14 and built frontend assets; Node.js and uv are
not needed at runtime. Supports `x86_64-linux` and `aarch64-linux` using NixOS
26.05 nixpkgs. Lockfiles pin dependencies; new Nix files must be tracked by Git.

`nix develop` supplies Python 3.14, uv, and Node.js 24. After frontend dependency
changes, update `npmDepsHash` in `flake.nix` using the hash reported on rebuild.
Update flake inputs deliberately with `nix flake update`.

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

Apply with `sudo nixos-rebuild switch`. Inspect `systemctl status penrecon` or
`journalctl -u penrecon`. The service uses a dynamic unprivileged user, stores
state in `/var/lib/penrecon`, listens on loopback, and opens no firewall port.
Removing the service preserves data. For backups, stop it with
`sudo systemctl stop penrecon`, copy the entire state directory, then run
`sudo systemctl start penrecon`.

### Docker

Requires Docker Engine and the Compose plugin; host Nix is not needed:

```sh
docker compose up --build -d
docker compose logs -f penrecon
# Alternative host port:
PENRECON_PORT=8765 docker compose up --build -d
```

Open <http://127.0.0.1:8000> or the chosen port. Compose publishes only on host
loopback and disables forwarded proxy headers. Do not publish on `0.0.0.0` or
use an unauthenticated proxy.

The nonroot runtime uses UID/GID `65532:65532`, a read-only root, writable
`/tmp`, no capabilities, and no privilege escalation. Build tools stay in the
Nix builder, but the runtime is not shell-free: its Python closure includes Bash.

The `penrecon-data` volume stores `/data` and survives rebuilds and
`docker compose down`. **`docker compose down --volumes` deletes it.** Local
`./data` is not imported. Bind mounts must be writable by `65532:65532`.

Upload through Scans or use the CLI (replace `UUID` with an engagement ID):

```sh
docker compose run --rm -v "$PWD/scan.xml:/input/scan.xml:ro" \
  penrecon -m penrecon ingest /input/scan.xml --tool nmap --engagement UUID
docker compose exec penrecon /app/bin/python3.14 -m penrecon --help
```

For a full backup:

```sh
docker compose stop penrecon
docker compose cp penrecon:/data ./penrecon-backup
docker compose start penrecon
```

## API

`GET /openapi.json` documents routes, inputs, responses, errors, and downloads.
`/docs` and `/redoc` require internet for UI assets; set Swagger's `LocalRequest`
authorization value to `1` for mutations.

- JSON routes live under `/api`; browser URLs return the React shell, not JSON.
- Every scoped read, mutation, and download requires `?engagement_id=UUID`.
  Only engagement listing/creation is unscoped. Missing scope returns 422;
  unknown engagements and missing/foreign resources return 404.
- Mutations require `X-Penrecon-Request: 1` and form bodies, not JSON. Use
  URL encoding or multipart forms; uploads require multipart.
- `POST` creates/imports. `PUT` replaces all editable fields, resetting omitted
  optional fields to defaults; separately linked resources remain separate.
  `PATCH` changes the specified part; `DELETE` removes a resource/link.

```sh
curl -H 'X-Penrecon-Request: 1' -d 'name=Example' \
  http://127.0.0.1:8000/api/engagements
curl -H 'X-Penrecon-Request: 1' -F 'tool=nmap' -F 'file=@scan.xml' \
  'http://127.0.0.1:8000/api/scans?engagement_id=UUID'
```

Success returns `{"ok": true}` with an optional document URL in `redirect_to`,
not an HTTP redirect. Post-commit attachment cleanup failures additionally
return `committed: true`, `cleanup_pending: true`, and `detail`; do not resubmit.

Errors return `{"detail": "..."}` with optional `field_errors`. Expected statuses
are 400 (invalid input/import/Host), 403 (request protection), 404 (missing/foreign
resource), 409 (identity conflict), 413 (size limit), and 422 (validation).
Transport errors, 5xx, or missing confirmation can leave mutation outcomes
unknown; inspect current data before retrying.

### Security and limits

- The request header is not authentication. Network exposure requires an
  authenticating proxy, preservation of the original Host, and security review.
- Accepted Hosts: `localhost`, `127.0.0.1`, `[::1]` (`testserver` for tests).
  Arbitrary DNS names and cross-origin browser API requests are rejected.
  CLI clients may omit Origin.
- API/HTML responses use `Cache-Control: no-store`. Attachments are inert
  downloads with `nosniff`; stored paths are not exposed.
- Limits: **32 MiB per upload, 33 MiB total request body**, including chunked
  bodies before form parsing. Every lookup/link/download checks ownership.

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

For frontend work, run `npm --prefix frontend run dev` alongside FastAPI. It
watches/rebuilds assets, not a separate server; refresh the browser after changes.
`build` checks TypeScript and emits assets; `npm --prefix frontend run typecheck`
checks types alone. **Use a port other than 8000 for previews/tests**, and build
the frontend before browser verification.

Scans and Scan diff load their shared page-code chunk in parallel with API data,
then display the page once both are ready. Loading failures use the existing
view error and Retry flow.

CI runs locked Python checks, frontend TypeScript/build, wheel packaging and
installed-CLI smoke checks, plus a separate locked Nix build/CLI smoke.
Test observable behavior, isolation, preservation, rollback, and query boundaries
rather than implementation details. Delete/reimport tests need separate sessions
because database cascades do not mark loaded ORM children deleted.

### Mock data

Use a disposable directory, then serve the same directory:

```sh
PENRECON_DATA=./data-test uv run penrecon seed
PENRECON_DATA=./data-test uv run penrecon serve --port 8765
```

Each run creates ten new engagements (**Mock engagement 01–10**) with fresh IDs;
it never modifies existing engagements and accepts no `--engagement`.
`seed --count 250` sets rows per type per engagement (default/minimum 100,
maximum 131070). Normal `serve` never seeds.

Mock data includes linked inventory, evidence, notes, credentials, operations,
triage, retained XML, and attachments. Addresses use `198.18.0.0/15`, names end
in `.mock.test`, and secrets are labeled mock. No scans or network requests run.
Host `198.18.0.1` has a multi-scan timeline; enable **Show unchanged scans** to
see partial, zero-port, and repeated results. Omit `PENRECON_DATA` to return to
normal `./data`.

### Source map

| Path | Responsibility |
| --- | --- |
| `src/penrecon/models.py`, `db.py` | Persisted entities and storage initialization |
| `src/penrecon/ingest.py`, `parsers/` | Shared CLI/web imports and parser registry |
| `src/penrecon/inventory.py`, `commands.py` | Identity transitions and manual mutations |
| `src/penrecon/history.py`, `*projection*.py` | Evidence replay and transactional read models |
| `src/penrecon/queries/` | Scoped reads, search, pagination, export; import submodules directly |
| `src/penrecon/web/` | API routers, HTTP contracts, security, and HTML delivery |
| `frontend/src/` | React pages, workflow state, and shared components |

The frontend uses Base UI, Tailwind 4, and Lucide. Add shadcn/ui components with
`npx shadcn@latest add <component> -c frontend`.
