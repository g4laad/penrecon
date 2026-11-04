# penrecon

Single-user, local pentest recon manager. Ingest scan output (nmap XML today),
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

## What it does

- **Ingest** nmap `-oX` XML via web upload or CLI. Each ingest is an immutable
  snapshot of observations.
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
- **Operation log**: manually create, review, edit, search, and delete timeline
  entries for commands and operator actions, with one replaceable attachment
  per entry. penrecon does not execute commands or capture terminal history.

## Adding a parser

Parsers live in `src/penrecon/parsers/` and register in `PARSERS`. Each is a
`fn(bytes) -> ScanResult`. masscan/rustscan/httpx/nuclei/whatweb/subfinder/
amass/dnsx are registered stubs — implement one file and it's wired in.

## Dev

```sh
uv run pytest
uv run mypy src/penrecon
```

For frontend work, run `npm --prefix frontend run dev` alongside FastAPI.
This watches and rebuilds the local bundle; refresh the browser after changes.
`npm --prefix frontend run build` checks TypeScript and produces release assets.

React source lives in `frontend/src`. Shared components are shadcn/ui's
`base-nova` style, backed by `@base-ui/react`, with Tailwind CSS 4 and Lucide
icons. Add components with `npx shadcn@latest add <component> -c frontend`.
Existing page URLs return the React shell, or the same page context as JSON
with `Accept: application/json`. Mutations retain their form endpoints and
refresh page data after success.
