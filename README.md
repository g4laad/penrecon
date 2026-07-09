# penrecon

Single-user, local pentest recon manager. Ingest scan output (nmap XML today),
browse hosts/services, diff two scans, and keep your own notes/tags/attachments
on findings. FastAPI + HTMX, SQLite, no auth — binds to `127.0.0.1`.

## Run

```sh
uv sync
uv run penrecon serve          # http://127.0.0.1:8000
uv run penrecon ingest scan.xml --tool nmap   # or upload on the /scans page
```

Data (SQLite db + attachments) lives under `./data` — override with
`PENRECON_DATA=/path`.

## What it does

- **Ingest** nmap `-oX` XML via web upload or CLI. Each ingest is an immutable
  snapshot of observations.
- **Merge, latest-wins**: current host/service state is the newest observation
  per `(host, port, proto)`; a web-tool scan never erases port data. Hosts are
  keyed by IP, with hostnames linked.
- **Diff** any two scans: added / removed / changed ports and versions.
- **Annotate**: markdown note + status + tags + file attachments on any host,
  service, or hostname. Annotations persist across re-scans; ingest never
  touches them.

## Adding a parser

Parsers live in `src/penrecon/parsers/` and register in `PARSERS`. Each is a
`fn(bytes) -> ScanResult`. masscan/rustscan/httpx/nuclei/whatweb/subfinder/
amass/dnsx are registered stubs — implement one file and it's wired in.

## Dev

```sh
uv run pytest
uv run mypy src/penrecon
```
