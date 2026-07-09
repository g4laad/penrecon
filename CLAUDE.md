# penrecon

Single-user, local pentest recon manager. FastAPI + HTMX (server-rendered
Jinja2, no frontend build) + SQLite via SQLModel. `uv` for everything. Full
type annotations; `mypy` must stay clean.

## Run / dev

```sh
uv run penrecon serve                          # http://127.0.0.1:8000
uv run penrecon ingest scan.xml --tool nmap    # or upload on /scans
uv run pytest
uv run mypy src/penrecon
```

Data (SQLite + attachments) lives under `./data` (override `PENRECON_DATA`).

## Layout

- `src/penrecon/models.py` — SQLModel tables (Host/Hostname/Service/Observation
  snapshots; Annotation/Attachment on any entity; Credential linked M:N to hosts
  and services via credential_host / credential_service).
- `src/penrecon/ingest.py` — `ingest_scan()`, shared by web + CLI.
- `src/penrecon/parsers/` — `PARSERS` registry, `fn(bytes) -> ScanResult`.
  nmap implemented; others stubbed.
- `src/penrecon/queries.py` — current-state merge (latest-observation-wins),
  scan diff, annotation/attachment access.
- `src/penrecon/web/` — FastAPI app + Jinja templates + static.

## Core model rules

- Host = IP (primary); hostnames linked M:N. Service = (host, port, proto).
- Each ingest is an immutable Observation snapshot. Current state = newest
  observation per (host, port, proto) — ingest merges, never replaces.
- Annotations (notes/status/tags/attachments) are user data and are **never**
  touched by ingest. Credentials are the same: pure user data, M:N to hosts and
  services; deleting a host/service drops its link rows but never the credential.

## Design Context

See `PRODUCT.md` (strategic) for the full brief. In short:

- **Register:** product — a local operator tool; design serves the work.
- **Character:** modern, clean, light, dense; monospace where data lives
  (IPs/ports/versions), a consistent icon set for wayfinding. Explicitly **not**
  a generic SaaS dashboard (no gradient hero-metrics, pastel card-grid, marketing
  chrome); cards/elevation/icons only where they aid triage.
- **Principles:** density serves triage · signal over chrome · notes are sacred
  · change is the story · fast and local.
- **A11y:** WCAG AA contrast, full keyboard nav + visible focus,
  `prefers-reduced-motion` honored, status never conveyed by color alone.
- Design work uses the `impeccable` skill; the committed system is `DESIGN.md`
  (modern light theme), implemented in `web/static/style.css`.
