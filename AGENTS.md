# penrecon contributor guide

Single-user, local pentest recon manager: FastAPI + React + shadcn/ui
(Base UI), SQLite via SQLModel. Use `uv` for Python and npm in `frontend/`.
Keep full type annotations; mypy and TypeScript must stay clean.

## Read before changing

- **README.md:** operational source of truth for setup, commands, supported
  importers, API/data contracts, deployment, backups, and developer checks.
- **PRODUCT.md:** read before changing product scope or priorities.
- **DESIGN.md:** read before layout, component, interaction, or accessibility
  changes; it defines the committed UI contracts.

## Development guardrails

- **Never bind port 8000 for tests or previews:** it is the user's dev server.
  Use another port, e.g. `uv run penrecon serve --port 8765`.
- After frontend changes, run `npm --prefix frontend run build` before browser
  verification or packaging. FastAPI serves `src/penrecon/web/static/ui`;
  `npm --prefix frontend run dev` watches and rebuilds those assets.
- Use disposable test data via `PENRECON_DATA`; preserve the user's database and
  retained files. Re-importing scans cannot restore user-authored data.
- Imports require an engagement, for example:
  ```sh
  uv run penrecon engagements create "Example engagement"
  uv run penrecon ingest scan.xml --tool nmap --engagement <uuid>
  ```
  Use the returned UUID. Browser workspaces are `/<uuid>/`; API requests use
  `?engagement_id=<uuid>`. See README for complete workflows and checks.

## Data invariants

- All workspace data and relationships are engagement-scoped. The same IP or
  hostname can exist independently in different engagements; queries, exports,
  diffs, and mutations must respect that boundary.
- Within an engagement, hosts are identified by IP, hostnames link M:N to hosts,
  and services by `(host, port, proto)`.
- Scan observations are immutable evidence; ingest merges rather than replacing
  history. Effective state uses trustworthy scan evidence and coverage, not mere
  port absence. Manual overrides win until reset to scan inheritance.
- Ingest and projection maintenance must preserve user notes, status, tags,
  attachments, credentials, and manual overrides.
- Credentials are user data linked M:N to hosts/services. Deleting a host or
  service removes its credential links, never the credential itself.

## Navigation

- `src/penrecon/models.py`: persisted entities and relationship constraints.
- `src/penrecon/ingest.py` and `parsers/`: shared CLI/web import path and parser registry.
- `src/penrecon/history.py`, `*projection*.py`, and `queries/`: evidence replay,
  materialized read models, and scoped reads.
- `src/penrecon/commands.py`: manual mutations; `web/`: FastAPI routes and static assets.
- `frontend/src/`: React pages and Base UI components; `index.css`: shared styling.
