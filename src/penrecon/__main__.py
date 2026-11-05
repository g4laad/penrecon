"""penrecon CLI: serve the UI, ingest scans, or seed a mock database."""

from __future__ import annotations

import argparse
from pathlib import Path

from sqlmodel import Session

from penrecon.db import engine, init_db
from penrecon.ingest import ingest_scan


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run("penrecon.web.app:app", host="127.0.0.1", port=args.port, reload=args.reload)


def _ingest(args: argparse.Namespace) -> None:
    init_db()
    path = Path(args.file)
    data = path.read_bytes()
    with Session(engine) as session:
        scan = ingest_scan(session, data, path.name, args.tool)
    print(f"ingested scan #{scan.id}: {scan.host_count} hosts from {path.name} ({args.tool})")


def _seed(args: argparse.Namespace) -> None:
    from penrecon.seed import seed_database

    init_db()
    with Session(engine) as session:
        try:
            counts = seed_database(session, args.count)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    print("Created mock data (no network commands executed):")
    for table, count in counts.items():
        print(f"  {table}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="penrecon")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="run the web UI on 127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=_serve)

    p_ingest = sub.add_parser("ingest", help="ingest a scan result file")
    p_ingest.add_argument("file")
    p_ingest.add_argument("--tool", default="nmap")
    p_ingest.set_defaults(func=_ingest)

    p_seed = sub.add_parser("seed", help="fill an empty database with linked mock data")
    p_seed.add_argument("--count", type=int, default=100, help="rows per type (100–131070)")
    p_seed.set_defaults(func=_seed)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
