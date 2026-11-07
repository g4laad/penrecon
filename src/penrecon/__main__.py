"""penrecon CLI: manage engagements, serve the UI, ingest scans, or seed mock data."""

from __future__ import annotations

import argparse
from pathlib import Path
from uuid import UUID

from sqlmodel import Session, col, select

from penrecon.db import engine, init_db
from penrecon.ingest import ingest_scan
from penrecon.models import Engagement


def _engagement_id(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("engagement must be a UUID") from exc


def _require_engagement(session: Session, engagement_id: str) -> Engagement:
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        raise SystemExit(f"engagement not found: {engagement_id}")
    return engagement


def _engagements_list(args: argparse.Namespace) -> None:
    init_db()
    with Session(engine) as session:
        for engagement in session.exec(
            select(Engagement).order_by(col(Engagement.created_at), Engagement.id)
        ).all():
            print(f"{engagement.id}\t{engagement.name}\t{engagement.description}")


def _engagements_create(args: argparse.Namespace) -> None:
    name = args.name.strip()
    if not name:
        raise SystemExit("engagement name must not be empty")
    init_db()
    with Session(engine) as session:
        engagement = Engagement(name=name, description=args.description)
        session.add(engagement)
        session.commit()
        session.refresh(engagement)
        print(f"{engagement.id}\t{engagement.name}")


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run("penrecon.web.app:app", host="127.0.0.1", port=args.port, reload=args.reload)


def _ingest(args: argparse.Namespace) -> None:
    init_db()
    path = Path(args.file)
    with Session(engine) as session:
        _require_engagement(session, args.engagement)
        data = path.read_bytes()
        scan = ingest_scan(
            session, data, path.name, args.tool, engagement_id=args.engagement
        )
    print(f"ingested scan #{scan.id}: {scan.host_count} hosts from {path.name} ({args.tool})")


def _seed(args: argparse.Namespace) -> None:
    from penrecon.seed import seed_mock_engagement

    if not 100 <= args.count <= 131070:
        raise SystemExit("count must be between 100 and 131070")
    init_db()
    print("Creating 10 mock engagements (no network commands executed):")
    with Session(engine) as session:
        for number in range(1, 11):
            try:
                outcome = seed_mock_engagement(
                    session, args.count, name=f"Mock engagement {number:02d}",
                )
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc
            print(f"{outcome.engagement_id}\t{outcome.name}")
            for table, count in outcome.counts.items():
                print(f"  {table}: {count}")
    print("Created 10 mock engagements.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="penrecon")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_engagements = sub.add_parser("engagements", help="list or create engagements")
    engagements_sub = p_engagements.add_subparsers(dest="engagements_cmd", required=True)
    p_engagements_list = engagements_sub.add_parser("list", help="list all engagements")
    p_engagements_list.set_defaults(func=_engagements_list)
    p_engagements_create = engagements_sub.add_parser("create", help="create an engagement")
    p_engagements_create.add_argument("name")
    p_engagements_create.add_argument("--description", default="")
    p_engagements_create.set_defaults(func=_engagements_create)

    p_serve = sub.add_parser("serve", help="run the web UI on 127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=_serve)

    p_ingest = sub.add_parser("ingest", help="ingest a scan result file")
    p_ingest.add_argument("file")
    p_ingest.add_argument("--tool", default="nmap")
    p_ingest.add_argument("--engagement", type=_engagement_id, required=True)
    p_ingest.set_defaults(func=_ingest)

    p_seed = sub.add_parser("seed", help="create 10 engagements filled with linked mock data")
    p_seed.add_argument(
        "--count", type=int, default=100,
        help="rows per type per engagement (100–131070)",
    )
    p_seed.set_defaults(func=_seed)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
