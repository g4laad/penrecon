"""Database engine, session, and on-disk data locations.

Everything lives under ./data (override with PENRECON_DATA): one shared SQLite
file and engagement-specific retained scans and operation attachments.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

DATA_DIR: Path = Path(os.environ.get("PENRECON_DATA", "data")).resolve()
DB_PATH: Path = DATA_DIR / "penrecon.db"
SQLITE_BUSY_TIMEOUT_MS = 30_000


def engagement_scans_dir(engagement_id: str) -> Path:
    return DATA_DIR / "engagements" / engagement_id / "scans"


def engagement_attachments_dir(engagement_id: str) -> Path:
    return DATA_DIR / "engagements" / engagement_id / "operation-attachments"


def enable_sqlite_fks(engine: object) -> None:
    """Turn on FK enforcement for every connection of ``engine``. SQLite defaults
    foreign_keys OFF per connection, so without this every foreign_key= in
    models.py is ignored — no integrity, no ON DELETE CASCADE. Tests reuse this."""

    @event.listens_for(engine, "connect")
    def _on(dbapi_conn: object, _record: object) -> None:
        cur = dbapi_conn.cursor()  # type: ignore[attr-defined]
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        # WAL still requires durable commits; do not trade evidence for speed.
        cur.execute("PRAGMA synchronous=FULL")
        cur.close()
        # SQLite's built-in lower() is ASCII-only; list searches preserve the
        # operation log's Unicode case-insensitive substring matching in SQL.
        dbapi_conn.create_function(  # type: ignore[attr-defined]
            "casefold", 1, lambda value: (value or "").casefold(), deterministic=True,
        )
        # Credential substring search retains Python lower(), not casefold().
        dbapi_conn.create_function(  # type: ignore[attr-defined]
            "unicode_lower", 1, lambda value: (value or "").lower(), deterministic=True,
        )


engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
enable_sqlite_fks(engine)


def init_db() -> None:
    """Ensure local storage is ready before opening CLI or web sessions.

    This idempotent command creates missing tables and transactionally backfills
    missing scan and inventory projections. New inventory tables reuse complete
    scan state without replaying evidence. Existing tables are never altered:
    incompatible schemas require an explicit manual database reset, never an
    automatic migration or deletion.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # import registers tables on SQLModel.metadata
    from penrecon import models  # noqa: F401

    # Journal mode is persistent and negotiated only at initialization, not
    # while opening request connections. In-memory databases keep their mode.
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")

    SQLModel.metadata.create_all(engine)
    from penrecon.projections import backfill_missing

    with Session(engine) as session:
        with session.begin():
            backfill_missing(session)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
