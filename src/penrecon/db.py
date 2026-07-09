"""Database engine, session, and on-disk data locations.

Everything lives under ./data (override with PENRECON_DATA): the SQLite file
and the retained raw scans.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

DATA_DIR: Path = Path(os.environ.get("PENRECON_DATA", "data")).resolve()
RAW_SCANS_DIR: Path = DATA_DIR / "scans"  # retained raw upload bytes (Scan.raw_path)
DB_PATH: Path = DATA_DIR / "penrecon.db"

def enable_sqlite_fks(engine: object) -> None:
    """Turn on FK enforcement for every connection of ``engine``. SQLite defaults
    foreign_keys OFF per connection, so without this every foreign_key= in
    models.py is ignored — no integrity, no ON DELETE CASCADE. Tests reuse this."""

    @event.listens_for(engine, "connect")
    def _on(dbapi_conn: object, _record: object) -> None:
        cur = dbapi_conn.cursor()  # type: ignore[attr-defined]
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
enable_sqlite_fks(engine)


def init_db() -> None:
    """Create data dirs and tables from the models. Idempotent.

    No migrations: this is a local single-user DB. If the schema changes,
    delete ./data/penrecon.db and re-ingest.
    """
    RAW_SCANS_DIR.mkdir(parents=True, exist_ok=True)
    # import registers tables on SQLModel.metadata
    from penrecon import models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
