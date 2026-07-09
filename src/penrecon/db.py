"""Database engine, session, and on-disk data locations.

Everything lives under ./data (override with PENRECON_DATA): the SQLite file
and the attachments directory.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

DATA_DIR: Path = Path(os.environ.get("PENRECON_DATA", "data")).resolve()
ATTACHMENTS_DIR: Path = DATA_DIR / "attachments"
RAW_SCANS_DIR: Path = DATA_DIR / "scans"  # retained raw upload bytes (Scan.raw_path)
DB_PATH: Path = DATA_DIR / "penrecon.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


# ponytail: no migration tool for a local single-user DB; ADD COLUMN keeps
# existing data (and the user's notes) when the schema grows. Upgrade to Alembic
# only if migrations get non-trivial.
_ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "service": [
        ("m_state", "VARCHAR"),
        ("m_service_name", "VARCHAR"),
        ("m_product", "VARCHAR"),
        ("m_version", "VARCHAR"),
    ],
    "host_hostname": [("hidden", "INTEGER NOT NULL DEFAULT 0")],
}


def _ensure_columns() -> None:
    from sqlalchemy import text

    with engine.begin() as conn:
        for table, cols in _ADDED_COLUMNS.items():
            have = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            for name, decl in cols:
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {decl}"))


def init_db() -> None:
    """Create data dirs and tables, then add any new columns. Idempotent."""
    ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)
    RAW_SCANS_DIR.mkdir(parents=True, exist_ok=True)
    # import registers tables on SQLModel.metadata
    from penrecon import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _ensure_columns()


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
