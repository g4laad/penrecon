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
DB_PATH: Path = DATA_DIR / "penrecon.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


def init_db() -> None:
    """Create data dirs and tables. Idempotent."""
    ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)
    # import registers tables on SQLModel.metadata
    from penrecon import models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
