from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import penrecon.models  # noqa: F401  (register tables)
from penrecon.db import enable_sqlite_fks


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    enable_sqlite_fks(engine)  # match prod: FKs + ON DELETE CASCADE enforced
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
