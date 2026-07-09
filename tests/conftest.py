from __future__ import annotations

import os
import tempfile

# Point all runtime data (sqlite db + retained raw scan bytes) at a throwaway
# dir BEFORE importing penrecon — db.py binds DATA_DIR/RAW_SCANS_DIR at import
# time. Keeps the suite (and ingest's raw-file writes) off the real ./data.
os.environ.setdefault("PENRECON_DATA", tempfile.mkdtemp(prefix="penrecon-test-"))

from collections.abc import Iterator

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine
from starlette.testclient import TestClient

import penrecon.models  # noqa: F401  (register tables)
from penrecon.db import enable_sqlite_fks, get_session
from penrecon.web.app import app


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    enable_sqlite_fks(engine)  # match prod: FKs + ON DELETE CASCADE enforced
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Isolated in-memory DB via dependency override, so tests never touch ./data.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    enable_sqlite_fks(engine)
    SQLModel.metadata.create_all(engine)

    def _override() -> Iterator[Session]:
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
