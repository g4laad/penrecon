from __future__ import annotations

import os
import tempfile

# Point all runtime data (sqlite db + retained raw scan bytes) at a throwaway
# dir BEFORE importing penrecon — db.py binds DATA_DIR at import time.
# Always override external settings so the suite cannot touch a user database.
os.environ["PENRECON_DATA"] = tempfile.mkdtemp(prefix="penrecon-test-")

from collections.abc import Iterator

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine
from starlette.testclient import TestClient

import penrecon.models  # noqa: F401  (register tables)
from penrecon.db import enable_sqlite_fks, get_session
from penrecon.models import Engagement
from penrecon.web.app import app
from tests.fixtures import TEST_ENGAGEMENT_ID


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    enable_sqlite_fks(engine)  # match prod: FKs + ON DELETE CASCADE enforced
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Engagement(id=TEST_ENGAGEMENT_ID, name="Test engagement"))
        s.commit()
        yield s


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Isolated in-memory DB via dependency override, so tests never touch ./data.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    enable_sqlite_fks(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Engagement(id=TEST_ENGAGEMENT_ID, name="Test engagement"))
        s.commit()

    def _override() -> Iterator[Session]:
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _override
    with TestClient(
        app,
        headers={"Accept": "application/json", "X-Penrecon-Request": "1"},
        follow_redirects=False,
    ) as c:
        yield c
    app.dependency_overrides.clear()
