from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastapi import HTTPException
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, create_engine, select
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import JSONResponse

from penrecon import db, ingest
from penrecon.models import Engagement, Host, Observation, Scan
from penrecon.parsers import PARSERS
from penrecon.web import evidence, security
from penrecon.web.app import app
from tests.fixtures import SCAN_A, TEST_ENGAGEMENT_ID, api_url


@pytest.fixture
def import_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Engine, list[Session]]]:
    engine = create_engine(f"sqlite:///{tmp_path / 'imports.db'}", connect_args={"check_same_thread": False})
    db.enable_sqlite_fks(engine)
    monkeypatch.setattr(db, "engine", engine)
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ingest, "DATA_DIR", tmp_path)
    db.init_db()
    with Session(engine) as session:
        session.add(Engagement(id=TEST_ENGAGEMENT_ID, name="Imports"))
        session.add(Engagement(id="other", name="Other"))
        session.commit()
    request_sessions: list[Session] = []

    def override() -> Iterator[Session]:
        with Session(engine) as session:
            request_sessions.append(session)
            yield session

    monkeypatch.setitem(app.dependency_overrides, db.get_session, override)
    try:
        yield engine, request_sessions
    finally:
        engine.dispose()


def _client() -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver",
        headers={"X-Penrecon-Request": "1", "Accept": "application/json"},
    )


async def _upload(client: AsyncClient, filename: str = "scan.xml") -> Any:
    return await client.post(api_url("/scans"), files={"file": (filename, SCAN_A, "text/xml")}, data={"tool": "nmap"})


def _assert_retained(engine: Engine, expected: int) -> None:
    with Session(engine) as session:
        scans = session.exec(select(Scan)).all()
        assert len(scans) == expected
        assert all(scan.engagement_id == TEST_ENGAGEMENT_ID for scan in scans)
        for scan in scans:
            assert scan.raw_path is not None
            assert (db.DATA_DIR / scan.raw_path).read_bytes() == SCAN_A.encode()
        assert len(session.exec(select(Host)).all()) == (1 if expected else 0)
        assert len(session.exec(select(Observation)).all()) == 2 * expected
        assert session.exec(select(Scan).where(Scan.engagement_id == "other")).all() == []
    assert len(list(db.DATA_DIR.rglob("*.xml"))) == expected


def test_upload_parsing_leaves_event_loop_and_read_routes_responsive(
    import_store: tuple[Engine, list[Session]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, request_sessions = import_store
    entered, release = threading.Event(), threading.Event()
    parser = PARSERS["nmap"]
    parser_threads: list[int] = []
    commits: list[tuple[Session, int]] = []

    def slow_parser(data: bytes) -> Any:
        parser_threads.append(threading.get_ident())
        entered.set()
        release.wait(3)
        return parser(data)

    def record_commit(session: Session) -> None:
        commits.append((session, threading.get_ident()))

    monkeypatch.setitem(PARSERS, "nmap", slow_parser)
    event.listen(Session, "before_commit", record_commit)

    async def scenario() -> None:
        loop_thread = threading.get_ident()
        async with _client() as client:
            upload = asyncio.create_task(_upload(client))
            try:
                assert await anyio.to_thread.run_sync(entered.wait, 2)
                assert not upload.done(), "the upload blocked the event loop until parsing finished"
                for path in ("/hosts", "/scans"):
                    response = await asyncio.wait_for(client.get(api_url(path)), 1)
                    assert response.status_code == 200
                assert len(parser_threads) == 1
                assert parser_threads[0] != loop_thread
            finally:
                release.set()
                response = await upload
            assert response.status_code == 200
            assert commits
            assert all(session not in request_sessions and thread != loop_thread for session, thread in commits)

    try:
        asyncio.run(scenario())
    finally:
        event.remove(Session, "before_commit", record_commit)
    _assert_retained(engine, 1)


def test_wal_readers_and_competing_upload_writers_preserve_both_scans(
    import_store: tuple[Engine, list[Session]],
) -> None:
    engine, _ = import_store
    insert_started = threading.Event()

    def observe_insert(_conn: Any, _cursor: Any, statement: str, _parameters: Any, _context: Any, _many: bool) -> None:
        if statement.startswith("INSERT INTO scan "):
            insert_started.set()

    event.listen(engine, "before_cursor_execute", observe_insert)

    async def scenario() -> None:
        async with _client() as client:
            with engine.connect() as lock:
                lock.exec_driver_sql("BEGIN IMMEDIATE")
                lock.exec_driver_sql("UPDATE engagement SET name = 'Committed writer' WHERE id = ?", (TEST_ENGAGEMENT_ID,))
                uploads = [asyncio.create_task(_upload(client, f"{index}.xml")) for index in range(2)]
                try:
                    assert await anyio.to_thread.run_sync(insert_started.wait, 2)
                    assert not any(upload.done() for upload in uploads)
                    response = await asyncio.wait_for(client.get(api_url("/scans")), 1)
                    assert response.status_code == 200
                    assert response.json()["scans"] == []
                finally:
                    lock.commit()
                    responses = await asyncio.gather(*uploads)
                assert [response.status_code for response in responses] == [200, 200]
            response = await client.get(api_url("/hosts"))
            assert [row["ip"] for row in response.json()["rows"]] == ["10.0.0.1"]

    try:
        asyncio.run(scenario())
    finally:
        event.remove(engine, "before_cursor_execute", observe_insert)
    _assert_retained(engine, 2)
    with Session(engine) as session:
        assert session.get(Engagement, TEST_ENGAGEMENT_ID).name == "Committed writer"


def test_wal_upload_commits_while_existing_reader_keeps_its_snapshot(
    import_store: tuple[Engine, list[Session]],
) -> None:
    engine, _ = import_store

    async def scenario() -> None:
        with engine.connect() as reader:
            reader.exec_driver_sql("BEGIN")
            assert reader.exec_driver_sql("SELECT count(*) FROM scan").scalar_one() == 0
            async with _client() as client:
                response = await asyncio.wait_for(_upload(client), 2)
                assert response.status_code == 200
            assert reader.exec_driver_sql("SELECT count(*) FROM scan").scalar_one() == 0
            reader.commit()
            assert reader.exec_driver_sql("SELECT count(*) FROM scan").scalar_one() == 1

    asyncio.run(scenario())
    _assert_retained(engine, 1)


@pytest.mark.parametrize("failure", ["parse", "partial_write", "commit", "refresh"])
def test_worker_errors_preserve_rollback_and_retained_file_semantics(
    import_store: tuple[Engine, list[Session]], monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    engine, _ = import_store
    if failure == "partial_write":
        write_bytes = Path.write_bytes

        def broken_write(path: Path, data: bytes) -> int:
            write_bytes(path, data[:10])
            raise OSError("partial scan write")

        monkeypatch.setattr(Path, "write_bytes", broken_write)
    elif failure == "commit":
        def broken_commit(_session: Session) -> None:
            raise RuntimeError("scan commit failed")

        monkeypatch.setattr(Session, "commit", broken_commit)
    elif failure == "refresh":
        def broken_refresh(_session: Session, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("scan refresh failed")

        monkeypatch.setattr(Session, "refresh", broken_refresh)

    async def scenario() -> None:
        async with _client() as client:
            if failure == "parse":
                response = await client.post(api_url("/scans"), files={"file": ("bad.xml", b"not XML", "text/xml")})
                assert response.status_code == 400
                assert "XML" in response.json()["detail"]
            else:
                with pytest.raises((OSError, RuntimeError), match="partial scan write|scan commit failed|scan refresh failed"):
                    await _upload(client)

    asyncio.run(scenario())
    _assert_retained(engine, 1 if failure == "refresh" else 0)


def test_worker_rechecks_ownership_and_always_closes_upload(
    import_store: tuple[Engine, list[Session]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = import_store

    async def scenario() -> None:
        with Session(engine) as request_session:
            file = UploadFile(io.BytesIO(SCAN_A.encode()), filename="scan.xml")
            with pytest.raises(HTTPException) as error:
                await evidence.upload_scan(Request({"type": "http"}), file, "nmap", "missing", request_session)
            assert error.value.status_code == 404
            assert file.file.closed
        monkeypatch.setattr(evidence, "MAX_UPLOAD_BYTES", 8)
        async with _client() as client:
            assert (await _upload(client)).status_code == 413
            assert (await client.post(api_url("/scans", "missing"), files={"file": ("scan.xml", SCAN_A)})).status_code == 404

    asyncio.run(scenario())
    _assert_retained(engine, 0)


@pytest.mark.parametrize("cancellation", ["anyio", "asyncio"])
@pytest.mark.parametrize("fail_after_write", [False, True])
def test_request_cancellation_waits_for_worker_commit_or_compensation(
    import_store: tuple[Engine, list[Session]], monkeypatch: pytest.MonkeyPatch, fail_after_write: bool,
    cancellation: str,
) -> None:
    engine, _ = import_store
    retained, release = threading.Event(), threading.Event()
    retain_raw = ingest._retain_raw

    def pause_after_write(*args: Any) -> None:
        retain_raw(*args)
        retained.set()
        release.wait(3)
        if fail_after_write:
            raise OSError("cancelled request write failure")

    monkeypatch.setattr(ingest, "_retain_raw", pause_after_write)

    async def scenario() -> None:
        scope = anyio.CancelScope()
        complete = anyio.Event()
        errors: list[BaseException] = []
        upload_tasks: list[asyncio.Task[Any]] = []
        file = UploadFile(io.BytesIO(SCAN_A.encode()), filename="scan.xml")
        with Session(engine) as request_session:
            async def upload() -> None:
                task = asyncio.current_task()
                assert task is not None
                upload_tasks.append(task)
                try:
                    with scope:
                        await evidence.upload_scan(Request({"type": "http"}), file, "nmap", TEST_ENGAGEMENT_ID, request_session)
                except (OSError, asyncio.CancelledError) as exc:
                    errors.append(exc)
                finally:
                    complete.set()

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(upload)
                try:
                    assert await anyio.to_thread.run_sync(retained.wait, 2)
                    if cancellation == "asyncio":
                        upload_tasks[0].cancel()
                    else:
                        scope.cancel()
                    await anyio.sleep(0.02)
                    assert not complete.is_set()
                    assert not file.file.closed
                    if cancellation == "asyncio":
                        upload_tasks[0].cancel()
                        await anyio.sleep(0.02)
                        assert not complete.is_set()
                finally:
                    release.set()
                with anyio.fail_after(2):
                    await complete.wait()
            assert file.file.closed
            if cancellation == "asyncio":
                assert len(errors) == 1 and isinstance(errors[0], asyncio.CancelledError)
                if fail_after_write:
                    assert any("cancelled request write failure" in note for note in errors[0].__notes__)
            else:
                assert bool(errors) is fail_after_write

    anyio.run(scenario)
    _assert_retained(engine, 0 if fail_after_write else 1)


@pytest.mark.parametrize("memory", [False, True])
def test_database_initialization_is_idempotent_and_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, memory: bool,
) -> None:
    engine = create_engine(
        "sqlite://" if memory else f"sqlite:///{tmp_path / 'database.db'}",
        connect_args={"check_same_thread": False}, **({"poolclass": StaticPool} if memory else {}),
    )
    db.enable_sqlite_fks(engine)
    monkeypatch.setattr(db, "engine", engine)
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    try:
        db.init_db()
        with Session(engine) as session:
            session.add(Engagement(id="persistent", name="Preserved"))
            session.commit()
        db.init_db()
        with Session(engine) as session:
            assert session.get(Engagement, "persistent").name == "Preserved"
        for _ in range(2):
            if not memory:
                engine.dispose()
            with engine.connect() as connection:
                assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == ("memory" if memory else "wal")
                assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == db.SQLITE_BUSY_TIMEOUT_MS
                assert connection.exec_driver_sql("PRAGMA synchronous").scalar_one() == 2
                assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("outcome", ["success", "oversize", "disconnect", "handler_error", "cancel"])
def test_security_disk_spooling_is_off_loop_bounded_and_closed(
    monkeypatch: pytest.MonkeyPatch, outcome: str,
) -> None:
    disk_files: list[Any] = []
    disk_operations: list[str] = []
    temporary_file = tempfile.TemporaryFile
    loop_thread = threading.get_ident()

    class GuardedFile:
        def __init__(self, file: Any) -> None:
            self.file = file

        def __getattr__(self, name: str) -> Any:
            value = getattr(self.file, name)
            if name not in {"read", "write", "seek", "close"}:
                return value

            def off_loop(*args: Any, **kwargs: Any) -> Any:
                assert threading.get_ident() != loop_thread, f"disk {name} ran on the event loop"
                disk_operations.append(name)
                return value(*args, **kwargs)

            return off_loop

    def guarded_temporary_file(*args: Any, **kwargs: Any) -> Any:
        assert threading.get_ident() != loop_thread, "disk creation ran on the event loop"
        file = GuardedFile(temporary_file(*args, **kwargs))
        disk_files.append(file)
        return file

    monkeypatch.setattr(tempfile, "TemporaryFile", guarded_temporary_file)
    monkeypatch.setattr(security, "MAX_REQUEST_BYTES", 2 * 1024 * 1024)
    payload = b"retained request bytes" * 60_000
    messages = [{"type": "http.request", "body": payload, "more_body": outcome in {"oversize", "disconnect"}}]
    if outcome == "oversize":
        messages.append({"type": "http.request", "body": b"x" * 1024 * 1024, "more_body": False})
    elif outcome == "disconnect":
        messages.append({"type": "http.disconnect"})
    responses: list[Any] = []
    called = False

    async def receive() -> Any:
        return messages.pop(0)

    async def send(message: Any) -> None:
        responses.append(message)

    async def consumer(scope: Any, replay: Any, reply: Any) -> None:
        nonlocal called
        called = True
        digest = hashlib.sha256()
        while True:
            message = await replay()
            digest.update(message["body"])
            if not message["more_body"]:
                break
        if outcome == "handler_error":
            raise RuntimeError("consumer failed")
        if outcome == "cancel":
            outer_scope.cancel()
            await anyio.sleep(0)
        await JSONResponse({"sha256": digest.hexdigest()})(scope, replay, reply)

    scope = {"type": "http", "method": "POST", "path": "/api/scans", "scheme": "http", "headers": [(b"host", b"testserver"), (b"x-penrecon-request", b"1")]}
    outer_scope: anyio.CancelScope

    async def scenario() -> None:
        nonlocal outer_scope
        with anyio.CancelScope() as outer_scope:
            await security.LocalSecurityMiddleware(consumer)(scope, receive, send)

    if outcome == "handler_error":
        with pytest.raises(RuntimeError, match="consumer failed"):
            anyio.run(scenario)
    else:
        anyio.run(scenario)
    assert disk_files and all(file.closed for file in disk_files)
    assert {"write", "close"}.issubset(disk_operations)
    if outcome in {"success", "handler_error", "cancel"}:
        assert called
        assert {"seek", "read"}.issubset(disk_operations)
    else:
        assert not called
    if outcome in {"success", "oversize"}:
        assert responses[0]["status"] == (200 if outcome == "success" else 413)
        assert (b"cache-control", b"no-store") in responses[0]["headers"]
        if outcome == "success":
            assert json.loads(responses[1]["body"])["sha256"] == hashlib.sha256(payload).hexdigest()
