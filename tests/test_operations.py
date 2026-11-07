from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID, ENGAGEMENT_PREFIX
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlmodel import Session
from starlette.testclient import TestClient

from penrecon.db import engagement_attachments_dir
from penrecon.models import OperationLog
from penrecon.queries import operation_logs

def _assert_outcome(response) -> None:
    assert response.status_code == 200
    assert "location" not in response.headers
    assert response.json() == {"ok": True, "redirect_to": ENGAGEMENT_PREFIX + "/operations"}



def _attachment_files() -> set[Path]:
    directory = engagement_attachments_dir(TEST_ENGAGEMENT_ID)
    if not directory.exists():
        return set()
    return {path.resolve() for path in directory.iterdir() if path.is_file()}


def _create_operation(
    client: TestClient,
    *,
    command: str = "id",
    data: dict[str, str] | None = None,
    attachment: tuple[str, bytes, str] | None = None,
):
    fields = {"command": command}
    if data:
        fields.update(data)
    files = {"attachment": attachment} if attachment is not None else None
    return client.post(ENGAGEMENT_PREFIX + "/operations", data=fields, files=files, follow_redirects=False)


def _only_operation_id(client: TestClient) -> int:
    operations = client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"]
    assert len(operations) == 1
    return int(operations[0]["id"])


def test_operation_logs_orders_dated_then_undated_newest_first(session: Session) -> None:
    dated_old = OperationLog(command="dated old",
        started_at=datetime(2026, 9, 20, 8, 0),
        created_at=datetime(2026, 9, 20, 8, 0, tzinfo=UTC), engagement_id=TEST_ENGAGEMENT_ID)
    dated_new = OperationLog(command="dated new",
        started_at=datetime(2026, 9, 21, 8, 0),
        created_at=datetime(2026, 9, 19, 8, 0, tzinfo=UTC), engagement_id=TEST_ENGAGEMENT_ID)
    undated_old = OperationLog(command="undated old",
        created_at=datetime(2026, 9, 18, 8, 0, tzinfo=UTC), engagement_id=TEST_ENGAGEMENT_ID)
    undated_new = OperationLog(command="undated new",
        created_at=datetime(2026, 9, 22, 8, 0, tzinfo=UTC), engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([undated_new, dated_old, undated_old, dated_new])
    session.commit()

    assert [row.command for row in operation_logs(session, engagement_id=TEST_ENGAGEMENT_ID)] == [
        "dated new",
        "dated old",
        "undated new",
        "undated old",
    ]


def test_operation_logs_searches_command_endpoint_tag_and_attachment(session: Session) -> None:
    rows = [
        OperationLog(command="NMAP -SV 10.0.0.1", engagement_id=TEST_ENGAGEMENT_ID),
        OperationLog(command="connect", destination="Database.Internal", engagement_id=TEST_ENGAGEMENT_ID),
        OperationLog(command="review", tags=["Credential-Audit"], engagement_id=TEST_ENGAGEMENT_ID),
        OperationLog(command="inspect", attachment_name="Evidence.TXT", engagement_id=TEST_ENGAGEMENT_ID),
        OperationLog(command="unrelated", engagement_id=TEST_ENGAGEMENT_ID),
    ]
    session.add_all(rows)
    session.commit()

    assert [row.command for row in operation_logs(session, "nmap", engagement_id=TEST_ENGAGEMENT_ID)] == ["NMAP -SV 10.0.0.1"]
    assert [row.command for row in operation_logs(session, "DATABASE", engagement_id=TEST_ENGAGEMENT_ID)] == ["connect"]
    assert [row.command for row in operation_logs(session, "credential-audit", engagement_id=TEST_ENGAGEMENT_ID)] == ["review"]
    assert [row.command for row in operation_logs(session, "evidence.txt", engagement_id=TEST_ENGAGEMENT_ID)] == ["inspect"]


def test_operation_logs_blank_query_returns_every_entry(session: Session) -> None:
    session.add_all([OperationLog(command="one", engagement_id=TEST_ENGAGEMENT_ID), OperationLog(command="two", engagement_id=TEST_ENGAGEMENT_ID)])
    session.commit()

    assert {row.command for row in operation_logs(session, "  ", engagement_id=TEST_ENGAGEMENT_ID)} == {"one", "two"}


def test_operation_summaries_search_full_text_without_returning_details(session: Session) -> None:
    body = "evidence " * 10000 + "Straße needle"
    session.add(OperationLog(
        command="inspect", output=body, comments="private comment",
        description="private description", engagement_id=TEST_ENGAGEMENT_ID,
    ))
    session.commit()

    statements = []

    def record_sql(connection, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", record_sql)
    try:
        rows = operation_logs(session, "STRASSE NEEDLE", engagement_id=TEST_ENGAGEMENT_ID)
    finally:
        event.remove(engine, "before_cursor_execute", record_sql)
    projections = [statement.split("FROM", 1)[0].lower() for statement in statements]
    assert projections
    assert all("operation_log.output" not in projection and "operation_log.comments" not in projection for projection in projections)
    assert len(rows) == 1
    assert vars(rows[0]).keys() == {"id", "started_at", "destination", "tool", "command"}
    assert rows[0].command == "inspect"




def test_create_operation_round_trips_all_detail_fields(client: TestClient) -> None:
    response = _create_operation(
        client,
        command="  nmap -sV target.internal  ",
        data={
            "started_at": "2026-09-22T09:15",
            "ended_at": "2026-09-22T09:45",
            "source": "  jump.internal  ",
            "destination": "  target.internal  ",
            "tool": "  nmap  ",
            "user_context": "  operator  ",
            "output": "line one\nline two",
            "description": "Service enumeration",
            "comments": "First pass\nReview later",
            "tags": " recon, , priority ",
        },
    )
    _assert_outcome(response)

    operation = client.get(ENGAGEMENT_PREFIX + f"/operations/{_only_operation_id(client)}").json()["operation"]
    assert operation["command"] == "nmap -sV target.internal"
    assert operation["started_at"] == "2026-09-22T09:15:00"
    assert operation["ended_at"] == "2026-09-22T09:45:00"
    assert operation["source"] == "jump.internal"
    assert operation["destination"] == "target.internal"
    assert operation["tool"] == "nmap"
    assert operation["user_context"] == "operator"
    assert operation["output"] == "line one\nline two"
    assert operation["description"] == "Service enumeration"
    assert operation["comments"] == "First pass\nReview later"
    assert operation["tags"] == ["recon", "priority"]


def test_create_operation_rejects_blank_command(client: TestClient) -> None:
    response = _create_operation(client, command="  ")
    assert response.status_code == 400
    assert response.json()["detail"]
    assert client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"] == []


def test_create_operation_rejects_invalid_date_ranges(client: TestClient) -> None:
    backwards = _create_operation(
        client,
        command="bad range",
        data={"started_at": "2026-09-22T10:00", "ended_at": "2026-09-22T09:59"},
    )
    assert backwards.status_code == 400
    assert "ended_at" in backwards.json()["detail"]

    malformed = _create_operation(
        client,
        command="bad date",
        data={"started_at": "not-a-date"},
    )
    assert malformed.status_code == 400
    assert "started_at" in malformed.json()["detail"]
    assert client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"] == []


def test_edit_preserves_existing_attachment_without_attachment_control(client: TestClient) -> None:
    before_upload = _attachment_files()
    created = _create_operation(
        client,
        command="original command",
        attachment=("original.txt", b"original bytes", "text/plain"),
    )
    _assert_outcome(created)
    after_upload = _attachment_files()
    created_files = after_upload - before_upload
    assert len(created_files) == 1

    operation_id = _only_operation_id(client)
    edited = client.post(
        ENGAGEMENT_PREFIX + f"/operations/{operation_id}/edit",
        data={"command": "edited command", "tool": "curl"},
        follow_redirects=False,
    )
    _assert_outcome(edited)
    assert _attachment_files() == after_upload
    download = client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment")
    assert download.status_code == 200
    assert download.content == b"original bytes"
    operation = client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"][0]
    assert operation["command"] == "edited command"
    assert operation["tool"] == "curl"


def test_uploaded_attachment_downloads_with_original_name_and_bytes(client: TestClient) -> None:
    before = _attachment_files()
    response = _create_operation(
        client,
        command="collect evidence",
        attachment=("evidence notes.txt", b"evidence\nbytes", "text/plain"),
    )
    _assert_outcome(response)
    after = _attachment_files()
    assert len(after - before) == 1
    operation = client.get(ENGAGEMENT_PREFIX + f"/operations/{_only_operation_id(client)}").json()["operation"]
    assert operation["attachment_name"] == "evidence notes.txt"
    assert {"attachment_path", "engagement_id"}.isdisjoint(operation)

    operation_id = _only_operation_id(client)
    download = client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment")
    assert download.status_code == 200
    assert download.content == b"evidence\nbytes"
    assert "filename*=utf-8''evidence%20notes.txt" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("text/plain")


def test_attachment_replacement_conflict_and_removal(client: TestClient) -> None:
    before_upload = _attachment_files()
    _assert_outcome(_create_operation(
        client,
        command="attach",
        attachment=("old.txt", b"old", "text/plain"),
    ))
    after_upload = _attachment_files()
    old_files = after_upload - before_upload
    assert len(old_files) == 1
    old_file = next(iter(old_files))
    operation_id = _only_operation_id(client)

    before_replace = _attachment_files()
    replaced = client.post(
        ENGAGEMENT_PREFIX + f"/operations/{operation_id}/edit",
        data={"command": "attach replaced"},
        files={"attachment": ("new.txt", b"new", "text/plain")},
        follow_redirects=False,
    )
    _assert_outcome(replaced)
    after_replace = _attachment_files()
    new_files = after_replace - before_replace
    assert len(new_files) == 1
    new_file = next(iter(new_files))
    assert old_file not in after_replace
    download = client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment")
    assert download.content == b"new"
    assert 'filename="new.txt"' in download.headers["content-disposition"]

    before_conflict = _attachment_files()
    conflict = client.post(
        ENGAGEMENT_PREFIX + f"/operations/{operation_id}/edit",
        data={"command": "must not change", "remove_attachment": "true"},
        files={"attachment": ("conflict.txt", b"conflict", "text/plain")},
        follow_redirects=False,
    )
    assert conflict.status_code == 400
    assert _attachment_files() == before_conflict
    assert client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment").content == b"new"
    assert client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"][0]["command"] == "attach replaced"

    before_remove = _attachment_files()
    removed = client.post(
        ENGAGEMENT_PREFIX + f"/operations/{operation_id}/edit",
        data={"command": "attachment removed", "remove_attachment": "true"},
        follow_redirects=False,
    )
    _assert_outcome(removed)
    assert _attachment_files() == before_remove - {new_file}
    assert client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment").status_code == 404


def test_delete_operation_removes_row_and_attachment(client: TestClient) -> None:
    before_upload = _attachment_files()
    _assert_outcome(_create_operation(
        client,
        command="delete me",
        attachment=("delete.txt", b"delete", "text/plain"),
    ))
    after_upload = _attachment_files()
    created_files = after_upload - before_upload
    assert len(created_files) == 1
    created_file = next(iter(created_files))
    operation_id = _only_operation_id(client)

    before_delete = _attachment_files()
    deleted = client.post(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/delete", follow_redirects=False)
    _assert_outcome(deleted)
    assert _attachment_files() == before_delete - {created_file}
    assert client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"] == []
    assert client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment").status_code == 404


def test_missing_operation_ids_return_404(client: TestClient) -> None:
    assert client.get(ENGAGEMENT_PREFIX + "/operations/999999").status_code == 404
    assert client.post(ENGAGEMENT_PREFIX + "/operations/999999/edit", data={"command": "missing"}).status_code == 404
    assert client.post(ENGAGEMENT_PREFIX + "/operations/999999/delete").status_code == 404
    assert client.get(ENGAGEMENT_PREFIX + "/operations/999999/attachment").status_code == 404


def test_search_and_pagination_retain_state_and_expected_rows(client: TestClient) -> None:
    for index in range(11):
        _assert_outcome(_create_operation(client, command=f"batch {index:02d}"))
    _assert_outcome(_create_operation(
        client,
        command="endpoint result",
        data={"source": "NeedleHost"},
    ))

    search = client.get(ENGAGEMENT_PREFIX + "/operations", params={"q": "needlehost", "per": "10", "page": "1"}).json()
    assert [row["command"] for row in search["operations"]] == ["endpoint result"]
    assert search["q"] == "needlehost"
    assert search["total"] == 1

    first = client.get(ENGAGEMENT_PREFIX + "/operations", params={"q": "batch", "per": "10", "page": "1"}).json()
    assert [row["command"] for row in first["operations"]] == [
        f"batch {index:02d}" for index in range(10, 0, -1)
    ]
    assert first["q"] == "batch"
    assert first["page"] == 1
    assert first["pages"] == 2
    assert first["per"] == "10"
    assert first["total"] == 11

    second = client.get(ENGAGEMENT_PREFIX + "/operations", params={"q": "batch", "per": "10", "page": "2"}).json()
    assert [row["command"] for row in second["operations"]] == ["batch 00"]
    assert second["page"] == 2
    assert second["per"] == "10"


def test_failed_attachment_write_and_commit_leave_no_new_file(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    before_write = _attachment_files()

    def fail_copy(source, target) -> None:
        target.write(b"partial")
        raise OSError("simulated write failure")

    with monkeypatch.context() as patch:
        patch.setattr(shutil, "copyfileobj", fail_copy)
        with pytest.raises(OSError, match="simulated write failure"):
            _create_operation(
                client,
                command="write failure",
                attachment=("partial.txt", b"payload", "text/plain"),
            )
    assert _attachment_files() == before_write

    before_commit = _attachment_files()

    def fail_commit(self: Session) -> None:
        raise RuntimeError("simulated commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(Session, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            _create_operation(
                client,
                command="commit failure",
                attachment=("orphan.txt", b"payload", "text/plain"),
            )
    assert _attachment_files() == before_commit


def test_operation_mixed_timezone_inputs_return_validation_error(client: TestClient) -> None:
    response = _create_operation(client, data={
        "started_at": "2026-09-22T10:00+02:00", "ended_at": "2026-09-22T11:00",
    })
    assert response.status_code == 400
    assert "timezone" in response.json()["detail"].lower()
    assert client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"] == []


def test_operation_aware_dates_are_normalized_before_storage(client: TestClient) -> None:
    response = _create_operation(client, data={
        "started_at": "2026-09-22T10:00+02:00", "ended_at": "2026-09-22T08:30Z",
    })
    _assert_outcome(response)
    operation = client.get(ENGAGEMENT_PREFIX + f"/operations/{_only_operation_id(client)}").json()["operation"]
    assert operation["started_at"] == "2026-09-22T08:00:00"
    assert operation["ended_at"] == "2026-09-22T08:30:00"


@pytest.mark.parametrize("action", ["replace", "remove", "delete"])
def test_attachment_cleanup_failure_reports_committed_mutation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    before = _attachment_files()
    _assert_outcome(_create_operation(client, attachment=("old.txt", b"old", "text/plain")))
    old_file = next(iter(_attachment_files() - before))
    operation_id = _only_operation_id(client)
    original_unlink = Path.unlink

    def deny_old_unlink(path: Path, missing_ok: bool = False) -> None:
        if path.resolve() == old_file:
            raise PermissionError("locked attachment")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", deny_old_unlink)
    if action == "delete":
        response = client.post(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/delete", follow_redirects=False)
    else:
        response = client.post(
            ENGAGEMENT_PREFIX + f"/operations/{operation_id}/edit",
            data={"command": "committed", "remove_attachment": str(action == "remove").lower()},
            files={"attachment": ("new.txt", b"new", "text/plain")} if action == "replace" else None,
            follow_redirects=False,
        )
    assert response.status_code == 200
    assert response.json()["committed"] is True
    assert response.json()["cleanup_pending"] is True
    assert response.json()["redirect_to"] == ENGAGEMENT_PREFIX + "/operations"
    assert response.json()["detail"]
    assert set(response.json()) == {"ok", "committed", "cleanup_pending", "detail", "redirect_to"}
    assert "location" not in response.headers
    assert old_file.is_file()
    operations = client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"]
    if action == "delete":
        assert operations == []
    else:
        assert operations[0]["command"] == "committed"
        download = client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment")
        assert download.content == b"new" if action == "replace" else download.status_code == 404


def test_failed_attachment_replacement_keeps_old_metadata_and_file(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_outcome(_create_operation(client, command="original", attachment=("old.txt", b"old", "text/plain")))
    operation_id = _only_operation_id(client)
    before = _attachment_files()

    def fail_commit(session: Session) -> None:
        raise RuntimeError("replacement commit failed")

    with monkeypatch.context() as patch:
        patch.setattr(Session, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="replacement commit failed"):
            client.post(
                ENGAGEMENT_PREFIX + f"/operations/{operation_id}/edit",
                data={"command": "discard"},
                files={"attachment": ("new.txt", b"new", "text/plain")},
            )
    assert _attachment_files() == before
    assert client.get(ENGAGEMENT_PREFIX + "/operations").json()["operations"][0]["command"] == "original"
    assert client.get(ENGAGEMENT_PREFIX + f"/operations/{operation_id}/attachment").content == b"old"
