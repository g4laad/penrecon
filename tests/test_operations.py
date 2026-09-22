from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlmodel import Session
from starlette.testclient import TestClient

from penrecon.db import OPERATION_ATTACHMENTS_DIR
from penrecon.models import OperationLog
from penrecon.queries import operation_logs


def _attachment_files() -> set[Path]:
    if not OPERATION_ATTACHMENTS_DIR.exists():
        return set()
    return {path.resolve() for path in OPERATION_ATTACHMENTS_DIR.iterdir() if path.is_file()}


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
    return client.post("/operations", data=fields, files=files, follow_redirects=False)


def _only_operation_id(client: TestClient) -> int:
    page = client.get("/operations")
    match = re.search(r'id="operation-edit-(\d+)"', page.text)
    assert match is not None
    return int(match.group(1))


def test_operation_logs_orders_dated_then_undated_newest_first(session: Session) -> None:
    dated_old = OperationLog(
        command="dated old",
        started_at=datetime(2026, 9, 20, 8, 0),
        created_at=datetime(2026, 9, 20, 8, 0, tzinfo=UTC),
    )
    dated_new = OperationLog(
        command="dated new",
        started_at=datetime(2026, 9, 21, 8, 0),
        created_at=datetime(2026, 9, 19, 8, 0, tzinfo=UTC),
    )
    undated_old = OperationLog(
        command="undated old",
        created_at=datetime(2026, 9, 18, 8, 0, tzinfo=UTC),
    )
    undated_new = OperationLog(
        command="undated new",
        created_at=datetime(2026, 9, 22, 8, 0, tzinfo=UTC),
    )
    session.add_all([undated_new, dated_old, undated_old, dated_new])
    session.commit()

    assert [row.command for row in operation_logs(session)] == [
        "dated new",
        "dated old",
        "undated new",
        "undated old",
    ]


def test_operation_logs_searches_command_endpoint_tag_and_attachment(session: Session) -> None:
    rows = [
        OperationLog(command="NMAP -SV 10.0.0.1"),
        OperationLog(command="connect", destination="Database.Internal"),
        OperationLog(command="review", tags=["Credential-Audit"]),
        OperationLog(command="inspect", attachment_name="Evidence.TXT"),
        OperationLog(command="unrelated"),
    ]
    session.add_all(rows)
    session.commit()

    assert [row.command for row in operation_logs(session, "nmap")] == ["NMAP -SV 10.0.0.1"]
    assert [row.command for row in operation_logs(session, "DATABASE")] == ["connect"]
    assert [row.command for row in operation_logs(session, "credential-audit")] == ["review"]
    assert [row.command for row in operation_logs(session, "evidence.txt")] == ["inspect"]


def test_operation_logs_blank_query_returns_every_entry(session: Session) -> None:
    session.add_all([OperationLog(command="one"), OperationLog(command="two")])
    session.commit()

    assert {row.command for row in operation_logs(session, "  ")} == {"one", "two"}


def test_operations_full_page_and_htmx_fragment(client: TestClient) -> None:
    full = client.get("/operations")
    assert full.status_code == 200
    assert "<!doctype html>" in full.text.lower()
    assert "Operation log" in full.text

    fragment = client.get("/operations", headers={"HX-Request": "true"})
    assert fragment.status_code == 200
    assert "<html" not in fragment.text.lower()
    assert 'id="operation-table"' in fragment.text


def test_create_operation_round_trips_all_summary_fields(client: TestClient) -> None:
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
    assert response.status_code == 303
    assert response.headers["location"] == "/operations"

    page = client.get("/operations")
    for expected in (
        "nmap -sV target.internal",
        "jump.internal",
        "target.internal",
        "nmap",
        "operator",
        "recon",
        "priority",
    ):
        assert expected in page.text


def test_create_operation_rejects_blank_command(client: TestClient) -> None:
    response = _create_operation(client, command="  ")
    assert response.status_code == 400
    assert "Command is required" in response.text
    assert "No operations recorded yet" in client.get("/operations").text


def test_create_operation_rejects_invalid_date_ranges(client: TestClient) -> None:
    backwards = _create_operation(
        client,
        command="bad range",
        data={"started_at": "2026-09-22T10:00", "ended_at": "2026-09-22T09:59"},
    )
    assert backwards.status_code == 400
    assert "ended_at" in backwards.text

    malformed = _create_operation(
        client,
        command="bad date",
        data={"started_at": "not-a-date"},
    )
    assert malformed.status_code == 400
    assert "started_at" in malformed.text
    page = client.get("/operations")
    assert "bad range" not in page.text
    assert "bad date" not in page.text


def test_edit_preserves_existing_attachment_without_attachment_control(client: TestClient) -> None:
    before_upload = _attachment_files()
    created = _create_operation(
        client,
        command="original command",
        attachment=("original.txt", b"original bytes", "text/plain"),
    )
    assert created.status_code == 303
    after_upload = _attachment_files()
    created_files = after_upload - before_upload
    assert len(created_files) == 1

    operation_id = _only_operation_id(client)
    edited = client.post(
        f"/operations/{operation_id}/edit",
        data={"command": "edited command", "tool": "curl"},
        follow_redirects=False,
    )
    assert edited.status_code == 303
    assert _attachment_files() == after_upload
    download = client.get(f"/operations/{operation_id}/attachment")
    assert download.status_code == 200
    assert download.content == b"original bytes"
    page = client.get("/operations")
    assert "edited command" in page.text
    assert "curl" in page.text


def test_uploaded_attachment_downloads_with_original_name_and_bytes(client: TestClient) -> None:
    before = _attachment_files()
    response = _create_operation(
        client,
        command="collect evidence",
        attachment=("evidence notes.txt", b"evidence\nbytes", "text/plain"),
    )
    assert response.status_code == 303
    after = _attachment_files()
    assert len(after - before) == 1

    operation_id = _only_operation_id(client)
    download = client.get(f"/operations/{operation_id}/attachment")
    assert download.status_code == 200
    assert download.content == b"evidence\nbytes"
    assert "filename*=utf-8''evidence%20notes.txt" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("text/plain")


def test_attachment_replacement_conflict_and_removal(client: TestClient) -> None:
    before_upload = _attachment_files()
    assert _create_operation(
        client,
        command="attach",
        attachment=("old.txt", b"old", "text/plain"),
    ).status_code == 303
    after_upload = _attachment_files()
    old_files = after_upload - before_upload
    assert len(old_files) == 1
    old_file = next(iter(old_files))
    operation_id = _only_operation_id(client)

    before_replace = _attachment_files()
    replaced = client.post(
        f"/operations/{operation_id}/edit",
        data={"command": "attach replaced"},
        files={"attachment": ("new.txt", b"new", "text/plain")},
        follow_redirects=False,
    )
    assert replaced.status_code == 303
    after_replace = _attachment_files()
    new_files = after_replace - before_replace
    assert len(new_files) == 1
    new_file = next(iter(new_files))
    assert old_file not in after_replace
    download = client.get(f"/operations/{operation_id}/attachment")
    assert download.content == b"new"
    assert 'filename="new.txt"' in download.headers["content-disposition"]

    before_conflict = _attachment_files()
    conflict = client.post(
        f"/operations/{operation_id}/edit",
        data={"command": "must not change", "remove_attachment": "true"},
        files={"attachment": ("conflict.txt", b"conflict", "text/plain")},
        follow_redirects=False,
    )
    assert conflict.status_code == 400
    assert _attachment_files() == before_conflict
    assert client.get(f"/operations/{operation_id}/attachment").content == b"new"
    assert "attach replaced" in client.get("/operations").text

    before_remove = _attachment_files()
    removed = client.post(
        f"/operations/{operation_id}/edit",
        data={"command": "attachment removed", "remove_attachment": "true"},
        follow_redirects=False,
    )
    assert removed.status_code == 303
    assert _attachment_files() == before_remove - {new_file}
    assert client.get(f"/operations/{operation_id}/attachment").status_code == 404


def test_delete_operation_removes_row_and_attachment(client: TestClient) -> None:
    before_upload = _attachment_files()
    assert _create_operation(
        client,
        command="delete me",
        attachment=("delete.txt", b"delete", "text/plain"),
    ).status_code == 303
    after_upload = _attachment_files()
    created_files = after_upload - before_upload
    assert len(created_files) == 1
    created_file = next(iter(created_files))
    operation_id = _only_operation_id(client)

    before_delete = _attachment_files()
    deleted = client.post(f"/operations/{operation_id}/delete", follow_redirects=False)
    assert deleted.status_code == 303
    assert _attachment_files() == before_delete - {created_file}
    assert "delete me" not in client.get("/operations").text
    assert client.get(f"/operations/{operation_id}/attachment").status_code == 404


def test_missing_operation_ids_return_404(client: TestClient) -> None:
    assert client.post("/operations/999999/edit", data={"command": "missing"}).status_code == 404
    assert client.post("/operations/999999/delete").status_code == 404
    assert client.get("/operations/999999/attachment").status_code == 404


def test_search_and_pagination_retain_state_and_expected_rows(client: TestClient) -> None:
    for index in range(11):
        assert _create_operation(client, command=f"batch {index:02d}").status_code == 303
    assert _create_operation(
        client,
        command="endpoint result",
        data={"source": "NeedleHost"},
    ).status_code == 303

    search = client.get("/operations", params={"q": "needlehost", "per": "10", "page": "1"})
    assert "endpoint result" in search.text
    assert "batch 10" not in search.text
    assert 'name="q" value="needlehost"' in search.text

    first = client.get("/operations", params={"q": "batch", "per": "10", "page": "1"})
    assert "batch 10" in first.text
    assert "batch 01" in first.text
    assert "batch 00" not in first.text
    assert "q=batch&amp;per=10&amp;page=2" in first.text

    second = client.get(
        "/operations",
        params={"q": "batch", "per": "10", "page": "2"},
        headers={"HX-Request": "true"},
    )
    assert "batch 00" in second.text
    assert "batch 10" not in second.text
    assert '<option value="10" selected>10</option>' in second.text


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
