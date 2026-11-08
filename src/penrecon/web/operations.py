"""Operation-log API and transactional attachment storage."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel
from sqlmodel import Session

from penrecon import commands
from penrecon.queries import operations as operation_queries
from penrecon.queries import ownership as ownership_queries
from penrecon.queries import pagination as pagination_queries
from penrecon.db import DATA_DIR, engagement_attachments_dir, get_session
from penrecon.models import OperationLog
from penrecon.web.common import (
    MAX_UPLOAD_BYTES,
    ErrorResponse,
    MutationResponse,
    invalid_command,
    mutation_response,
    require_engagement,
)
from penrecon.web.serialization import encode_page


class OperationSummary(BaseModel):
    id: int
    started_at: datetime | None
    destination: str
    tool: str
    command: str


class OperationDetail(OperationSummary):
    ended_at: datetime | None
    source: str
    user_context: str
    output: str
    description: str
    comments: str
    tags: list[str]
    attachment_name: str | None
    created_at: datetime
    updated_at: datetime


class OperationsPage(BaseModel):
    operations: list[OperationSummary]
    total: int
    q: str
    page: int
    pages: int
    per: str


class OperationDetailResponse(BaseModel):
    operation: OperationDetail


router = APIRouter(
    tags=["operations"],
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)


@dataclass(frozen=True)
class _OperationForm:
    started_at: datetime | None
    ended_at: datetime | None
    source: str
    destination: str
    tool: str
    user_context: str
    command: str
    output: str
    description: str
    comments: str
    tags: list[str]


def _parse_operation_datetime(raw: str, field: str) -> datetime | None:
    value = raw.strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise commands.InvalidCommand(field, f"Invalid {field} date-time.") from exc


@dataclass(frozen=True)
class _OperationInput:
    """Bind raw form fields once; handlers choose when validation runs."""

    started_at: str = Form("")
    ended_at: str = Form("")
    source: str = Form("")
    destination: str = Form("")
    tool: str = Form("")
    user_context: str = Form("")
    command: str = Form("")
    output: str = Form("")
    description: str = Form("")
    comments: str = Form("")
    tags: str = Form("")

    def normalize(self) -> _OperationForm:
        parsed_start = _parse_operation_datetime(self.started_at, "started_at")
        parsed_end = _parse_operation_datetime(self.ended_at, "ended_at")
        clean_command = self.command.strip()
        if not clean_command:
            raise commands.InvalidCommand("command", "Command is required.")
        if parsed_start is not None and parsed_end is not None and (
            (parsed_start.utcoffset() is None) != (parsed_end.utcoffset() is None)
        ):
            raise commands.InvalidCommand("ended_at", "Use the same timezone convention for started_at and ended_at.")
        if parsed_start is not None and parsed_end is not None and parsed_end < parsed_start:
            raise commands.InvalidCommand("ended_at", "ended_at must not be earlier than started_at.")
        return _OperationForm(
            # SQLite stores naive datetimes: aware inputs must first become UTC
            # rather than silently losing their offset. Naive operator-local
            # times remain naive; mixing the conventions is rejected above.
            started_at=parsed_start.astimezone(UTC).replace(tzinfo=None) if parsed_start is not None and parsed_start.utcoffset() is not None else parsed_start,
            ended_at=parsed_end.astimezone(UTC).replace(tzinfo=None) if parsed_end is not None and parsed_end.utcoffset() is not None else parsed_end,
            source=self.source.strip(),
            destination=self.destination.strip(),
            tool=self.tool.strip(),
            user_context=self.user_context.strip(),
            command=clean_command,
            output=self.output,
            description=self.description,
            comments=self.comments,
            tags=[tag.strip() for tag in self.tags.split(",") if tag.strip()],
        )


def _apply_operation_form(operation: OperationLog, values: _OperationForm) -> None:
    operation.started_at = values.started_at
    operation.ended_at = values.ended_at
    operation.source = values.source
    operation.destination = values.destination
    operation.tool = values.tool
    operation.user_context = values.user_context
    operation.command = values.command
    operation.output = values.output
    operation.description = values.description
    operation.comments = values.comments
    operation.tags = values.tags


def _safe_attachment_path(stored_path: str | None, *, engagement_id: str) -> Path | None:
    if stored_path is None:
        return None
    root = engagement_attachments_dir(engagement_id).resolve()
    try:
        if Path(stored_path).is_absolute():
            return None
        path = (DATA_DIR / stored_path).resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    return path


def _remove_operation_attachment(stored_path: str | None, *, engagement_id: str) -> None:
    path = _safe_attachment_path(stored_path, engagement_id=engagement_id)
    if path is not None:
        path.unlink(missing_ok=True)


def _save_operation_attachment(upload: UploadFile, *, engagement_id: str) -> tuple[str, str, str | None]:
    original_name = Path(upload.filename or "").name
    if not original_name:
        raise commands.InvalidCommand("attachment", "Attachment filename is required.")
    directory = engagement_attachments_dir(engagement_id)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / uuid4().hex
    try:
        with destination.open("xb") as target:
            written = 0
            while chunk := upload.file.read(64 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Attachment exceeds the 32 MiB limit.")
                target.write(chunk)
    except Exception as exc:
        try:
            destination.unlink(missing_ok=True)
        except OSError as cleanup:
            exc.add_note(f"Partial attachment cleanup pending: {cleanup}")
        raise
    return original_name, str(destination.relative_to(DATA_DIR)), upload.content_type


class _AttachmentAction(StrEnum):
    keep = "keep"
    replacement = "replace"
    remove = "remove"


@dataclass
class _AttachmentChange:
    """One guarded file transition; old bytes survive until metadata commits."""

    action: _AttachmentAction
    upload: UploadFile | None
    old_path: str | None
    new_path: str | None = None

    @classmethod
    def choose(cls, operation: OperationLog, upload: UploadFile | None, remove: bool = False) -> _AttachmentChange:
        replacing = upload is not None and bool(upload.filename)
        if replacing and remove:
            raise commands.InvalidCommand("attachment", "Cannot replace and remove an attachment in the same request.")
        return cls(
            _AttachmentAction.replacement if replacing else _AttachmentAction.remove if remove else _AttachmentAction.keep,
            upload, operation.attachment_path,
        )

    def stage(self, operation: OperationLog) -> None:
        if self.action == _AttachmentAction.replacement:
            assert self.upload is not None
            name, self.new_path, media_type = _save_operation_attachment(self.upload, engagement_id=operation.engagement_id)
            operation.attachment_name = name
            operation.attachment_path = self.new_path
            operation.attachment_media_type = media_type
        elif self.action == _AttachmentAction.remove:
            operation.attachment_name = None
            operation.attachment_path = None
            operation.attachment_media_type = None

    def compensate(self, engagement_id: str, failure: Exception) -> None:
        try:
            _remove_operation_attachment(self.new_path, engagement_id=engagement_id)
        except OSError as cleanup:
            failure.add_note(f"New attachment cleanup pending after rollback: {cleanup}")
            logging.getLogger(__name__).warning("Rolled-back attachment cleanup pending: %s", cleanup)

    def finish(self, engagement_id: str) -> bool:
        if self.action == _AttachmentAction.keep:
            return False
        try:
            _remove_operation_attachment(self.old_path, engagement_id=engagement_id)
        except OSError:
            logging.getLogger(__name__).warning("Committed operation attachment cleanup pending: %s", self.old_path, exc_info=True)
            return True
        return False


def _commit_operation(
    session: Session, operation: OperationLog, change: _AttachmentChange,
    values: _OperationForm | None,
) -> bool:
    """Commit edit/create/delete, compensate only uncommitted new files.

    Returns whether obsolete-file cleanup remains after a successful commit.
    No exception from that cleanup may imply that the database mutation failed.
    """
    engagement_id = operation.engagement_id
    try:
        if values is None:
            session.delete(operation)
        else:
            _apply_operation_form(operation, values)
            operation.updated_at = datetime.now(UTC)
            change.stage(operation)
            session.add(operation)
        session.commit()
    except Exception as exc:
        try:
            session.rollback()
        except Exception as rollback:
            exc.add_note(f"Operation rollback failed: {rollback}")
        change.compensate(engagement_id, exc)
        raise
    return change.finish(engagement_id)


def _operation_committed_response(engagement_id: str, cleanup_pending: bool, *, deleted: bool = False) -> Response:
    destination = f"/{engagement_id}/operations"
    if cleanup_pending:
        return JSONResponse({
            "ok": True, "committed": True, "cleanup_pending": True,
            "detail": f"Operation {'deleted' if deleted else 'saved'}; obsolete attachment cleanup could not finish.",
            "redirect_to": destination,
        })
    return mutation_response(destination)


def _operations_ctx(
    session: Session, q: str, page: int, per: str, *, engagement_id: str,
) -> dict[str, object]:
    normalized_per = (
        per
        if per == "all" or (len(per) <= 10 and per.isascii() and per.isdecimal() and int(per) in pagination_queries.PER_PAGE_OPTIONS)
        else "25"
    )
    result = operation_queries.operation_logs(
        session, q, engagement_id=engagement_id,
        page=page, per_page=pagination_queries.resolve_per_page(normalized_per),
    )
    return {
        "operations": result.operations,
        "total": result.total,
        "q": q,
        "page": result.page,
        "pages": result.pages,
        "per": normalized_per,
    }


@router.get("/operations", response_model=OperationsPage)
def operations_page(
    q: str = "",
    page: int = 1,
    per: str = "25",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return JSONResponse(encode_page(_operations_ctx(session, q, page, per, engagement_id=engagement_id)))




@router.get("/operations/{operation_id}", response_model=OperationDetailResponse)
def operation_detail(
    operation_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    operation = ownership_queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        raise HTTPException(
            status_code=404, detail="operation not found", headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        encode_page({"operation": operation}), headers={"Cache-Control": "no-store"},
    )


@router.post("/operations", response_model=MutationResponse)
def create_operation(
    form: _OperationInput = Depends(_OperationInput),
    attachment: UploadFile | None = File(None, description="Optional attachment, limited to 32 MiB."),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    try:
        values = form.normalize()
    except commands.InvalidCommand as exc:
        return invalid_command(exc)
    operation = OperationLog(command=values.command, engagement_id=engagement_id)
    change = _AttachmentChange.choose(operation, attachment)
    try:
        cleanup_pending = _commit_operation(session, operation, change, values)
    except commands.InvalidCommand as exc:
        return invalid_command(exc)
    return _operation_committed_response(engagement_id, cleanup_pending)


@router.put("/operations/{operation_id}", response_model=MutationResponse)
def edit_operation(
    operation_id: int,
    form: _OperationInput = Depends(_OperationInput),
    remove_attachment: bool = Form(False),
    attachment: UploadFile | None = File(None, description="Optional replacement attachment, limited to 32 MiB."),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Replace editable fields; keep, replace, or explicitly remove the attachment."""
    operation = ownership_queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        return JSONResponse({"detail": "operation not found"}, status_code=404)
    try:
        change = _AttachmentChange.choose(operation, attachment, remove_attachment)
        values = form.normalize()
    except commands.InvalidCommand as exc:
        return invalid_command(exc)
    try:
        cleanup_pending = _commit_operation(session, operation, change, values)
    except commands.InvalidCommand as exc:
        return invalid_command(exc)
    return _operation_committed_response(engagement_id, cleanup_pending)


@router.delete("/operations/{operation_id}", response_model=MutationResponse)
def delete_operation(
    operation_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session),
) -> Response:
    operation = ownership_queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        return JSONResponse({"detail": "operation not found"}, status_code=404)
    change = _AttachmentChange.choose(operation, None, remove=True)
    cleanup_pending = _commit_operation(session, operation, change, None)
    return _operation_committed_response(engagement_id, cleanup_pending, deleted=True)


@router.get(
    "/operations/{operation_id}/attachment",
    response_class=FileResponse,
    response_model=None,
    responses={
        200: {
            "description": "Download the original attachment as inert binary content.",
            "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}},
            "headers": {
                "Content-Disposition": {"schema": {"type": "string"}, "description": "Attachment disposition with the original filename."},
                "X-Content-Type-Options": {"schema": {"type": "string", "const": "nosniff"}},
            },
        },
    },
)
def download_operation_attachment(
    operation_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session),
) -> Response:
    operation = ownership_queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None or not operation.attachment_name:
        return JSONResponse({"detail": "attachment not found"}, status_code=404)
    path = _safe_attachment_path(operation.attachment_path, engagement_id=engagement_id)
    if path is None or not path.is_file():
        return JSONResponse({"detail": "attachment not found"}, status_code=404)
    return FileResponse(
        path,
        filename=operation.attachment_name,
        media_type="application/octet-stream",
        content_disposition_type="attachment",
    )
