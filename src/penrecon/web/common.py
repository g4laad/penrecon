"""Shared HTTP contracts and engagement dependency; no domain mutation logic."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, col, select

from penrecon import commands
from penrecon.db import get_session
from penrecon.models import Engagement, Host
from penrecon.queries import ownership as ownership_queries

MAX_UPLOAD_BYTES = 32 * 1024 * 1024


class ErrorResponse(BaseModel):
    detail: str
    field_errors: dict[str, str] = Field(default_factory=dict)


class MutationResponse(BaseModel):
    ok: Literal[True]
    redirect_to: str | None = None
    committed: bool | None = None
    cleanup_pending: bool | None = None
    detail: str | None = None


ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorResponse} for code in (400, 403, 404, 409, 413, 422)
}


def load_engagement(request: Request, engagement_id: str, session: Session) -> str:
    """Validate ownership scope for either a document path or API query."""
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    request.state.engagement = engagement
    return engagement_id


def require_engagement(
    request: Request,
    engagement_id: str = Query(
        ..., min_length=1, description="Engagement owning the requested resources."
    ),
    session: Session = Depends(get_session),
) -> str:
    return load_engagement(request, engagement_id, session)


def owned_host(session: Session, host_id: int, *, engagement_id: str) -> Host:
    """Return an engagement-owned host; missing and foreign hosts both return 404."""
    host = ownership_queries.get_owned(
        session, Host, host_id, engagement_id=engagement_id
    )
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    return host


def bootstrap_data(
    session: Session, engagement: Engagement | None = None
) -> dict[str, object]:
    return {
        "engagement": {"id": engagement.id, "name": engagement.name}
        if engagement
        else None,
        "engagements": [
            {"id": engagement_id, "name": name}
            for engagement_id, name in session.exec(
                select(Engagement.id, Engagement.name).order_by(
                    col(Engagement.created_at).desc()
                )
            ).all()
        ],
    }


def mutation_response(redirect_to: str) -> JSONResponse:
    """Return a document navigation hint, never an HTTP redirect from the API."""
    return JSONResponse({"ok": True, "redirect_to": redirect_to})


def invalid_command(
    exc: commands.InvalidCommand, *, status_code: int = 400
) -> JSONResponse:
    return JSONResponse(
        {
            "detail": exc.public_message,
            "field_errors": {exc.field: exc.public_message},
        },
        status_code=status_code,
    )
