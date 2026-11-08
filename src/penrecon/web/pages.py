"""HTML document routes. Domain data is loaded exclusively through /api."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session

from penrecon.db import get_session
from penrecon.models import Engagement
from penrecon.web.common import bootstrap_data, load_engagement

router = APIRouter(include_in_schema=False)
_HERE = Path(__file__).parent


def shell(session: Session, engagement_id: str | None = None) -> HTMLResponse:
    engagement = session.get(Engagement, engagement_id) if engagement_id else None
    serialized = json.dumps(
        bootstrap_data(session, engagement),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    for char, escaped in (
        ("&", "\\u0026"),
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        serialized = serialized.replace(char, escaped)
    css_version = (_HERE / "static/ui/app.css").stat().st_mtime_ns
    js_version = (_HERE / "static/ui/app.js").stat().st_mtime_ns
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>penrecon</title><link rel="stylesheet" href="/static/ui/app.css?v={css_version}">'
        '</head><body><div id="root"></div>'
        f'<script id="page-data" type="application/json">{serialized}</script>'
        f'<script type="module" src="/static/ui/app.js?v={js_version}"></script></body></html>'
    )


@router.get("/")
def landing() -> RedirectResponse:
    return RedirectResponse("/engagements", status_code=303)


@router.get("/engagements", response_class=HTMLResponse)
def catalog_page(session: Session = Depends(get_session)) -> HTMLResponse:
    return shell(session)


@router.get("/{engagement_id}/", response_class=HTMLResponse)
@router.get("/{engagement_id}/hosts/{host_id}", response_class=HTMLResponse)
@router.get("/{engagement_id}/credentials", response_class=HTMLResponse)
@router.get("/{engagement_id}/scans", response_class=HTMLResponse)
@router.get("/{engagement_id}/diff", response_class=HTMLResponse)
@router.get("/{engagement_id}/operations", response_class=HTMLResponse)
@router.get("/{engagement_id}/search", response_class=HTMLResponse)
def engagement_page(
    request: Request, engagement_id: str, session: Session = Depends(get_session)
) -> HTMLResponse:
    load_engagement(request, engagement_id, session)
    return shell(session, engagement_id)
