"""Workspace catalog and editable engagement metadata."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlmodel import Session, col, select

from penrecon.db import get_session
from penrecon.models import Engagement
from penrecon.web.common import MutationResponse, mutation_response

router = APIRouter(tags=["Engagements"])


class EngagementResponse(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime


class CatalogResponse(BaseModel):
    catalog: list[EngagementResponse]
    sort: str
    direction: str


@router.get("/engagements", response_model=CatalogResponse)
def catalog(
    sort: str = "created_at", dir: str = "", session: Session = Depends(get_session)
) -> dict[str, object]:
    sort = sort if sort in ("name", "created_at") else "created_at"
    direction = dir if dir in ("asc", "desc") else "asc" if sort == "name" else "desc"
    order = (
        col(Engagement.name).collate("NOCASE")
        if sort == "name"
        else col(Engagement.created_at)
    )
    rows = session.exec(
        select(Engagement).order_by(
            order.desc() if direction == "desc" else order.asc(),
            col(Engagement.id).asc(),
        )
    ).all()
    return {"catalog": rows, "sort": sort, "direction": direction}


@router.post(
    "/engagements", response_model=MutationResponse, response_model_exclude_unset=True
)
def create_engagement(
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
) -> JSONResponse:
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(400, detail="Enter an engagement name.")
    engagement = Engagement(name=clean_name, description=description.strip())
    session.add(engagement)
    session.commit()
    session.refresh(engagement)
    return mutation_response(f"/{engagement.id}/")


@router.put(
    "/engagements", response_model=MutationResponse, response_model_exclude_unset=True
)
def edit_engagement(
    engagement_id: str = Query(..., min_length=1),
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
) -> dict[str, bool]:
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(404, detail="engagement not found")
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(400, detail="Enter an engagement name.")
    engagement.name = clean_name
    engagement.description = description.strip()
    session.commit()
    return {"ok": True}
