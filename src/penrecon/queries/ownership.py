from __future__ import annotations

from typing import TypeVar

from sqlalchemy import inspect
from sqlmodel import Session, select

from penrecon.models import EngagementOwned


_Owned = TypeVar("_Owned", bound=EngagementOwned)


def get_owned(
    session: Session,
    model: type[_Owned],
    identity: int | tuple[int, ...],
    *,
    engagement_id: str,
) -> _Owned | None:
    """Fetch an entity or link by its existing primary key within an engagement."""
    values = identity if isinstance(identity, tuple) else (identity,)
    mapper = inspect(model)
    assert mapper is not None
    primary_key = mapper.primary_key
    if len(values) != len(primary_key):
        raise ValueError("identity does not match the model primary key")
    return session.exec(
        select(model).where(
            model.engagement_id == engagement_id,
            *(column == value for column, value in zip(primary_key, values, strict=True)),
        )
    ).first()
