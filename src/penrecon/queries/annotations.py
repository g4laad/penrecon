from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlmodel import Session, select

from penrecon.models import Annotation, Host, Note, Status
from penrecon.queries.ownership import get_owned


@dataclass
class NoteHit:
    """One note matched by an engagement-wide search, linked back to its target."""

    href: str
    where: str  # human label of the annotated entity (IP, IP·port/proto, hostname)
    kind: str  # "host" | "service" | "hostname"
    title: str
    preview: str


def get_annotation(
    session: Session,
    *,
    engagement_id: str,
    host_id: int | None = None,
    service_id: int | None = None,
) -> Annotation | None:
    """The triage annotation for a host or service. Pass exactly one id."""
    assert (host_id is None) != (service_id is None), "pass exactly one target id"
    if host_id is not None:
        return session.exec(
            select(Annotation).where(
                Annotation.engagement_id == engagement_id, Annotation.host_id == host_id
            )
        ).first()
    return session.exec(
        select(Annotation).where(
            Annotation.engagement_id == engagement_id,
            Annotation.service_id == service_id,
        )
    ).first()


def upsert_annotation(
    session: Session,
    status: Status,
    tags: list[str],
    *,
    engagement_id: str,
    host_id: int | None = None,
    service_id: int | None = None,
) -> Annotation:
    """Save a free status classification and tags; existence means triaged.

    No status is terminal and returning to ``new`` does not remove triage.
    """
    ann = get_annotation(
        session, host_id=host_id, service_id=service_id, engagement_id=engagement_id
    )
    if ann is None:
        ann = Annotation(
            engagement_id=engagement_id, host_id=host_id, service_id=service_id
        )
        session.add(ann)
    ann.status = status
    ann.tags = tags
    ann.updated_at = datetime.now(UTC)
    session.commit()
    return ann


def notes_for(session: Session, host_id: int, *, engagement_id: str) -> list[Note]:
    """All notes on a host, oldest first."""
    return list(
        session.exec(
            select(Note)
            .where(Note.engagement_id == engagement_id, Note.host_id == host_id)
            .order_by(Note.created_at)  # type: ignore[arg-type]
        ).all()
    )


def _note_preview(body: str, ql: str, width: int = 200) -> str:
    """A short excerpt of the note body, windowed around the first match of ``ql``."""
    body = body.strip()
    if not body:
        return ""
    i = body.lower().find(ql)
    if i < 0:  # matched on a tag, not the body — show the body's opening
        return body[:width] + ("…" if len(body) > width else "")
    start = max(0, i - 60)
    end = min(len(body), i + len(ql) + 140)
    return (
        ("…" if start else "")
        + body[start:end].strip()
        + ("…" if end < len(body) else "")
    )


def search_notes(session: Session, ql: str, *, engagement_id: str) -> list[NoteHit]:
    """Notes whose title or body contains ``ql`` (already lowercased). Notes live
    only on hosts, and the FK cascade drops them with the host, so the host
    always exists (the None guard is just for the type checker)."""
    hits: list[NoteHit] = []
    for note in session.exec(
        select(Note).where(Note.engagement_id == engagement_id)
    ).all():
        if ql not in note.title.lower() and ql not in note.body_md.lower():
            continue
        host = get_owned(session, Host, note.host_id, engagement_id=engagement_id)
        if host is None:  # ponytail: unreachable under FK, keeps mypy happy
            continue
        hits.append(
            NoteHit(
                href=f"/{engagement_id}/hosts/{host.id}",
                where=host.ip,
                kind="host",
                title=note.title,
                preview=_note_preview(note.body_md, ql),
            )
        )
    return hits
