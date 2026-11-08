from __future__ import annotations

from dataclasses import dataclass, field

from sqlmodel import Session, col, select

from penrecon.models import Credential, CredentialHost, Host
from penrecon.queries.annotations import NoteHit, search_notes
from penrecon.queries.credentials import CredentialHit, LinkedHost
from penrecon.queries.inventory import HostRow, host_rows


@dataclass
class SearchResults:
    q: str
    hosts: list[HostRow] = field(default_factory=list)
    notes: list[NoteHit] = field(default_factory=list)
    credentials: list[CredentialHit] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.hosts) + len(self.notes) + len(self.credentials)


def search(session: Session, q: str, *, engagement_id: str) -> SearchResults:
    """Search this engagement's hosts/hostnames/services, notes, tags and credentials.
    Empty queries return nothing (the page shows a hint instead)."""
    ql = q.strip().lower()
    if not ql:
        return SearchResults(q="")
    creds = [
        CredentialHit(cid, kind, username, [])
        for cid, kind, username, notes in session.exec(
            select(Credential.id, Credential.kind, Credential.username, Credential.notes)
            .where(Credential.engagement_id == engagement_id)
            .order_by(Credential.created_at.desc())  # type: ignore[attr-defined]
        ).all()
        if cid is not None and (ql in username.lower() or ql in notes.lower())
    ]
    if creds:
        hits_by_id = {c.id: c for c in creds}
        for cid, hid, ip in session.exec(
            select(CredentialHost.credential_id, Host.id, Host.ip)
            .join(Host, Host.id == CredentialHost.host_id)  # type: ignore[arg-type]
            .where(
                CredentialHost.engagement_id == engagement_id,
                Host.engagement_id == engagement_id,
                col(CredentialHost.credential_id).in_(hits_by_id),
            )
            .order_by(Host.ip)
        ).all():
            if hid is not None:
                hits_by_id[cid].hosts.append(LinkedHost(hid, ip))
    return SearchResults(
        q=q.strip(),
        hosts=host_rows(session, engagement_id=engagement_id, q=ql),
        notes=search_notes(session, ql, engagement_id=engagement_id),
        credentials=creds,
    )
