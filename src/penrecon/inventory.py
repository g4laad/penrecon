"""Inventory mutations shared by manual editing and scan ingestion."""

from datetime import datetime

from sqlmodel import Session, select

from penrecon.models import Hostname, HostHostname


def link_hostname(
    session: Session, host_id: int, name: str, now: datetime, *, engagement_id: str
) -> None:
    """Link a hostname without committing or changing a sticky hidden flag."""
    hn = session.exec(
        select(Hostname).where(Hostname.engagement_id == engagement_id, Hostname.name == name)
    ).first()
    if hn is None:
        hn = Hostname(engagement_id=engagement_id, name=name)
        session.add(hn)
        session.flush()
    assert hn.id is not None
    link = session.exec(
        select(HostHostname).where(
            HostHostname.engagement_id == engagement_id,
            HostHostname.host_id == host_id, HostHostname.hostname_id == hn.id
        )
    ).first()
    if link is None:
        session.add(HostHostname(
            engagement_id=engagement_id, host_id=host_id, hostname_id=hn.id, last_seen=now
        ))
    else:
        link.last_seen = now
