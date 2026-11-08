"""Inventory mutations shared by manual editing and scan ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address

from sqlmodel import Session, col, select

from penrecon.models import Host, HostHostname, Hostname, Service


def normalize_ip(raw: str) -> str:
    """Canonical IPv4/IPv6 identity; invalid input raises ``ValueError``."""
    return str(ip_address(raw.strip()))


def same_ip(left: str, right: str) -> bool:
    """Compare legacy spellings without rejecting unrelated malformed old rows."""
    try:
        return normalize_ip(left) == normalize_ip(right)
    except ValueError:
        return False


def find_host_by_ip(
    session: Session,
    ip: str,
    *,
    engagement_id: str,
    excluding: int | None = None,
) -> Host | None:
    """Reuse the lowest-ID equivalent identity without rewriting or merging rows.

    Existing equivalent collisions remain separate user records. Discovery and
    manual creation consistently select their oldest identity; edit callers can
    exclude their own ID to guard against every equivalent conflicting identity.
    """
    canonical = normalize_ip(ip)
    return next(
        (
            host
            for host in session.exec(
                select(Host)
                .where(Host.engagement_id == engagement_id)
                .order_by(col(Host.id))
            ).all()
            if host.id != excluding and same_ip(host.ip, canonical)
        ),
        None,
    )


def normalize_hostname(raw: str) -> str:
    """Canonical hostname identity shared by manual entry and scan discovery."""
    name = raw.strip().rstrip(".").lower()
    if not name or any(character.isspace() for character in name):
        raise ValueError("hostname must not be empty or contain whitespace")
    return name


def normalize_protocol(raw: str) -> str:
    """Normalize a protocol identity without imposing a classification list."""
    protocol = raw.strip().lower()
    if not protocol or any(character.isspace() for character in protocol):
        raise ValueError("protocol must not be empty or contain whitespace")
    return protocol


@dataclass
class DiscoveryIndex:
    """Canonical lookups for one import command, never cached across sessions.

    Load each engagement identity/link table once, then update these maps as the
    command stages discoveries. Ordered loading preserves lowest-ID selection.
    """

    engagement_id: str
    hosts: dict[str, Host]
    hostnames: dict[str, list[Hostname]]
    links: dict[tuple[int, str], list[HostHostname]]
    services: set[tuple[int, int, str]]

    @classmethod
    def load(cls, session: Session, *, engagement_id: str) -> DiscoveryIndex:
        hosts: dict[str, Host] = {}
        for host in session.exec(
            select(Host)
            .where(Host.engagement_id == engagement_id)
            .order_by(col(Host.id))
        ).all():
            try:
                canonical = normalize_ip(host.ip)
            except ValueError:
                continue
            hosts.setdefault(canonical, host)
        names: dict[str, list[Hostname]] = {}
        names_by_id: dict[int, str] = {}
        for hostname in session.exec(
            select(Hostname)
            .where(Hostname.engagement_id == engagement_id)
            .order_by(col(Hostname.id))
        ).all():
            try:
                canonical = normalize_hostname(hostname.name)
            except ValueError:
                continue
            names.setdefault(canonical, []).append(hostname)
            assert hostname.id is not None
            names_by_id[hostname.id] = canonical
        links: dict[tuple[int, str], list[HostHostname]] = {}
        for link in session.exec(
            select(HostHostname).where(HostHostname.engagement_id == engagement_id)
        ).all():
            name = names_by_id.get(link.hostname_id)
            if name is not None:
                links.setdefault((link.host_id, name), []).append(link)
        services = {
            (host_id, port, proto)
            for host_id, port, proto in session.exec(
                select(Service.host_id, Service.port, Service.proto).where(
                    Service.engagement_id == engagement_id
                )
            ).all()
        }
        return cls(engagement_id, hosts, names, links, services)


def _equivalent_hostnames(
    session: Session, name: str, engagement_id: str
) -> list[Hostname]:
    canonical = normalize_hostname(name)
    matches: list[Hostname] = []
    for hostname in session.exec(
        select(Hostname)
        .where(Hostname.engagement_id == engagement_id)
        .order_by(col(Hostname.id))
    ).all():
        try:
            equivalent = normalize_hostname(hostname.name) == canonical
        except ValueError:
            continue
        if equivalent:
            matches.append(hostname)
    return matches


def _hostname_links(
    session: Session,
    host_id: int,
    names: list[Hostname],
    engagement_id: str,
) -> list[HostHostname]:
    identities = {name.id for name in names}
    return [
        link
        for link in session.exec(
            select(HostHostname).where(
                HostHostname.engagement_id == engagement_id,
                HostHostname.host_id == host_id,
            )
        ).all()
        if link.hostname_id in identities
    ]


def link_hostname(
    session: Session,
    host_id: int,
    name: str,
    now: datetime,
    *,
    engagement_id: str,
    discovery: DiscoveryIndex | None = None,
) -> None:
    """Refresh equivalent associations without rewriting legacy identities.

    Existing links win over unlinked equivalent hostname rows. Hidden intent
    wins equivalent-link collisions for this host only; no rows are merged or
    deleted. With no existing link, reuse the lowest-ID equivalent hostname.
    """
    name = normalize_hostname(name)
    if discovery is not None and discovery.engagement_id != engagement_id:
        raise ValueError("discovery index belongs to another engagement")
    names = (
        discovery.hostnames.get(name, [])
        if discovery is not None
        else _equivalent_hostnames(session, name, engagement_id)
    )
    links = (
        discovery.links.get((host_id, name), [])
        if discovery is not None
        else _hostname_links(session, host_id, names, engagement_id)
    )
    if links:
        hidden = any(link.hidden for link in links)
        for link in links:
            link.last_seen = now
            if hidden:
                link.hidden = True
        return
    hn = names[0] if names else Hostname(engagement_id=engagement_id, name=name)
    if not names:
        session.add(hn)
        session.flush()
        if discovery is not None:
            discovery.hostnames[name] = [hn]
    assert hn.id is not None
    link = HostHostname(
        engagement_id=engagement_id, host_id=host_id, hostname_id=hn.id, last_seen=now
    )
    session.add(link)
    if discovery is not None:
        discovery.links[(host_id, name)] = [link]


def hide_hostname(
    session: Session, host_id: int, hostname_id: int, *, engagement_id: str
) -> bool:
    """Hide all equivalent links for this host, retaining identities and history.

    Missing links are no-ops. Other hosts' visibility is never changed.
    """
    link = session.exec(
        select(HostHostname).where(
            HostHostname.engagement_id == engagement_id,
            HostHostname.host_id == host_id,
            HostHostname.hostname_id == hostname_id,
        )
    ).first()
    if link is None:
        return False
    hostname = session.get(Hostname, hostname_id)
    assert hostname is not None
    links = _hostname_links(
        session,
        host_id,
        _equivalent_hostnames(session, hostname.name, engagement_id),
        engagement_id,
    )
    changed = False
    for equivalent in links:
        if not equivalent.hidden:
            equivalent.hidden = True
            changed = True
    return changed
