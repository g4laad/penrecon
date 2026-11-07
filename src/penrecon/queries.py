"""Read-side helpers: current-state merge, host listing/detail, scan diff,
and annotation access.

Scale note: current-state is computed in Python (latest-observation-wins).
# ponytail: naive per-host dedupe, fine for single-user local; push into SQL
# window functions if a project ever holds huge scan history.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TypeVar

from sqlalchemy import func, inspect, or_, select as sql_select
from sqlmodel import Session, col, select

from penrecon.history import HostTimeline, Overrides, State, host_history, timeline
from penrecon.models import (
    Annotation,
    Credential,
    CredentialHost,
    CredentialService,
    EngagementOwned,
    Host,
    Hostname,
    HostHostname,
    Note,
    Observation,
    OperationLog,
    Scan,
    Service,
    Status,
)


@dataclass
class ServiceView:
    service_id: int
    port: int
    proto: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    last_seen: str
    annotation: Annotation | None
    overrides: Overrides
    manual: bool = False


@dataclass
class HostRow:
    id: int
    ip: str
    hostnames: list[str]
    open_count: int
    status: str
    tags: list[str]
    open_ports: list[int]
    service_names: list[str]
    open_services: list[tuple[int, str | None]]  # (port, service_name), port-sorted
    change: str = ""  # "new" | "changed" | "" — scan-delta marker
    triaged: bool = False  # has an annotation; un-triaged hosts wear only the default status


@dataclass
class DiffEntry:
    ip: str
    port: int
    proto: str
    kind: str  # added | removed | changed
    before: str | None = None
    after: str | None = None


@dataclass
class DiffResult:
    scan_a: Scan
    scan_b: Scan
    entries: list[DiffEntry] = field(default_factory=list)


@dataclass
class NoteHit:
    """One note matched by an engagement-wide search, linked back to its target."""

    href: str
    where: str  # human label of the annotated entity (IP, IP·port/proto, hostname)
    kind: str  # "host" | "service" | "hostname"
    title: str
    preview: str


@dataclass
class SearchResults:
    q: str
    hosts: list[HostRow] = field(default_factory=list)
    notes: list[NoteHit] = field(default_factory=list)
    credentials: list[CredentialHit] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.hosts) + len(self.notes) + len(self.credentials)


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


# --- annotations ---------------------------------------------------------------

def get_annotation(
    session: Session, *, engagement_id: str,
    host_id: int | None = None, service_id: int | None = None
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
            Annotation.engagement_id == engagement_id, Annotation.service_id == service_id
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
        ann = Annotation(engagement_id=engagement_id, host_id=host_id, service_id=service_id)
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


# --- operation log ------------------------------------------------------------

@dataclass
class OperationSummary:
    id: int
    started_at: datetime | None
    destination: str
    tool: str
    command: str


def operation_logs(session: Session, q: str = "", *, engagement_id: str) -> list[OperationSummary]:
    """Timeline summaries; search full text in SQL without loading detail bodies."""
    statement = sql_select(
        col(OperationLog.id), col(OperationLog.started_at), col(OperationLog.destination),
        col(OperationLog.tool), col(OperationLog.command),
    ).where(col(OperationLog.engagement_id) == engagement_id)
    needle = q.strip().casefold()
    if needle:
        tags = func.json_each(OperationLog.tags).table_valued("value")
        tag_match = select(tags.c.value).where(
            func.instr(func.casefold(tags.c.value), needle) > 0,
        ).exists()
        statement = statement.where(or_(
            *(
                func.instr(func.casefold(value), needle) > 0
                for value in (
                    OperationLog.source, OperationLog.destination, OperationLog.tool,
                    OperationLog.user_context, OperationLog.command, OperationLog.output,
                    OperationLog.description, OperationLog.comments, OperationLog.attachment_name,
                )
            ),
            tag_match,
        ))
    statement = statement.order_by(
        col(OperationLog.started_at).is_(None),
        col(OperationLog.started_at).desc(),
        col(OperationLog.created_at).desc(),
    )
    return [
        OperationSummary(oid, started_at, destination, tool, command)
        for oid, started_at, destination, tool, command in session.connection().execute(statement)
        if oid is not None
    ]


# --- current-state merge -------------------------------------------------------

def latest_observations(
    session: Session, host_id: int, *, engagement_id: str
) -> dict[tuple[int, str], Observation]:
    """Latest trustworthy scan evidence per (port, proto), ordered by scan time.

    Aggregate closure/filtering only updates previously known ports; omitted
    ports retain their last known state. Manual events never enter this replay;
    current manual overrides are applied later.
    """
    _, latest = host_history(session, host_id, engagement_id=engagement_id)
    return latest


def _hostnames_for(session: Session, host_id: int, *, engagement_id: str) -> list[str]:
    return [
        name for _id, name in host_hostnames(session, host_id, engagement_id=engagement_id)
    ]


def host_hostnames(
    session: Session, host_id: int, *, engagement_id: str
) -> list[tuple[int, str]]:
    """(hostname_id, name) for a host, excluding manually-hidden links."""
    rows = session.exec(
        select(Hostname.id, Hostname.name)
        .join(HostHostname, HostHostname.hostname_id == Hostname.id)  # type: ignore[arg-type]
        .where(
            Hostname.engagement_id == engagement_id,
            HostHostname.engagement_id == engagement_id,
            HostHostname.host_id == host_id, HostHostname.hidden == False,  # noqa: E712
        )
        .order_by(Hostname.name)
    ).all()
    return [(hid, name) for hid, name in rows if hid is not None]


def _service_name(svc: Service, observation: Observation | None) -> str | None:
    """Manual names override the latest observation, including a missing name."""
    return svc.m_service_name or (observation.service_name if observation else None)


def service_state(svc: Service, observation: Observation | None) -> State:
    """Resolve the effective values shared by inventory and manual snapshots."""
    return State(
        state=str(svc.m_state or (observation.state if observation else None) or "unknown"),
        service_name=_service_name(svc, observation),
        product=svc.m_product or (observation.product if observation else None),
        version=svc.m_version or (observation.version if observation else None),
    )


def service_overrides(svc: Service) -> Overrides:
    """Raw override values, including nulls that inherit scan evidence."""
    return Overrides(
        state=str(svc.m_state) if svc.m_state is not None else None,
        service_name=svc.m_service_name, product=svc.m_product, version=svc.m_version,
    )


def resolved_services(
    session: Session, host_id: int, *, engagement_id: str
) -> list[ServiceView]:
    """Current services for display: manual overrides win over the latest
    observation; manual-only services are included."""
    latest = latest_observations(session, host_id, engagement_id=engagement_id)
    views: list[ServiceView] = []
    for svc in session.exec(
        select(Service)
        .where(Service.engagement_id == engagement_id, Service.host_id == host_id)
        .order_by(Service.port)  # type: ignore[arg-type]
    ).all():
        assert svc.id is not None
        o = latest.get((svc.port, svc.proto))
        effective = service_state(svc, o)
        views.append(
            ServiceView(
                service_id=svc.id,
                port=svc.port,
                proto=svc.proto,
                state=effective.state,
                service_name=effective.service_name,
                product=effective.product,
                version=effective.version,
                last_seen=(o.observed_at.strftime("%Y-%m-%d %H:%M") if o else ""),
                annotation=get_annotation(session, service_id=svc.id, engagement_id=engagement_id),
                overrides=service_overrides(svc),
                manual=o is None
                or any((svc.m_state, svc.m_service_name, svc.m_product, svc.m_version)),
            )
        )
    return views


def host_timeline(
    session: Session, host_id: int, *, engagement_id: str,
    page: int = 1, show_unchanged: bool = False,
) -> HostTimeline:
    """Newest-first scans and manual actions, merged before 20-entry pagination.

    Unchanged scans are opt-in; every recorded manual action remains visible.
    """
    return timeline(
        session, host_id, engagement_id=engagement_id,
        page=page, show_unchanged=show_unchanged,
    )


def host_change(
    session: Session, host_id: int, *, engagement_id: str,
    scan_count: int, latest_scan_id: int | None
) -> str:
    """Scan-only marker, unaffected by manual actions in the unified timeline.

    Preserve the first-sighting baseline rule: only a host introduced in the
    latest imported scan is new, and only when an earlier scan exists.
    Otherwise ``changed`` describes the last scan of this host, not freshness:
    unrelated later scans and manual actions do not clear it. Missing evidence
    never expires an open service.
    """
    entries, _ = host_history(session, host_id, engagement_id=engagement_id)
    if not entries:
        return ""
    if len(entries) == 1:
        return "new" if scan_count > 1 and entries[0].scan_id == latest_scan_id else ""
    return "changed" if entries[-1].changes else ""


def host_rows(session: Session, *, engagement_id: str) -> list[HostRow]:
    # scan baseline for the "new" marker: how many scans exist, and which is latest
    scan_ids = session.exec(
        select(Scan.id)
        .where(Scan.engagement_id == engagement_id)
        .order_by(Scan.imported_at.desc())  # type: ignore[attr-defined]
    ).all()
    scan_count = len(scan_ids)
    latest_scan_id = scan_ids[0] if scan_ids else None
    rows: list[HostRow] = []
    for host in session.exec(
        select(Host).where(Host.engagement_id == engagement_id).order_by(Host.ip)
    ).all():
        assert host.id is not None
        open_s = [
            s for s in resolved_services(session, host.id, engagement_id=engagement_id)
            if s.state == "open"
        ]
        ann = get_annotation(session, host_id=host.id, engagement_id=engagement_id)
        rows.append(
            HostRow(
                id=host.id,
                ip=host.ip,
                hostnames=_hostnames_for(session, host.id, engagement_id=engagement_id),
                open_count=len(open_s),
                status=(ann.status if ann else Status.new),
                tags=(ann.tags if ann else []),
                open_ports=sorted(s.port for s in open_s),
                service_names=sorted({s.service_name for s in open_s if s.service_name}),
                open_services=sorted((s.port, s.service_name) for s in open_s),
                change=host_change(
                    session, host.id, engagement_id=engagement_id,
                    scan_count=scan_count, latest_scan_id=latest_scan_id
                ),
                triaged=ann is not None,
            )
        )
    return rows


def filter_hosts(
    rows: list[HostRow],
    q: str = "",
    port: int | None = None,
    tag: str = "",
    status: str = "",
    change: str = "",
) -> list[HostRow]:
    out = rows
    if q:
        ql = q.lower()
        out = [
            r
            for r in out
            if ql in r.ip.lower()
            or any(ql in h.lower() for h in r.hostnames)
            or any(ql in s.lower() for s in r.service_names)
            or any(ql in t.lower() for t in r.tags)
        ]
    if port is not None:
        out = [r for r in out if port in r.open_ports]
    if tag:
        out = [r for r in out if tag in r.tags]
    if status:
        out = [r for r in out if r.status == status]
    if change:  # "new" | "changed" | "unchanged" — isolate by scan-delta state
        want = "" if change == "unchanged" else change  # "" is the internal no-change marker
        out = [r for r in out if r.change == want]
    return out


PER_PAGE_OPTIONS = (10, 25, 50)  # selectable page sizes; "all" (no limit) is the 4th choice
PER_PAGE_DEFAULT = 10

_Row = TypeVar("_Row")


def resolve_per_page(raw: str) -> int | None:
    """Map a ``?per`` query value to a row limit. ``"all"`` -> ``None`` (no
    limit); an empty/unknown/non-whitelisted value falls back to the default."""
    if raw == "all":
        return None
    return int(raw) if raw.isdigit() and int(raw) in PER_PAGE_OPTIONS else PER_PAGE_DEFAULT


def paginate(
    rows: list[_Row], page: int, per_page: int | None = PER_PAGE_DEFAULT
) -> tuple[list[_Row], int, int]:
    """Slice ``rows`` to one page. Returns ``(page_rows, page, pages)`` with
    ``page`` clamped into ``[1, pages]`` so an out-of-range or filtered-away
    page lands on the last real page rather than an empty table. ``per_page``
    of ``None`` means "all": one page holds every row."""
    if per_page is None:
        return list(rows), 1, 1
    pages = max(1, -(-len(rows) // per_page))  # ceil division
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    return rows[start : start + per_page], page, pages


SORT_DEFAULT_DIR = {"change": "asc", "ports": "desc", "ip": "asc", "status": "asc"}

# change is the story: new first, then changed, then unchanged
_CHANGE_RANK = {"new": 0, "changed": 1}


def sort_hosts(rows: list[HostRow], sort: str, direction: str = "") -> list[HostRow]:
    reverse = direction == "desc"
    if sort == "change":
        # two stable passes: most-open-ports first within each change group
        by_ports = sorted(rows, key=lambda r: r.open_count, reverse=True)
        return sorted(by_ports, key=lambda r: _CHANGE_RANK.get(r.change, 2), reverse=reverse)
    if sort == "ports":
        return sorted(rows, key=lambda r: r.open_count, reverse=reverse)
    if sort == "status":
        return sorted(rows, key=lambda r: r.status, reverse=reverse)

    def ip_key(r: HostRow) -> tuple[int, ...]:
        parts = r.ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return tuple(int(p) for p in parts)
        return (999, 999, 999, 999)  # non-IPv4 sorts last

    return sorted(rows, key=ip_key, reverse=reverse)


def filter_services(
    services: list[ServiceView], port: str = "", state: str = "",
    service: str = "", status: str = "",
) -> list[ServiceView]:
    """Per-column filter: port/service match as substrings, state/status exact."""
    port = port.strip()
    service = service.strip().lower()

    def keep(s: ServiceView) -> bool:
        if port and port not in str(s.port):
            return False
        if state and s.state != state:
            return False
        if status and (s.annotation.status if s.annotation else "") != status:
            return False
        if service:
            hay = " ".join(x for x in (s.service_name, s.product, s.version) if x).lower()
            if service not in hay:
                return False
        return True

    return [s for s in services if keep(s)]


SERVICE_SORT_DEFAULT_DIR = {"port": "asc", "state": "asc", "service": "asc", "status": "asc"}


def sort_services(
    services: list[ServiceView], sort: str, direction: str = ""
) -> list[ServiceView]:
    """Sort a host's services by one column; ties fall back to port order."""
    reverse = direction == "desc"
    if sort == "state":
        return sorted(services, key=lambda s: (s.state, s.port), reverse=reverse)
    if sort == "service":
        return sorted(services, key=lambda s: ((s.service_name or "").lower(), s.port), reverse=reverse)
    if sort == "status":
        return sorted(services, key=lambda s: (s.annotation.status if s.annotation else "", s.port), reverse=reverse)
    return sorted(services, key=lambda s: s.port, reverse=reverse)


# --- credentials ---------------------------------------------------------------

@dataclass
class LinkedHost:
    host_id: int
    ip: str


@dataclass
class CredentialHit:
    """Search identity and navigation only; never includes credential secrets."""

    id: int
    kind: str
    username: str
    hosts: list[LinkedHost]


@dataclass
class LinkedService:
    service_id: int
    host_id: int
    ip: str
    port: int
    proto: str
    name: str | None  # current display name (manual override or latest observation)


@dataclass
class CredentialView:
    id: int
    kind: str
    username: str
    secret: str
    notes: str
    created_at: str
    hosts: list[LinkedHost]
    services: list[LinkedService]
    pickable_services: list[LinkedService]  # services of linked hosts, not yet linked


@dataclass
class CredentialSummary:
    id: int
    kind: str
    username: str
    notes_preview: str
    host_count: int
    service_count: int


def credential_summaries(
    session: Session, q: str = "", kind: str = "", scope: str = "", *, engagement_id: str,
) -> tuple[list[CredentialSummary], int]:
    """List identities without secrets or picker pools; search full notes and links."""
    total = session.exec(select(func.count()).select_from(Credential).where(
        Credential.engagement_id == engagement_id,
    )).one()
    if scope not in ("", "linked", "unlinked"):
        return [], total
    host_count = select(func.count()).select_from(CredentialHost).where(
        CredentialHost.engagement_id == engagement_id,
        CredentialHost.credential_id == Credential.id,
    ).scalar_subquery()
    service_count = select(func.count()).select_from(CredentialService).where(
        CredentialService.engagement_id == engagement_id,
        CredentialService.credential_id == Credential.id,
    ).scalar_subquery()
    statement = sql_select(
        col(Credential.id), col(Credential.kind), col(Credential.username),
        col(Credential.notes) if q else func.substr(col(Credential.notes), 1, 160),
        host_count, service_count,
    ).where(col(Credential.engagement_id) == engagement_id)
    if kind:
        statement = statement.where(col(Credential.kind) == kind)
    if scope == "linked":
        statement = statement.where(host_count + service_count > 0)
    elif scope == "unlinked":
        statement = statement.where(host_count + service_count == 0)
    rows = session.connection().execute(statement.order_by(col(Credential.created_at).desc())).all()
    hosts: dict[int, list[LinkedHost]] = {}
    services: dict[int, list[LinkedService]] = {}
    if q and rows:
        hosts, services, _ = _credential_links(
            session, {row[0] for row in rows}, engagement_id=engagement_id, pickers=False,
        )
    needle = q.lower()
    summaries = []
    for cid, credential_kind, username, notes, host_total, service_total in rows:
        if needle:
            text = " ".join((
                username, credential_kind, notes,
                *(host.ip for host in hosts.get(cid, [])),
                *(
                    f"{service.ip}:{service.port}/{service.proto} {service.name or ''}"
                    for service in services.get(cid, [])
                ),
            ))
            if needle not in text.lower():
                continue
        summaries.append(CredentialSummary(
            cid, credential_kind, username, notes[:160], host_total, service_total,
        ))
    return summaries, total


def _credential_links(
    session: Session, credential_ids: set[int], *, engagement_id: str, pickers: bool,
) -> tuple[
    dict[int, list[LinkedHost]], dict[int, list[LinkedService]], dict[int, list[LinkedService]],
]:
    """Resolve only requested credentials' links, optionally including picker pools."""

    hosts_by_cred: dict[int, list[LinkedHost]] = defaultdict(list)
    for cid, hid, ip in session.exec(
        select(CredentialHost.credential_id, Host.id, Host.ip)
        .join(Host, Host.id == CredentialHost.host_id)  # type: ignore[arg-type]
        .where(
            CredentialHost.engagement_id == engagement_id, Host.engagement_id == engagement_id,
            col(CredentialHost.credential_id).in_(credential_ids),
        )
        .order_by(Host.ip)
    ).all():
        if hid is not None:
            hosts_by_cred[cid].append(LinkedHost(hid, ip))

    latest_by_host: dict[int, dict[tuple[int, str], Observation]] = {}

    def linked_service(svc: Service, ip: str) -> LinkedService:
        assert svc.id is not None
        observation = None
        if not svc.m_service_name:
            if svc.host_id not in latest_by_host:
                latest_by_host[svc.host_id] = latest_observations(
                    session, svc.host_id, engagement_id=engagement_id
                )
            observation = latest_by_host[svc.host_id].get((svc.port, svc.proto))
        return LinkedService(
            svc.id, svc.host_id, ip, svc.port, svc.proto,
            _service_name(svc, observation),
        )

    services_by_cred: dict[int, list[LinkedService]] = defaultdict(list)
    for cid, svc, ip in session.exec(
        select(CredentialService.credential_id, Service, Host.ip)
        .join(Service, Service.id == CredentialService.service_id)  # type: ignore[arg-type]
        .join(Host, Host.id == Service.host_id)  # type: ignore[arg-type]
        .where(
            CredentialService.engagement_id == engagement_id,
            col(CredentialService.credential_id).in_(credential_ids),
            Service.engagement_id == engagement_id, Host.engagement_id == engagement_id,
        )
        .order_by(Host.ip, Service.port)  # type: ignore[arg-type]
    ).all():
        if svc.id is not None:
            services_by_cred[cid].append(linked_service(svc, ip))

    # Services grouped by host, but only for hosts that some credential links —
    # this is the pool the per-credential picker draws from (services of linked
    # hosts), so we never ship the whole service table to the page.
    linked_host_ids = {h.host_id for hs in hosts_by_cred.values() for h in hs}
    services_by_host: dict[int, list[LinkedService]] = defaultdict(list)
    if pickers and linked_host_ids:
        for svc, ip in session.exec(
            select(Service, Host.ip)
            .join(Host, Host.id == Service.host_id)  # type: ignore[arg-type]
            .where(
                Service.engagement_id == engagement_id, Host.engagement_id == engagement_id,
                Service.host_id.in_(linked_host_ids),  # type: ignore[attr-defined]
            )
            .order_by(Host.ip, Service.port)  # type: ignore[arg-type]
        ).all():
            if svc.id is not None:
                services_by_host[svc.host_id].append(linked_service(svc, ip))

    return hosts_by_cred, services_by_cred, services_by_host


def _credential_views(
    session: Session, creds: list[Credential], *, engagement_id: str,
) -> list[CredentialView]:
    if not creds:
        return []
    hosts_by_cred, services_by_cred, services_by_host = _credential_links(
        session, {c.id for c in creds if c.id is not None},
        engagement_id=engagement_id, pickers=True,
    )

    def _pickable(cid: int) -> list[LinkedService]:
        linked = {s.service_id for s in services_by_cred.get(cid, [])}
        return [
            s for h in hosts_by_cred.get(cid, [])
            for s in services_by_host.get(h.host_id, [])
            if s.service_id not in linked
        ]

    return [
        CredentialView(
            id=c.id,
            kind=c.kind,
            username=c.username,
            secret=c.secret,
            notes=c.notes,
            created_at=c.created_at.strftime("%Y-%m-%d %H:%M"),
            hosts=hosts_by_cred.get(c.id, []),
            services=services_by_cred.get(c.id, []),
            pickable_services=_pickable(c.id),
        )
        for c in creds
        if c.id is not None
    ]


def credential_view(
    session: Session, credential_id: int, *, engagement_id: str,
) -> CredentialView | None:
    """Full editable projection of one owned credential and its associations."""
    credential = get_owned(session, Credential, credential_id, engagement_id=engagement_id)
    if credential is None:
        return None
    return _credential_views(session, [credential], engagement_id=engagement_id)[0]


def credentials_for_host(
    session: Session, host_id: int, *, engagement_id: str
) -> list[CredentialView]:
    """Credentials tied to this host directly *or* via one of its services."""
    host_links = select(CredentialHost.credential_id).where(
        CredentialHost.engagement_id == engagement_id, CredentialHost.host_id == host_id,
    )
    service_links = (
        select(CredentialService.credential_id)
        .join(Service, Service.id == CredentialService.service_id)  # type: ignore[arg-type]
        .where(
            CredentialService.engagement_id == engagement_id,
            Service.engagement_id == engagement_id, Service.host_id == host_id,
        )
    )
    credentials = list(session.exec(
        select(Credential).where(
            Credential.engagement_id == engagement_id,
            or_(col(Credential.id).in_(host_links), col(Credential.id).in_(service_links)),
        ).order_by(col(Credential.created_at).desc())
    ).all())
    return _credential_views(session, credentials, engagement_id=engagement_id)


# --- diff ----------------------------------------------------------------------

def _obs_by_key(
    session: Session, scan_id: int, *, engagement_id: str
) -> dict[tuple[str, int, str], Observation]:
    stmt = (
        select(Observation, Host.ip)
        .join(Host, Host.id == Observation.host_id)  # type: ignore[arg-type]
        .where(
            Observation.engagement_id == engagement_id, Host.engagement_id == engagement_id,
            Observation.scan_id == scan_id,
        )
    )
    out: dict[tuple[str, int, str], Observation] = {}
    for obs, ip in session.exec(stmt).all():
        out[(ip, obs.port, obs.proto)] = obs
    return out


def _summary(o: Observation) -> str:
    parts: list[str] = [o.state]
    if o.service_name:
        parts.append(o.service_name)
    if o.product or o.version:
        parts.append(" ".join(p for p in (o.product, o.version) if p))
    return " ".join(parts)


def diff_scans(
    session: Session, scan_a_id: int, scan_b_id: int, *, engagement_id: str
) -> DiffResult:
    a = get_owned(session, Scan, scan_a_id, engagement_id=engagement_id)
    b = get_owned(session, Scan, scan_b_id, engagement_id=engagement_id)
    if a is None or b is None:
        raise ValueError("scan not found")
    result = DiffResult(scan_a=a, scan_b=b)
    obs_a = _obs_by_key(session, scan_a_id, engagement_id=engagement_id)
    obs_b = _obs_by_key(session, scan_b_id, engagement_id=engagement_id)

    for key in sorted(obs_b.keys() - obs_a.keys()):
        ip, port, proto = key
        result.entries.append(
            DiffEntry(ip, port, proto, "added", after=_summary(obs_b[key]))
        )
    for key in sorted(obs_a.keys() - obs_b.keys()):
        ip, port, proto = key
        result.entries.append(
            DiffEntry(ip, port, proto, "removed", before=_summary(obs_a[key]))
        )
    for key in sorted(obs_a.keys() & obs_b.keys()):
        sa, sb = _summary(obs_a[key]), _summary(obs_b[key])
        if sa != sb:
            ip, port, proto = key
            result.entries.append(DiffEntry(ip, port, proto, "changed", before=sa, after=sb))
    return result


# --- global search -------------------------------------------------------------
# ponytail: in-Python substring match over already-loaded rows, same as
# filter_hosts. Single-user local scale; swap to SQLite FTS5 only if a project
# ever holds enough notes that a full-table scan is felt.

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
    return ("…" if start else "") + body[start:end].strip() + ("…" if end < len(body) else "")


def search_notes(session: Session, ql: str, *, engagement_id: str) -> list[NoteHit]:
    """Notes whose title or body contains ``ql`` (already lowercased). Notes live
    only on hosts, and the FK cascade drops them with the host, so the host
    always exists (the None guard is just for the type checker)."""
    hits: list[NoteHit] = []
    for note in session.exec(select(Note).where(Note.engagement_id == engagement_id)).all():
        if ql not in note.title.lower() and ql not in note.body_md.lower():
            continue
        host = get_owned(session, Host, note.host_id, engagement_id=engagement_id)
        if host is None:  # ponytail: unreachable under FK, keeps mypy happy
            continue
        hits.append(
            NoteHit(
                href=f"/e/{engagement_id}/hosts/{host.id}", where=host.ip, kind="host",
                title=note.title, preview=_note_preview(note.body_md, ql),
            )
        )
    return hits


# --- export --------------------------------------------------------------------

EXPORT_COLUMNS = [
    "ip", "hostnames", "port", "proto", "state",
    "service", "product", "version", "status", "tags",
]

# characters that make a spreadsheet treat a cell as a formula (CSV injection)
_CSV_RISKY_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection. Scan-derived fields (service
    banners, hostnames) are attacker-controlled; a leading =/+/-/@ makes Excel
    or Calc execute the cell as a formula. Prefix such values with a quote so
    they open as literal text. CSV export only — never for HTML display."""
    return "'" + value if value.startswith(_CSV_RISKY_PREFIXES) else value


def export_rows(session: Session, *, engagement_id: str) -> list[dict[str, str]]:
    """One flat row per service across all hosts, for CSV export. A host with no
    services still yields one row (empty service columns) so nothing is dropped.
    Reflects current merged state — manual overrides win over observations,
    exactly like the host detail view."""
    rows: list[dict[str, str]] = []
    for host in session.exec(
        select(Host).where(Host.engagement_id == engagement_id).order_by(Host.ip)
    ).all():
        assert host.id is not None
        ann = get_annotation(session, host_id=host.id, engagement_id=engagement_id)
        base = {
            "ip": _csv_safe(host.ip),
            "hostnames": _csv_safe(
                " ".join(_hostnames_for(session, host.id, engagement_id=engagement_id))
            ),
            "status": ann.status.value if ann else Status.new.value,
            "tags": _csv_safe(" ".join(ann.tags) if ann else ""),
        }
        services = resolved_services(session, host.id, engagement_id=engagement_id)
        if not services:
            rows.append({**base, "port": "", "proto": "", "state": "",
                         "service": "", "product": "", "version": ""})
            continue
        for s in services:
            rows.append({
                **base, "port": str(s.port), "proto": _csv_safe(s.proto),
                "state": _csv_safe(s.state),
                "service": _csv_safe(s.service_name or ""),
                "product": _csv_safe(s.product or ""),
                "version": _csv_safe(s.version or ""),
            })
    return rows


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
        hosts=filter_hosts(host_rows(session, engagement_id=engagement_id), q=ql),
        notes=search_notes(session, ql, engagement_id=engagement_id),
        credentials=creds,
    )
