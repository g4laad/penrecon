"""Rebuild effective inventory from persisted scan state and manual overrides."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import delete, insert
from sqlmodel import Session, col, select


def rebuild_inventory(session: Session, engagement_id: str) -> None:
    from penrecon.models import (
        Annotation, CurrentService, Host, Hostname, HostHostname, HostScanState,
        HostSummary, HostSummaryTag, Observation, Service, Status,
    )
    from penrecon.queries.inventory import service_state

    states = {
        row.host_id: row for row in session.execute(
            select(HostScanState).where(HostScanState.engagement_id == engagement_id)
        ).scalars()
    }
    annotations = {
        row.host_id: row for row in session.execute(
            select(Annotation).where(
                Annotation.engagement_id == engagement_id,
                col(Annotation.host_id).is_not(None),
            )
        ).scalars()
    }
    names: dict[int, list[str]] = defaultdict(list)
    for host_id, name in session.execute(
        select(HostHostname.host_id, Hostname.name).join(
            Hostname,
            (col(Hostname.id) == col(HostHostname.hostname_id))
            & (col(Hostname.engagement_id) == col(HostHostname.engagement_id)),
        ).where(
            HostHostname.engagement_id == engagement_id,
            HostHostname.hidden == False,  # noqa: E712
        ).order_by(Hostname.name)
    ):
        names[host_id].append(name)
    services: dict[int, list[Service]] = defaultdict(list)
    for service in session.execute(
        select(Service).where(Service.engagement_id == engagement_id)
        .order_by(col(Service.port), Service.proto, col(Service.id))
    ).scalars():
        services[service.host_id].append(service)

    current_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    tag_rows: list[dict[str, Any]] = []
    for host in session.execute(
        select(Host).where(Host.engagement_id == engagement_id)
    ).scalars():
        assert host.id is not None
        state = states.get(host.id)
        latest: dict[tuple[int, str], Observation] = {}
        for record in state.latest if state else []:
            scanned = Observation.model_validate(record)
            latest[(scanned.port, scanned.proto)] = scanned
        open_services: list[tuple[int, str | None]] = []
        for service in services.get(host.id, []):
            observation = latest.get((service.port, service.proto))
            effective = service_state(service, observation)
            current_rows.append({
                "engagement_id": engagement_id,
                "service_id": service.id,
                "host_id": host.id,
                "port": service.port,
                "proto": service.proto,
                "state": effective.state,
                "service_name": effective.service_name,
                "product": effective.product,
                "version": effective.version,
                "observation_id": observation.id if observation else None,
                "last_seen": observation.observed_at.strftime("%Y-%m-%d %H:%M") if observation else "",
                "manual": observation is None or any((
                    service.m_state, service.m_service_name, service.m_product, service.m_version,
                )),
                "service_name_lower": (effective.service_name or "").lower(),
                "search_text": " ".join(value for value in (
                    effective.service_name, effective.product, effective.version,
                ) if value).lower(),
            })
            if effective.state == "open":
                open_services.append((service.port, effective.service_name))
        # TCP and UDP may share a port, with only one having a name.
        open_services.sort(key=lambda value: (value[0], value[1] or ""))
        annotation = annotations.get(host.id)
        tags = annotation.tags if annotation else []
        hostnames = names.get(host.id, [])
        change = state.change if state else ""
        ip_sort = "4294967296"
        parts = host.ip.split(".")
        if len(parts) == 4 and all(part.isascii() and part.isdecimal() for part in parts):
            octets = [int(part) for part in parts]
            if all(value <= 255 for value in octets):
                # Legacy dotted addresses can retain leading zeroes.
                numeric_ip = sum(value << shift for value, shift in zip(octets, (24, 16, 8, 0), strict=True))
                ip_sort = f"{numeric_ip:010d}"
        summary_rows.append({
            "engagement_id": engagement_id,
            "host_id": host.id,
            "ip": host.ip,
            "ip_sort": ip_sort,
            "open_count": len(open_services),
            "status": str(annotation.status if annotation else Status.new),
            "triaged": annotation is not None,
            "change": change,
            "change_rank": {"new": 0, "changed": 1}.get(change, 2),
            "hostnames": hostnames,
            "tags": tags,
            "open_services": open_services,
            "search_values": [value.lower() for value in (
                host.ip, *hostnames, *(name for _port, name in open_services if name), *tags,
            )],
        })
        tag_rows.extend({
            "engagement_id": engagement_id, "host_id": host.id, "tag": tag,
        } for tag in sorted(set(tags)))

    for model, rows in (
        (CurrentService, current_rows), (HostSummary, summary_rows), (HostSummaryTag, tag_rows),
    ):
        session.execute(delete(model).where(col(model.engagement_id) == engagement_id))
        for start in range(0, len(rows), 500):
            session.execute(insert(model), rows[start:start + 500])
