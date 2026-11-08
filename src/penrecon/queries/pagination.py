from __future__ import annotations

PER_PAGE_OPTIONS = (
    10,
    25,
    50,
)  # selectable page sizes; "all" (no limit) is the 4th choice
PER_PAGE_DEFAULT = 10


def resolve_per_page(raw: str) -> int | None:
    """Map a ``?per`` query value to a row limit. ``"all"`` -> ``None`` (no
    limit); an empty/unknown/non-whitelisted value falls back to the default."""
    if raw == "all":
        return None
    if len(raw) <= 10 and raw.isascii() and raw.isdecimal():
        value = int(raw)
        if value in PER_PAGE_OPTIONS:
            return value
    return PER_PAGE_DEFAULT


SORT_DEFAULT_DIR = {"change": "asc", "ports": "desc", "ip": "asc", "status": "asc"}


def _page_bounds(total: int, page: int, per_page: int | None) -> tuple[int, int]:
    if per_page is None:
        return 1, 1
    pages = max(1, (total + per_page - 1) // per_page)
    return max(1, min(page, pages)), pages


SERVICE_SORT_DEFAULT_DIR = {
    "port": "asc",
    "state": "asc",
    "service": "asc",
    "status": "asc",
}
