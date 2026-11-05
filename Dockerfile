# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.11.26 AS uv
FROM python:3.14-slim-trixie AS backend
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src/ src/
COPY --from=frontend /build/src/penrecon/web/static/ui/ src/penrecon/web/static/ui/
RUN python -m pip uninstall --yes pip
RUN uv sync --locked --no-dev --no-editable

# Carry the matching Python interpreter and its native dependencies into
# distroless. Discover libraries rather than hard-coding architecture paths.
RUN python - <<'PY'
import pathlib
import re
import shutil
import subprocess

root = pathlib.Path('/runtime')
candidates = [pathlib.Path('/usr/local/bin/python3.14')]
for directory in ('/usr/local/lib', '/build/.venv'):
    candidates.extend(pathlib.Path(directory).rglob('*.so*'))
for candidate in candidates:
    if not candidate.is_file():
        continue
    result = subprocess.run(['ldd', str(candidate)], capture_output=True, text=True)
    for library in re.findall(r'(?:=>\s+)?(/\S+)', result.stdout):
        source = pathlib.Path(library)
        # Resolve directory aliases (/lib -> /usr/lib), but keep the SONAME.
        source = source.parent.resolve() / source.name
        target = root / source.relative_to('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copy2(source, target)
pathlib.Path('/data').mkdir()
PY

FROM gcr.io/distroless/base-debian13:nonroot
COPY --from=backend /runtime/ /
COPY --from=backend /usr/local/bin/python3.14 /usr/local/bin/python3.14
COPY --from=backend /usr/local/lib/ /usr/local/lib/
COPY --from=backend --chown=65532:65532 /data/ /data/
COPY --from=backend /build/.venv/lib/python3.14/site-packages/ /usr/local/lib/python3.14/site-packages/
ENV PATH="/usr/local/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PENRECON_DATA=/data
WORKDIR /data
USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/python3.14"]
CMD ["-m", "uvicorn", "penrecon.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
