# syntax=docker/dockerfile:1

FROM docker.io/nixos/nix:2.35.0 AS builder
WORKDIR /build
COPY flake.nix flake.lock pyproject.toml uv.lock README.md ./
COPY frontend/ frontend/
COPY src/ src/

# Preserve store paths and symlinks: Nix binaries embed absolute runtime paths.
# Copy only the runtime closure, not the builder's Nix installation or database.
RUN nix --extra-experimental-features "nix-command flakes" \
      build path:.#default --option sandbox false --no-link --print-out-paths \
      > /tmp/app-path \
    && mkdir -p /runtime/nix/store /runtime/data \
    && nix-store --query --requisites "$(cat /tmp/app-path)" \
      | xargs cp -a --parents -t /runtime \
    && ln -s "$(cat /tmp/app-path)" /runtime/app

FROM gcr.io/distroless/base-debian13:nonroot
COPY --from=builder /runtime/nix/store/ /nix/store/
COPY --from=builder /runtime/app /app
COPY --from=builder --chown=65532:65532 /runtime/data/ /data/
ENV PATH="/app/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PENRECON_DATA=/data
WORKDIR /data
USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["/app/bin/python3.14"]
CMD ["-m", "uvicorn", "penrecon.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
