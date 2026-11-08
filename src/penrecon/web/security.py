"""Local-only HTTP protections, applied before parsing or domain handlers."""
from __future__ import annotations

from urllib.parse import urlsplit

from anyio import CancelScope, SpooledTemporaryFile
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from penrecon.web.common import MAX_UPLOAD_BYTES

MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 1024 * 1024


class LocalSecurityMiddleware:
    """Bound request bodies and prevent browser-driven cross-origin API access.

    This is not authentication. The server must remain on loopback; a reverse
    proxy needs its own authentication and must preserve the original Host.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin1").lower(): value.decode("latin1") for key, value in scope["headers"]}
        api = scope["path"] == "/api" or scope["path"].startswith("/api/")

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                values = list(message["headers"])
                values += [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY")]
                if api or not scope["path"].startswith("/static/"):
                    values = [(k, v) for k, v in values if k.lower() != b"cache-control"]
                    values.append((b"cache-control", b"no-store"))
                if scope["path"] not in ("/docs", "/redoc", "/docs/oauth2-redirect"):
                    values.append((b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"))
                message = {**message, "headers": values}
            await send(message)

        async def reject(status: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, status_code=status)(scope, receive, secure_send)
        try:
            authority = urlsplit("//" + headers.get("host", ""))
            trusted = (
                authority.hostname in {"localhost", "127.0.0.1", "::1", "testserver"}
                and authority.username is None and authority.password is None
                and not authority.path and not authority.query and not authority.fragment
            )
            authority.port  # reject malformed or out-of-range ports
        except ValueError:
            trusted = False
        if not trusted:
            await reject(400, "Invalid Host header.")
            return

        if api:
            origin = headers.get("origin")
            try:
                expected = urlsplit(f"{scope.get('scheme', 'http')}://{headers.get('host', '')}")
                supplied = urlsplit(origin) if origin else None
            except ValueError:
                await reject(403, "Invalid request origin.")
                return
            if headers.get("sec-fetch-site") == "cross-site" or (supplied is not None and (
                supplied.scheme != expected.scheme or supplied.netloc != expected.netloc or supplied.path or supplied.query or supplied.fragment
            )):
                await reject(403, "Cross-origin API requests are not allowed.")
                return
            if scope["method"] not in ("GET", "HEAD", "OPTIONS") and headers.get("x-penrecon-request") != "1":
                await reject(403, "Mutations require X-Penrecon-Request: 1.")
                return
            raw_length = headers.get("content-length")
            if raw_length is not None:
                try:
                    length = int(raw_length)
                except ValueError:
                    await reject(400, "Invalid Content-Length.")
                    return
                if length < 0:
                    await reject(400, "Invalid Content-Length.")
                    return
                if length > MAX_REQUEST_BYTES:
                    await reject(413, "Request body exceeds the 33 MiB limit.")
                    return
            # Spool before multipart parsing, bounding chunked requests as well as
            # Content-Length uploads without retaining the entire body in RAM.
            body = SpooledTemporaryFile[bytes](max_size=1024 * 1024)
            try:
                total = 0
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    total += len(chunk)
                    if total > MAX_REQUEST_BYTES:
                        await reject(413, "Request body exceeds the 33 MiB limit.")
                        return
                    await body.write(chunk)
                    if not message.get("more_body", False):
                        break
                await body.seek(0)
                remaining = total
                replay_complete = False

                async def replay() -> Message:
                    nonlocal remaining, replay_complete
                    if replay_complete:
                        return await receive()
                    if remaining == 0:
                        replay_complete = True
                        return {"type": "http.request", "body": b"", "more_body": False}
                    chunk = await body.read(min(65536, remaining))
                    remaining -= len(chunk)
                    replay_complete = remaining == 0
                    return {"type": "http.request", "body": chunk, "more_body": remaining > 0}

                await self.app(scope, replay, secure_send)
                return
            finally:
                with CancelScope(shield=True):
                    await body.aclose()
        await self.app(scope, receive, secure_send)
