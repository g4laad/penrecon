"""Application composition: documented JSON API, HTML shell, and HTTP policy."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from penrecon.db import init_db
from penrecon.web import (
    credentials,
    engagements,
    evidence,
    inventory,
    operations,
    pages,
)
from penrecon.web.common import ERROR_RESPONSES
from penrecon.web.security import LocalSecurityMiddleware


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


class LocalAPI(FastAPI):
    def openapi(self) -> dict[str, Any]:
        """Describe the browser-safety header on mutations only."""
        if self.openapi_schema is None:
            schema = get_openapi(
                title=self.title,
                version=self.version,
                description=self.description,
                routes=self.routes,
            )
            schema.setdefault("components", {}).setdefault("securitySchemes", {})[
                "LocalRequest"
            ] = {
                "type": "apiKey",
                "in": "header",
                "name": "X-Penrecon-Request",
                "description": "Set to 1 for mutations. Cross-origin requests are rejected; this is not authentication.",
            }
            for path, item in schema["paths"].items():
                if path.startswith("/api/"):
                    for method, operation in item.items():
                        if method in ("post", "put", "patch", "delete"):
                            operation["security"] = [{"LocalRequest": []}]
            self.openapi_schema = schema
        return self.openapi_schema


app = LocalAPI(
    title="penrecon API",
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "Single-user local recon API. JSON responses are independent of Accept. "
        "Mutations use documented form bodies and require X-Penrecon-Request: 1. "
        "All scoped resources are isolated by engagement. Not an authenticated network service; bind to loopback only."
    ),
)
app.add_middleware(LocalSecurityMiddleware)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        {"detail": str(exc.detail)}, status_code=exc.status_code, headers=exc.headers
    )


@app.exception_handler(RequestValidationError)
async def validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # Pydantic's default error includes raw input (potentially passwords, notes,
    # or uploaded bytes). Only locations and safe validation messages leave here.
    fields: dict[str, str] = {}
    for error in exc.errors():
        location = error.get("loc", ())
        if location:
            field = next(
                (part for part in location[1:] if isinstance(part, str)), "request"
            )
            fields[field] = str(error["msg"])
    return JSONResponse(
        {"detail": "Invalid request fields.", "field_errors": fields}, status_code=422
    )


api = APIRouter(prefix="/api", responses=ERROR_RESPONSES)
for module in (engagements, inventory, credentials, evidence, operations):
    api.include_router(module.router)
app.include_router(api)
app.include_router(pages.router)
app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).parent / "static")),
    name="static",
)
