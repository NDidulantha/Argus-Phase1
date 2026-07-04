"""Application entry point (app factory pattern).

create_app() builds a fully configured FastAPI instance. A factory (instead
of a global app built at import time) lets tests construct isolated app
instances and lets configuration be resolved at startup rather than import.
"""

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request

from argus.api.v1.router import api_router
from argus.core.config import get_settings
from argus.core.logging import configure_logging
from argus.infrastructure.db.session import dispose_engine

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    log.info("startup", env=settings.env)
    yield
    await dispose_engine()
    log.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ARGUS — AI Threat Hunting Platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        """Attach a request_id to logging context and the response.

        Honors an inbound X-Request-ID (so traces can span services) or
        generates one. Later, tenant_id from the JWT is bound here too.
        """
        structlog.contextvars.clear_contextvars()
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        structlog.contextvars.bind_contextvars(request_id=request_id)

        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        response.headers["x-request-id"] = request_id
        log.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=elapsed_ms,
        )
        return response

    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
