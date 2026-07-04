"""Health endpoints.

Liveness and readiness are deliberately separate (Kubernetes convention):
- /health/live  -> "the process is up"; never touches dependencies.
- /health/ready -> "the service can do useful work"; checks the database.
A load balancer stops routing traffic on readiness failure; an orchestrator
restarts the container on liveness failure. Conflating them causes restart
loops when only the database is down.
"""

from fastapi import APIRouter, Response, status

from argus.infrastructure.db.session import check_database

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def liveness() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/ready")
async def readiness(response: Response) -> dict[str, str]:
    if await check_database():
        return {"status": "ready"}
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "degraded", "reason": "database unreachable"}
