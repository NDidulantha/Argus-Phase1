from fastapi import APIRouter

from argus.api.v1.endpoints import health

api_router = APIRouter()
api_router.include_router(health.router)
