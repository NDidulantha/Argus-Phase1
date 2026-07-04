from fastapi import APIRouter

from argus.api.v1.endpoints import auth, health, tenants

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
