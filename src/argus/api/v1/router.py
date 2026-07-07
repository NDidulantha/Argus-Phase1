from fastapi import APIRouter

from argus.api.v1.endpoints import auth, enrichment, events, graph, health, mitre, tenants

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
api_router.include_router(events.router)
api_router.include_router(enrichment.router)
api_router.include_router(mitre.router)
api_router.include_router(graph.router)
api_router.include_router(mitre.router)
api_router.include_router(graph.router)
