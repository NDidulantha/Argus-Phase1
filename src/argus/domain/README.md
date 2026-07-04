# domain/

Pure business logic: entities, value objects, domain services.

Rules:
- No imports from `api/` or `infrastructure/`.
- No FastAPI, no SQLAlchemy, no HTTP concepts in here.

Dependency direction: api -> domain <- infrastructure.
