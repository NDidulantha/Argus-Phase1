# ADR 0002: PostgreSQL + pgvector as the single datastore

Status: Accepted (2026-07-04)

## Context
The platform needs relational data (tenants, events, investigations) and
vector similarity search (RAG over investigation history). A dedicated
vector DB (Qdrant, Weaviate, Pinecone) is another service to operate.

## Decision
Use PostgreSQL 16 with the pgvector extension for both relational and
vector workloads. Access via SQLAlchemy 2.0 async + asyncpg.

## Consequences
+ One database: one backup story, one auth story, transactional consistency
  between investigations and their embeddings.
+ Row-level tenant isolation applies to vectors too.
- At very large embedding volume, may revisit a dedicated vector store;
  the repository pattern keeps that swap contained.
