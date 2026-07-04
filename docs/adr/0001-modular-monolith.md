# ADR 0001: Modular monolith for Phase 1

Status: Accepted (2026-07-04)

## Context
The platform will eventually have many capabilities (ingestion, correlation,
enrichment, reasoning, reporting). Microservices add network boundaries,
deployment complexity, and distributed debugging cost.

## Decision
Build a single deployable FastAPI service with strict internal module
boundaries (api / domain / infrastructure / connectors). Extract services
later only when a module has a proven independent scaling need.

## Consequences
+ One repo, one deploy, fast iteration for a solo developer.
+ Module boundaries make later extraction feasible.
- Requires discipline: layer rules are enforced by review, not the network.
