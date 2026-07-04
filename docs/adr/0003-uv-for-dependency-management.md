# ADR 0003: uv for dependency and environment management

Status: Accepted (2026-07-04)

## Context
Reproducible builds are a commercial requirement: CI, teammates, and the
Docker image must resolve identical dependency versions.

## Decision
Use uv (pyproject.toml + uv.lock). The Dockerfile installs with
`uv sync --frozen` so images are built strictly from the lockfile.

## Consequences
+ Deterministic installs everywhere; fast resolution.
- Team must run `uv sync` rather than ad-hoc `pip install`.
