# ADR 0007: Cache-first, on-demand enrichment with a global intel cache

Status: Accepted (2026-07-06)

## Context
Events reference indicators (IPs, hashes, domains) whose reputation lives
in external providers (VirusTotal, AbuseIPDB, OTX, ...). Free-tier quotas
are tiny; a prior lab integration burned the VT quota by enriching inline
per alert.

## Decision
1. Enricher protocol (domain) + settings-driven registry: a provider
   without an API key does not exist. Adding a provider = 1 class + 1 line.
2. enrichment_cache is GLOBAL (no tenant_id, no RLS): reputation is world
   knowledge, not tenant data; one lookup serves every tenant.
3. Cache-first with TTL (default 24h); provider errors degrade to
   "no result", never fail a lookup.
4. Enrichment is ON-DEMAND (analyst/agent-triggered), not inline in
   ingestion: quota and hot-path latency protection.

## Consequences
+ Quota-safe by construction; MSSP-wide cache amplifies value per call.
+ Verdict provenance (provider, fetched_at, cached) is auditable.
- Verdicts can be up to TTL stale; acceptable for hunting timescales.
- Future: bulk/background enrichment for aggregates, OTX provider.
