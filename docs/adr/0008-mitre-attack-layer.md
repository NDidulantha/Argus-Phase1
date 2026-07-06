# ADR 0008: MITRE ATT&CK layer

Status: Accepted (2026-07-06)

## Context
Connectors emit technique IDs as bare strings in event attributes
(e.g. Wazuh mitre.id = ["T1110"]). To reason in ATT&CK terms and show
coverage, these must become first-class, joined to the real catalog.

## Decision
1. mitre_techniques: GLOBAL catalog table (no tenant_id/RLS), loaded from
   the official MITRE CTI bundle via scripts/load_mitre_attack.py
   (idempotent upsert; re-runnable on new ATT&CK releases). 697 active
   Enterprise techniques at load time.
2. event_techniques: tenant-owned link table (RLS), populated during
   ingestion by services/mitre.py — non-critical, savepoint-isolated like
   aggregation.
3. GET /mitre/coverage: per-tenant technique counts + first/last seen,
   decorated with global catalog names/tactics. The ATT&CK heatmap data.
4. GET /mitre/techniques/{id}: catalog lookup.

## Consequences
+ Coverage/gap analysis per tenant; heatmap-ready.
+ AI can reason over techniques/tactics, not raw log strings.
- Catalog must be periodically reloaded to track ATT&CK releases.
- Sub-technique roll-up to parents is a future refinement.
