# ADR 0006: Raw-first ingestion with best-effort normalization

Status: Accepted (2026-07-05)

## Context
ARGUS ingests events from many vendors (Wazuh, Cortex XDR, FortiSIEM,
Trellix, CrowdStrike, Chronicle, QRadar, CyberStellar, Sophos, Sentinel,
...). Vendor payloads are inconsistent and connectors will improve over
time. SIEM webhook senders retry on failure.

## Decision
1. Always persist the raw payload (raw_events) — forensic evidence and
   re-normalization input.
2. Normalize best-effort via an EventNormalizer protocol (domain) and a
   source->normalizer registry (connectors). Unknown source or malformed
   event: keep raw, skip normalized, never fail the batch.
3. tenant_id is taken from the JWT, never from the request body.
4. Batch endpoint (max 1000/request), returns 202 Accepted.

## Consequences
+ Adding a vendor = one normalizer class + one registry line.
+ No data loss while connector coverage grows.
- normalized_events lags raw_events until re-normalization tooling exists
  (future: backfill job re-runs normalizers over stored raw events).
