# ADR 0009: Layered ATT&CK mapping (vendor -> rules -> ai)

Status: Accepted (2026-07-06)

## Context
Relying only on vendor-supplied ATT&CK IDs inherits the upstream tool's
blind spots. Windows/Sysmon/Mordor data carries no technique IDs, so
coverage was empty for replayed datasets despite obvious attacks
(Mimikatz LSASS access, encoded PowerShell).

## Decision
Map events to techniques in precedence order, recording provenance:
1. vendor (confidence 100) - trust connector-supplied IDs.
2. rules  - deterministic classifier (services/technique_rules.py) over
   normalized fields; each match carries its own confidence. High
   precision, explainable, zero cost.
3. ai (Phase 3) - augments the ambiguous long tail via the same table
   and mapping_source='ai'.
event_techniques gains mapping_source + confidence (migration 0005);
/mitre/coverage reports by_source and per-technique source breakdown.

The Mordor normalizer now preserves TargetImage and a Message excerpt so
rules can read evidence Sysmon buries in the message body.

## Consequences
+ Coverage no longer depends on upstream ATT&CK tagging.
+ Every mapping is auditable (source + confidence).
+ Rules remain the high-precision floor and a validation oracle for the
  Phase 3 AI classifier.
- Rule maintenance is ongoing; rules are intentionally conservative.
