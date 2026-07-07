# ADR 0011: Correlation into scored evidence objects

Status: Accepted (2026-07-06)

## Context
Events, techniques and graph entities are fragments; analysts (and the
future AI) need consolidated, prioritized units. Per ADR 0010 the AI
reasons over evidence objects, not raw logs.

## Decision
services/correlation.py deterministically groups a tenant's
technique-bearing events by host into time-bounded windows, gathers the
distinct techniques / tactics / entities, and computes an EXPLAINABLE
score (base from confidence + tactic breadth + technique count + critical
tactic bonus + volume), stored with a full score_breakdown.

Runs on demand (POST /evidence/correlate), idempotent (rerun replaces
open objects). No LLM involved — evidence objects are the trustworthy
input the reasoning agent will consume.

## Consequences
+ ~11k raw events -> a handful of prioritized, scored evidence objects.
+ Every score is auditable via score_breakdown.
+ Multi-tactic intrusion chains rise to the top; single-technique noise
  sinks. Verified on Mimikatz + PsExec + discovery datasets.
- Correlation is host+time based today; entity-graph-driven correlation
  (chains spanning hosts for lateral movement) is a future refinement.
