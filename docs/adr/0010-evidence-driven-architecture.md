# ADR 0010: Evidence-driven architecture

Status: Accepted (2026-07-06)

## Context
ARGUS is an evidence-driven, multi-agent threat hunting platform, not an
AI chatbot. The LLM must never reason over raw telemetry; it reasons only
over curated, structured, scored evidence. This ADR fixes the spine that
all later phases (graph, correlation, scoring, RAG, agents) hang from.

## Decision

### 1. Deterministic-before-LLM contract
Raw telemetry passes through deterministic stages ONLY, in order:
  normalize -> entity extraction -> correlation -> enrichment ->
  ATT&CK mapping -> evidence scoring.
The output is Evidence Objects. The LLM consumes Evidence Objects, never
raw logs. This gives predictable behavior, low token cost, and
explainability. (Extends ADR 0006 raw-first ingestion.)

### 2. Evidence Graph as a core component (Postgres-native)
Model entities (user, host, process, file, ip, hash, ...) and typed
relationships (spawned, accessed, authenticated_from, connected_to, ...)
as first-class data. This enables attack-chain reconstruction, lateral
movement and privilege-escalation analysis across time and systems.

Rejected: a dedicated graph DB (Neo4j). It would violate ADR 0002 (single
datastore) and add major operational weight. Entities + edges are tables
in the existing Postgres; recursive CTEs traverse chains. The repository
pattern keeps a future graph-engine swap contained.

### 3. Hunting is a structured investigation, not a chat
hypothesis -> deterministic plan -> execute queries/enrichment via
dedicated services -> collect evidence -> LLM interprets. The LLM is a
PLANNER and REASONER; deterministic components own collection, querying,
enrichment, correlation. Ensures reproducibility and auditability.

### 4. Multi-agent = modules, not microservices
The nine responsibilities (Planner, Collector, Correlation, Threat
Intel, MITRE, Reasoning, Reporting, Memory, Case Management) are modules
with clean interfaces inside the modular monolith (ADR 0001), each
independently testable and later extractable. Premature microservices
would harm maintainability and cost. "Multi-agent" = separation of
responsibility, not of processes.

### 5. Explainability is mandatory
Every AI conclusion references supporting evidence, investigation steps,
tools/queries used, ATT&CK justification, a confidence assessment, and
plausible alternative / false-positive explanations. No opaque outputs.

### 6. Platform learning, never model retraining
Investigation history, analyst feedback, threat intel, prior findings,
confidence adjustments, MITRE knowledge and RAG are persistent
organizational knowledge that improves future investigations WITHOUT
modifying the LLM. Model capability and platform capability stay distinct.

## Consequences
+ The AI is constrained to trustworthy inputs by construction.
+ Graph enables analysis flat event tables cannot express.
+ One datastore, one operational story; solo-operable.
- More deterministic engineering up front before the AI adds value —
  intentional: the evidence must be trustworthy before reasoning over it.

## Re-sequenced Phase 3
1. Evidence Graph (entities + edges from existing events)  <- start here
2. Correlation into evidence objects
3. Evidence scoring
4. Embeddings + RAG over evidence objects
5. Reasoning agent (plans investigations, interprets curated evidence)
