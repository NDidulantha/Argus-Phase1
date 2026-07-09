# ADR 0012: Embeddings + RAG over evidence objects

Status: Accepted (2026-07-06)

## Context
Platform learning (ADR 0010) requires retrieving similar past evidence to
ground new investigations — without retraining any model. We embed
evidence objects (never raw logs) and search by similarity.

## Decision
1. Embedder Protocol (domain/embedding.py) + registry; provider chosen by
   ARGUS_EMBEDDING_PROVIDER. Default HashingEmbedder: deterministic,
   offline, dependency-free, L2-normalized 384-dim vectors — enough to
   cluster/retrieve by technique/tactic/host vocabulary and to build+test
   the whole RAG + reasoning pipeline now.
2. Upgrade path (no caller changes): implement an Embedder wrapping
   sentence-transformers on the local GPU or an API, register it, set the
   env var, backfill embeddings (summary_text is retained).
3. evidence_objects gains summary_text + embedding vector(384) +
   embedding_provider; IVFFlat cosine index for similarity search.
4. Evidence is embedded automatically on /evidence/correlate;
   /evidence/{id}/similar retrieves the k nearest (tenant-scoped by RLS).
5. render_summary() produces the single curated-evidence text used for
   BOTH embedding and (next) the reasoning prompt — retrieval and
   reasoning stay consistent.

## Consequences
+ RAG memory works today, offline, reproducibly; semantic model is a
  drop-in upgrade.
+ Same evidence text feeds retrieval and reasoning.
- Hashing embeddings are lexical, not deeply semantic; upgrade before
  relying on nuanced similarity in production.
