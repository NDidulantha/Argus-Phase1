# ADR 0013: Reasoning agent (local-first LLM over curated evidence)

Status: Accepted (2026-07-09)

## Context
Phase 3's final step: interpret evidence objects into analyst-ready,
explainable narratives. Per ADR 0010 the LLM reasons over CURATED
evidence only, and deterministic code owns data assembly.

## Decision
1. ReasoningProvider Protocol (domain/reasoning.py) + registry. Providers:
   - OllamaProvider (default): local, private, free. localhost:11434,
     model qwen2.5:7b. No client data leaves the host.
   - AnthropicProvider (optional drop-in): used only if an API key is set;
     absent key => unavailable, nothing breaks. No key required to operate.
2. services/investigation.py deterministically assembles context (summary,
   ATT&CK techniques w/ names+tactics, entities, score breakdown, and
   RAG-retrieved similar past evidence), builds a structured prompt
   demanding SUMMARY / ATT&CK ASSESSMENT / CONFIDENCE / ALTERNATIVE
   EXPLANATIONS / NEXT STEPS, then calls the provider.
3. POST /evidence/{id}/investigate (provider selectable per request);
   GET /evidence/reasoning/providers lists what's available.
4. temperature 0.2 for stable analysis; prompt forbids inventing facts and
   requires a false-positive scenario (explainability, ADR 0010 #5).

## Consequences
+ Fully local/private/free by default; cloud is opt-in, not required.
+ Deterministic assembly + LLM interpretation = reproducible, auditable.
+ Narrative is grounded only in curated evidence + org memory (RAG).
- Local 7B reasoning is good, not GPT-4-class; provider swap covers the
  gap when a key is available.
- Prompt-only structure today; JSON-schema-constrained output is a future
  hardening step.
