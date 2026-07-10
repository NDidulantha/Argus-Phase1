# ADR 0014: CTI grounding layer (real-world intel with citations)

Status: Accepted (2026-07-09)

## Context
The reasoning agent must ground attribution (actors, malware, campaigns,
exploited CVEs) in real threat intel, not model guessing. Where no intel
exists, it must say so rather than fabricate. Sources vary hugely in
accessibility.

## Decision
1. CTIProvider protocol (domain/cti.py): returns cited CTIFinding
   (found, malware, actors, tags, first/last seen, reference_url, summary).
2. Free, real providers implemented now:
   - ThreatFox, MalwareBazaar, URLhaus (abuse.ch; one free Auth-Key)
   - CISA KEV (no key) for actively-exploited CVEs
   Each yields a reference_url for analyst verification.
3. cti_cache: GLOBAL table (no tenant_id/RLS) — intel is world knowledge;
   caching protects rate limits (ADR 0007 pattern).
4. CTI findings feed the reasoning agent's curated context. Prompt cites
   them; when none found, prompt explicitly forbids speculating about
   actors/campaigns.
5. Interface-only slots for later: MISP, OpenCTI (self-hosted), OTX, and
   commercial (Mandiant, CrowdStrike, Recorded Future, Microsoft TI) —
   each = one provider class + one registry line, no core change.

## Consequences
+ Attribution is cited and verifiable, or truthfully absent — no guessing.
+ Quota-safe, provider-agnostic, extensible to paid/self-hosted sources.
- abuse.ch now requires a free Auth-Key; without it those three providers
  are disabled (CISA KEV still works).
- Live-API validation is manual (done against real keys on the dev host).
