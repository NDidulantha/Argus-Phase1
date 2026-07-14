# ARGUS — UI/UX Design System

> Enterprise AI Threat Hunting Platform for MSSP SOCs.
> This document is the single source of truth for ARGUS's visual language and screen design.
> It is written to be handed to Claude Code as the spec for building the frontend.

---

## 1. Brand foundation

ARGUS is named for **Argus Panoptes**, the hundred-eyed guardian of Greek myth — the all-seeing watcher who never fully sleeps. Everything in the interface should reinforce one feeling: *an analyst is not alone at the console; an intelligent guardian is watching alongside them.*

The design must read as **calm, intelligent, trustworthy, and precise** — a flagship security product, not a SIEM dashboard and not a "hacker" aesthetic.

**Hard bans** (these make the product look amateur): neon green, Matrix rain, binary streams, hooded figures, skulls, glitch effects, terminal-green-on-black gaming looks.

**Quality bar:** CrowdStrike Falcon and Microsoft Defender XDR for density and trust; Linear and Vercel for restraint and polish.

The logo is **finalized and frozen**. Every screen extends it — same palette, same geometry (the circular scanning ring, the eye, the soft rounded forms). We never redesign it.

---

## 2. Design tokens

### 2.1 Color

The palette is derived directly from the logo: deep purple field, silver ring, emerald eye.

| Token | Hex | Role |
|---|---|---|
| `--bg-base` | `#0F0A1E` | App background (deepest purple-black) |
| `--bg-surface` | `#160E28` | Primary panels, sidebar |
| `--bg-elevated` | `#1E1436` | Cards, table rows, raised surfaces |
| `--bg-hover` | `#281A45` | Hover / active row state |
| `--border-subtle` | `#2E1D4A` | Hairline dividers, card borders |
| `--border-strong` | `#3D2A5E` | Emphasis borders, focus outlines |
| `--accent` | `#2FE6A0` | Emerald — AI, healthy, active, success |
| `--accent-dim` | `#1D9E75` | Accent hover / pressed |
| `--accent-bg` | `#123528` | Accent tint fill (badges, highlights) |
| `--text-primary` | `#EDEBF5` | Primary text (near-white, warm) |
| `--text-secondary` | `#A79FC4` | Muted lavender-gray — labels, metadata |
| `--text-tertiary` | `#6E6690` | Hints, disabled, timestamps |
| `--silver` | `#B8B5C9` | Icon strokes, logo-ring echoes |

**Severity scale** — the only place non-brand color is allowed, because severity must never be ambiguous:

| Token | Hex | Meaning |
|---|---|---|
| `--sev-critical` | `#F26D6D` | Critical |
| `--sev-high` | `#F2A25A` | High |
| `--sev-medium` | `#EBCB5E` | Medium |
| `--sev-low` | `#5EEAB4` | Low (uses the emerald family — low severity reads as "calm") |
| `--sev-info` | `#7F9CF2` | Informational |

**Semantic rule that prevents the classic mistake:** emerald green means *AI / healthy / success*, never *severity*. Because critical/high alerts are red/orange, nothing dangerous is ever green. A green screen is always a safe screen.

**Color discipline:** purple and emerald dominate. Severity colors appear only on badges, status dots, and graph nodes — never as large fills. No gradients on structural surfaces (they flash and cheapen); a single soft radial glow behind the logo on login is the one exception.

### 2.2 Typography

- **Display / UI:** `Inter` — analyst-grade readability at small sizes, neutral and trustworthy.
- **Data / mono:** `Geist Mono` (or `IBM Plex Mono`) — IPs, hashes, MITRE IDs, log fields, timestamps. Monospace on technical values is a core part of feeling like a real security tool.

Scale (sentence case everywhere, never Title Case or ALL CAPS except the ARGUS wordmark):

| Role | Size / weight |
|---|---|
| Page title | 22px / 500 |
| Section heading | 18px / 500 |
| Card title | 15px / 500 |
| Body | 14px / 400, line-height 1.6 |
| Label / metadata | 12.5px / 400, `--text-secondary` |
| Data (mono) | 12.5px / 400 |

Two weights only: 400 and 500. Heavier weights look aggressive on dark surfaces.

### 2.3 Geometry & motion

Shapes echo the logo:

- **The scanning ring** — a thin dashed/segmented circular arc — is the signature motif. Reuse it for: loading spinners, the AI-thinking indicator, progress rings around confidence scores, and a faint watermark on empty states.
- **The eye** — focus/selection indicators use a soft elliptical highlight rather than a hard box.
- Corners: 8px on controls, 12px on cards, full-round on status dots and avatars.
- Dividers: 0.5px hairlines in `--border-subtle`.

Motion is subtle and purposeful:

- Hover: 120ms ease, background lift only (no scale bounce).
- Page transitions: 180ms cross-fade, no slide.
- **AI thinking state:** the scanning ring rotates slowly (2s/rev) with a soft emerald pulse — the guardian "watching." This is the one animation with personality.
- Investigation progress: the confidence ring fills clockwise as evidence accumulates.
- Reduced-motion: all of the above collapse to instant state changes.

---

## 3. Information architecture

Left sidebar, collapsible, grouped by analyst workflow rather than by feature:

```
[ARGUS logo]  ← eye mark + wordmark; collapses to eye-only

MONITOR
  Dashboard
  Alerts
INVESTIGATE
  AI workspace        ← the signature screen
  Cases
  Evidence graph
  Timeline
INTELLIGENCE
  MITRE ATT&CK
  Entity explorer
  Threat intel
MANAGE
  Reports
  Integrations
  Tenants             ← MSSP multi-tenant switch
  Settings
```

Global top bar (persistent): tenant switcher (left), global search (center), collector-health indicator + notifications + profile (right). The tenant switcher is prominent because MSSP analysts context-switch between client environments constantly.

---

## 4. Screens

Screens are ordered by priority. The **AI workspace gets the most detail — it is the product's signature.**

### 4.1 AI workspace — the signature screen

The thesis of ARGUS: analysts investigate *with* an AI guardian, not by chatting with a generic bot. The layout makes the AI's reasoning **visible and auditable**, never a black box.

**Three-column layout:**

```
┌─────────────┬───────────────────────────┬─────────────────┐
│ INVESTIGATION│      AI REASONING          │   EVIDENCE      │
│  PROGRESS    │        STREAM              │   & CONTEXT     │
│              │                            │                 │
│ ◔ Confidence │ Planner ▸ collecting…     │ Related entities│
│   72%        │ "Checking LSASS access    │  • host-4417    │
│              │  against baseline for      │  • svc_acct_09  │
│ Steps:       │  this tenant"              │                 │
│ ✓ Scope      │                            │ Attack chain    │
│ ✓ Collect    │ [evidence card:           │  T1003 → T1078  │
│ ◐ Correlate  │   231 events, 3 hosts]    │                 │
│ ○ Conclude   │                            │ Timeline (mini) │
│              │ MITRE ▸ mapped to          │  ▁▂▅▇▃▁         │
│ Hypotheses:  │  T1003.001                 │                 │
│  Cred dump   │                            │ Recommendations │
│  85% ▓▓▓▓░   │ [Reasoning ▸ "confidence   │  ▸ Isolate host │
│              │  raised: LSASS + outbound   │  ▸ Reset creds  │
│              │  to known-bad IP"]         │  ▸ Open case    │
│              │                            │                 │
│              │ ┌────────────────────────┐│                 │
│              │ │ Ask ARGUS…          ▸ ││                 │
│              │ └────────────────────────┘│                 │
└─────────────┴───────────────────────────┴─────────────────┘
```

**Left — investigation progress:**
- A **confidence ring** (logo-derived) at the top, filling clockwise, showing the AI's current confidence in its leading hypothesis.
- The nine-agent pipeline shown as an ordered checklist (Scope → Collect → Correlate → Conclude), with the active step marked by the rotating scan ring.
- Ranked **hypotheses** with confidence bars. Analysts can up/down-weight them — this is the feedback signal that later feeds the learning loop.

**Center — AI reasoning stream:**
- Not a chat bubble log. A **structured, timestamped reasoning trace**: each agent (Planner, Collector, Correlation, Threat Intel, MITRE, Reasoning) posts labeled entries with a colored agent tag.
- Evidence appears inline as **cards** (event clusters, IOC hits, host summaries) that expand in place.
- Every confidence change shows its *why* ("confidence raised: LSASS access + outbound to known-bad IP"). This explainability is the trust anchor — the whole reason the reasoning is a first-class column.
- A composer at the bottom lets the analyst steer ("focus on lateral movement", "rule out false positive") — natural language, but framed as *directing an investigator*, not chatting.

**Right — evidence & context:**
- **Related entities** (hosts, users, IPs, processes) as clickable chips that pivot to Entity explorer.
- **Attack chain** as a compact horizontal MITRE technique flow.
- **Mini timeline** sparkline; clicking opens full Timeline analysis.
- **Recommended next actions** as buttons: Isolate host, Reset credentials, Open case, Escalate. Each states exactly what it does.

**AI thinking state:** while agents work, the scan ring rotates in the active step and the reasoning stream shows a soft-pulsing "watching" line. Analyst never sees a dead spinner with no context.

### 4.2 Dashboard

The MONITOR home. Answers "what needs me right now?" in under three seconds.

- Top row: four metric tiles — Open alerts, Active hunts, Events (24h), Critical (24h). Critical uses `--sev-critical`; active hunts use emerald.
- Center: **priority alert queue** — a dense table sorted by risk, with severity badge, description, MITRE ID (mono), affected asset (mono), age. Row hover reveals a "Hunt with AI" action that deep-links into the AI workspace pre-scoped to that alert.
- Right rail: collector/connector health per tenant (green = healthy), and a live "guardian" activity feed (subtle, ambient — the eye is watching).
- Optional radial "threat overview" using the logo ring geometry, segments colored by severity — decorative but on-brand; keep it secondary to the queue.

### 4.3 Login

The one screen allowed a moment of drama.

- Centered card on `--bg-base`, with a single soft **emerald radial glow** behind the ARGUS eye mark — the guardian opening its eye.
- The scanning ring animates once on load (a slow single rotation) then settles.
- Minimal fields: email, password, tenant (for MSSP context), SSO button. Copy is calm and confident, not salesy.
- Error states are specific and blameless: "That email or password didn't match. Try again."

### 4.4 Investigation workspace / Cases

- Case header: title, severity, status pill, assigned analyst, linked tenant.
- Tabbed body: Overview · Evidence · Timeline · Graph · Notes · Report.
- Evidence items carry provenance (which agent/collector surfaced them) — auditability again.
- Case status flows: New → Investigating → Contained → Resolved → Closed, each a distinct pill color drawn from severity/accent families.

### 4.5 Evidence graph

- Force-directed node graph: hosts, users, processes, IPs, IOCs as nodes; relationships as edges.
- Node color encodes entity type (purple family) or severity when relevant; selected node gets the **eye-highlight** glow.
- Left drawer: filters by entity type, time window, tenant. Right drawer: selected-node detail.
- Interaction: hover highlights the node's neighborhood and dims the rest; click pins detail; double-click expands one hop. Smooth, damped physics — never chaotic.

### 4.6 Timeline analysis

- Horizontal swimlanes per entity (host/user/process); events plotted chronologically with severity-colored markers.
- Brush-to-zoom on a time range; the attack chain overlays as a connected path across lanes.
- Scrubber at the bottom; playback re-animates the attack unfolding (reduced-motion: static).

### 4.7 MITRE ATT&CK explorer

- The classic tactics × techniques matrix, dark-themed.
- Cells tinted by **coverage/hit frequency for the selected tenant** (emerald intensity = more detections), so managers see gaps at a glance.
- Click a technique → detections, mapped alerts, related hunts.

### 4.8 Entity explorer

- Search-first. Enter a host/user/IP → a 360° profile: risk score (confidence ring), recent events, related entities, associated cases, first/last seen.
- Pivots everywhere link back to graph, timeline, and AI workspace.

### 4.9 Threat intelligence

- IOC feeds and enrichment; searchable indicators with source provenance and confidence.
- Emerald "match" indicators when an IOC correlates to tenant telemetry.

### 4.10 Reports

- Template gallery (Executive summary, Incident report, Compliance) with live preview.
- Reports inherit the brand: purple cover with the eye mark, emerald section accents. Export to PDF.

### 4.11 Integrations (connectors)

Directly serves the roadmap goal: configure SIEM/XDR/EDR connectors **with no terminal work**.

- Grid of connector cards: Wazuh, Cortex XDR, CrowdStrike, FortiSIEM, Sentinel, Chronicle, QRadar, etc., each with vendor logo, status pill, last-sync time (mono).
- A **guided connection wizard** (not a raw form): pick vendor → enter endpoint/credentials → test connection (live scan-ring while testing) → map fields → confirm. Test-connection success flips the card to emerald "healthy."

### 4.12 Multi-tenant management

- MSSP control plane: table of client tenants with sector tag (banking, healthcare, insurance…), health, open alerts, connector count.
- Row → tenant detail. Global tenant switcher in the top bar mirrors this. Strict visual cues make it impossible to forget which client's data you're viewing (tenant name always visible, subtle sector-colored accent).

### 4.13 Settings & user profile

- Standard enterprise settings: account, security (MFA), notifications, API keys, team/roles (RBAC), appearance.
- Profile: avatar (initials in an emerald ring), role, assigned tenants, activity.

---

## 5. Component library

One language derived from the tokens above.

- **Sidebar nav:** icon + label, active item marked by an emerald left-bar + eye-highlight; collapses to icons.
- **Cards:** `--bg-elevated`, 0.5px `--border-subtle`, 12px radius, no shadow (or a whisper-soft one). Optional emerald top-border for "active/healthy" cards.
- **Tables:** dense, row hover = `--bg-hover`, technical columns in mono, severity as leading badge. Sticky header, virtualized for large event sets.
- **Badges/pills:** severity (filled tint + same-family text), status (outline), count (mono).
- **Buttons:** primary = emerald fill on dark; secondary = subtle border; ghost for tertiary. One primary per view.
- **Search:** global (top bar) with query-syntax hints; scoped filters as removable chips.
- **Graphs & timelines:** as specified per screen; consistent node/marker language.
- **Modals & drawers:** drawers for contextual detail (slide from right), modals only for confirmations/destructive actions.
- **Tabs:** underline style, emerald active indicator.
- **Notifications:** top-right toasts; critical alerts get a persistent banner with the severity color.
- **Empty states:** faint scan-ring watermark + one-line invitation + a primary action. Never a dead end. ("No active hunts. Start one from an alert.")
- **Loading states:** rotating scan ring, not a generic spinner. Skeleton rows for tables.
- **Success states:** emerald check inside a ring; brief, no exclamation marks.
- **Error states:** specific, blameless, actionable. State what happened and the fix.

---

## 6. Suggested implementation stack

(For when this feeds into Claude Code — not prescriptive, but fits the existing FastAPI backend.)

- **React + Vite + TypeScript**, Tailwind CSS with the tokens above wired into `tailwind.config` as CSS variables so dark theme is the default and only theme.
- **TanStack Query** for API calls against the FastAPI routes; **TanStack Table** for the virtualized event/alert tables.
- **Recharts** or **visx** for timelines/sparklines; **react-force-graph** or **cytoscape** for the evidence graph.
- **Framer Motion** for the scan-ring / thinking animations, gated behind `prefers-reduced-motion`.
- Auth against the existing JWT flow; tenant context carried in a top-level provider so every query is tenant-scoped (mirrors the backend RLS).

---

## 7. Build order (Phase-1 frontend)

1. Design tokens + Tailwind config + base layout shell (sidebar, top bar, tenant switcher).
2. Login (auth flow against existing JWT).
3. Dashboard + Alerts queue (read paths first).
4. **AI workspace** (the signature — worth the most iteration).
5. Cases + Investigation workspace.
6. Evidence graph + Timeline.
7. Integrations wizard (connector config, the roadmap goal).
8. MITRE explorer, Entity explorer, Threat intel.
9. Reports, Settings, Multi-tenant management.

Ship the shell + login + dashboard first so there's a walkable skeleton, then deepen the AI workspace.
