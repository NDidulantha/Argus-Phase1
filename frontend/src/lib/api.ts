// Thin client for the FastAPI backend (proxied to :8000 in dev — see vite.config.ts).

const API_BASE = '/api/v1'

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface Me {
  user_id: string
  tenant_id: string
  role: string
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, init)
  if (!res.ok) {
    const detail = await res
      .json()
      .then((body: { detail?: string }) => body.detail)
      .catch(() => undefined)
    throw new ApiError(res.status, detail ?? res.statusText)
  }
  return res.json() as Promise<T>
}

export function login(tenantSlug: string, email: string, password: string) {
  return request<TokenResponse>('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant_slug: tenantSlug, email, password }),
  })
}

export function fetchMe(token: string) {
  return request<Me>('/auth/me', {
    headers: { Authorization: `Bearer ${token}` },
  })
}

export async function changePassword(
  token: string,
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  const res = await fetch(`${API_BASE}/auth/password`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
  if (!res.ok) {
    const detail = await res
      .json()
      .then((b: { detail?: string }) => b.detail)
      .catch(() => undefined)
    throw new ApiError(res.status, detail ?? res.statusText)
  }
}

export interface EvidenceItem {
  id: number
  host_name: string | null
  window_start: string
  window_end: string
  event_count: number
  technique_ids: string[]
  tactics: string[]
  score: number
  status: string
}

export interface EvidenceList {
  items: EvidenceItem[]
  total: number
}

export interface EventItem {
  id: number
  event_time: string
  category: string
  action: string | null
  severity: number | null
  host_name: string | null
  user_name: string | null
  src_ip: string | null
  dst_ip: string | null
}

export interface EventList {
  items: EventItem[]
  total: number
  limit: number
  offset: number
}

function authed(token: string, params?: Record<string, string | number | undefined>) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined) qs.set(k, String(v))
  }
  const suffix = qs.size ? `?${qs}` : ''
  return { suffix, init: { headers: { Authorization: `Bearer ${token}` } } }
}

export function listEvidence(token: string, params?: { min_score?: number; limit?: number }) {
  const { suffix, init } = authed(token, params)
  return request<EvidenceList>(`/evidence${suffix}`, init)
}

export function listEvents(
  token: string,
  params?: {
    start?: string
    end?: string
    min_severity?: number
    host?: string
    limit?: number
    offset?: number
  },
) {
  const { suffix, init } = authed(token, params)
  return request<EventList>(`/events${suffix}`, init)
}

export function healthReady() {
  return request<{ status: string }>('/health/ready')
}

export interface TechniqueBrief {
  technique_id: string
  name: string | null
  tactics: string[]
}

export interface EntityBrief {
  id: number
  entity_type: string
  entity_key: string
}

export interface EvidenceDetail extends EvidenceItem {
  score_breakdown: Record<string, number>
  techniques: TechniqueBrief[]
  entities: EntityBrief[]
}

export interface SimilarEntry {
  id: number
  host_name: string | null
  score: number
  technique_ids: string[]
  similarity: number
}

export interface StageEvent {
  stage: string
  detail: string
  at: string
}

export interface InvestigationRun {
  investigation_id: number
  evidence_id: number
  status: 'running' | 'complete' | 'failed'
  provider: string | null
  model: string | null
  narrative: string | null
  grounded: boolean | null
  unsupported_terms: string[]
  directives: string[]
  stages: StageEvent[]
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
}

export type InvestigateStreamEvent =
  | ({ type: 'stage' } & StageEvent)
  | {
      type: 'complete'
      investigation: InvestigationRun
      techniques: unknown[]
      similar_count: number
    }
  | { type: 'error'; status_code: number; detail: string }

export function getEvidenceDetail(token: string, id: number) {
  const { init } = authed(token)
  return request<EvidenceDetail>(`/evidence/${id}`, init)
}

export function getSimilarEvidence(token: string, id: number, k = 5) {
  const { suffix, init } = authed(token, { k })
  return request<{ evidence_id: number; similar: SimilarEntry[] }>(
    `/evidence/${id}/similar${suffix}`,
    init,
  )
}

export function getReasoningProviders(token: string) {
  const { init } = authed(token)
  return request<{ providers: string[]; default: string }>('/evidence/reasoning/providers', init)
}

export function listInvestigations(token: string, evidenceId: number) {
  const { init } = authed(token)
  return request<InvestigationRun[]>(`/evidence/${evidenceId}/investigations`, init)
}

// SSE over fetch (EventSource can't POST or carry the bearer token).
export async function investigateStream(
  token: string,
  evidenceId: number,
  directives: string[],
  onEvent: (event: InvestigateStreamEvent) => void,
): Promise<void> {
  const res = await fetch(`${API_BASE}/evidence/${evidenceId}/investigate/stream`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ directives }),
  })
  if (!res.ok || !res.body) throw new ApiError(res.status, res.statusText)
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let sep
    while ((sep = buffer.indexOf('\n\n')) >= 0) {
      const chunk = buffer.slice(0, sep)
      buffer = buffer.slice(sep + 2)
      const data = chunk.split('\n').find((l) => l.startsWith('data: '))
      if (data) onEvent(JSON.parse(data.slice(6)) as InvestigateStreamEvent)
    }
  }
}

export type CaseStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface CaseItem {
  id: number
  title: string
  severity: CaseSeverity
  status: CaseStatus
  assignee_email: string | null
  evidence_count: number
  created_at: string
  updated_at: string
}

export interface CaseNote {
  id: number
  author_email: string | null
  body: string
  created_at: string
}

export interface CaseEvidenceBrief {
  id: number
  host_name: string | null
  score: number
  technique_ids: string[]
  window_end: string
  status: string
}

export interface CaseDetail extends CaseItem {
  description: string | null
  evidence: CaseEvidenceBrief[]
  notes: CaseNote[]
}

function jsonInit(token: string, method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }
}

export function listCases(token: string, params?: { status?: CaseStatus; limit?: number }) {
  const { suffix, init } = authed(token, params)
  return request<{ items: CaseItem[]; total: number }>(`/cases${suffix}`, init)
}

export function getCase(token: string, id: number) {
  const { init } = authed(token)
  return request<CaseDetail>(`/cases/${id}`, init)
}

export function createCase(
  token: string,
  body: { title: string; description?: string; severity?: CaseSeverity; evidence_ids?: number[] },
) {
  return request<CaseDetail>('/cases', jsonInit(token, 'POST', body))
}

export function updateCase(
  token: string,
  id: number,
  body: { title?: string; description?: string; severity?: CaseSeverity; status?: CaseStatus },
) {
  return request<CaseDetail>(`/cases/${id}`, jsonInit(token, 'PATCH', body))
}

export function addCaseNote(token: string, id: number, body: string) {
  return request<CaseDetail>(`/cases/${id}/notes`, jsonInit(token, 'POST', { body }))
}

export interface GraphEntity {
  id: number
  entity_type: string
  entity_key: string
  display_name: string | null
  first_seen: string
  last_seen: string
}

export interface GraphEdge {
  src_entity_id: number
  dst_entity_id: number
  relation: string
  observation_count: number
}

export interface GraphOverview {
  entities: GraphEntity[]
  edges: GraphEdge[]
  total_entities: number
}

export function getGraphOverview(token: string, params?: { search?: string; limit?: number }) {
  const { suffix, init } = authed(token, params)
  return request<GraphOverview>(`/graph/overview${suffix}`, init)
}

export function getNeighborhood(token: string, entityId: number) {
  const { init } = authed(token)
  return request<{ root: GraphEntity; edges: GraphEdge[]; entities: GraphEntity[] }>(
    `/graph/entities/${entityId}/neighborhood`,
    init,
  )
}

export function listEntities(
  token: string,
  params?: { entity_type?: string; search?: string; limit?: number },
) {
  const { suffix, init } = authed(token, params)
  return request<{ items: GraphEntity[]; total: number }>(`/graph/entities${suffix}`, init)
}

export interface MatrixTechnique {
  technique_id: string
  name: string
  tactics: string[]
  is_subtechnique: boolean
  parent_id: string | null
}

export interface TechniqueDetail extends MatrixTechnique {
  url: string | null
  description: string | null
}

export interface CoverageEntry {
  technique_id: string
  name: string | null
  tactics: string[]
  event_count: number
  first_seen: string
  last_seen: string
  sources: Record<string, number>
  max_confidence: number
}

export interface Coverage {
  techniques_seen: number
  total_events: number
  by_source: Record<string, number>
  coverage: CoverageEntry[]
}

export function getMitreMatrix(token: string) {
  const { init } = authed(token)
  return request<MatrixTechnique[]>('/mitre/matrix', init)
}

export function getMitreCoverage(token: string) {
  const { init } = authed(token)
  return request<Coverage>('/mitre/coverage', init)
}

export function getTechnique(token: string, id: string) {
  const { init } = authed(token)
  return request<TechniqueDetail>(`/mitre/techniques/${id}`, init)
}

export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'cve'

export interface CTIFinding {
  provider: string
  found: boolean
  malware: string[]
  threat_actors: string[]
  tags: string[]
  first_seen: string | null
  last_seen: string | null
  confidence: number | null
  reference_url: string | null
  summary: string | null
}

export interface CTILookup {
  indicator_type: IndicatorType
  value: string
  findings: CTIFinding[]
  providers_queried: number
  any_found: boolean
}

export function ctiLookup(token: string, indicatorType: IndicatorType, value: string) {
  return request<CTILookup>(
    '/cti/lookup',
    jsonInit(token, 'POST', { indicator_type: indicatorType, value }),
  )
}

export interface ConnectorCatalogEntry {
  vendor: string
  name: string
  description: string
  supported: boolean
  endpoint_hint?: string
  credential_fields?: string[]
  default_mapping?: Record<string, string>
}

export interface Connector {
  id: number
  vendor: string
  name: string
  endpoint_url: string
  verify_tls: boolean
  field_mapping: Record<string, string>
  status: 'unconfigured' | 'healthy' | 'error'
  last_checked_at: string | null
  last_error: string | null
  created_at: string
  updated_at: string
}

export interface ConnectorDraft {
  vendor: string
  name: string
  endpoint_url: string
  credentials: Record<string, string>
  verify_tls: boolean
}

export interface ConnectorTestResult {
  ok: boolean
  detail: string
  latency_ms: number
}

export function getConnectorCatalog(token: string) {
  const { init } = authed(token)
  return request<ConnectorCatalogEntry[]>('/connectors/catalog', init)
}

export function listConnectors(token: string) {
  const { init } = authed(token)
  return request<{ items: Connector[] }>('/connectors', init)
}

export function testConnectorDraft(token: string, draft: Omit<ConnectorDraft, 'name'>) {
  return request<ConnectorTestResult>('/connectors/test', jsonInit(token, 'POST', draft))
}

export function createConnector(token: string, draft: ConnectorDraft) {
  return request<Connector>('/connectors', jsonInit(token, 'POST', draft))
}

export function testConnector(token: string, id: number) {
  return request<Connector>(`/connectors/${id}/test`, jsonInit(token, 'POST', {}))
}

export async function deleteConnector(token: string, id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/connectors/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
}
