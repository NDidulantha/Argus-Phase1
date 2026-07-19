import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Crosshair, ExternalLink, Radar, Search } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import { useAuth } from '../context/AuthContext'
import * as api from '../lib/api'
import type { CTIFinding, CTIHuntFinding, CTILookup, IndicatorType } from '../lib/api'
import { formatCount } from '../lib/format'

// "3 minutes ago" style relative time for the autonomous hunter's last sweep.
function relativeTime(iso: string): string {
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (secs < 90) return 'just now'
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`
  return `${Math.round(secs / 86400)}d ago`
}

const TYPES: { value: IndicatorType; label: string; placeholder: string }[] = [
  { value: 'ip', label: 'IP', placeholder: '185.220.101.42' },
  { value: 'domain', label: 'Domain', placeholder: 'evil.example.com' },
  { value: 'url', label: 'URL', placeholder: 'https://evil.example.com/payload' },
  { value: 'hash', label: 'Hash', placeholder: 'sha256 / md5 of a sample' },
  { value: 'cve', label: 'CVE', placeholder: 'CVE-2024-3400' },
]

// Severity color for a 0-100 maliciousness signal. Zero is genuinely clean
// (accent green); anything flagged escalates through the severity ramp.
function scoreColor(score: number): string {
  if (score >= 75) return 'var(--sev-critical)'
  if (score >= 25) return 'var(--sev-high)'
  if (score > 0) return 'var(--sev-medium)'
  return 'var(--accent)'
}

function ScoreRing({
  score,
  numerator,
  denominator,
  caption,
}: {
  score: number
  numerator?: number
  denominator?: number
  caption: string
}) {
  const r = 26
  const c = 2 * Math.PI * r
  const filled = (Math.min(100, Math.max(0, score)) / 100) * c
  const color = scoreColor(score)
  const center =
    numerator !== undefined && denominator ? `${numerator}/${denominator}` : String(score)

  return (
    <div className="flex w-20 shrink-0 flex-col items-center gap-1">
      <svg width="64" height="64" viewBox="0 0 64 64" role="img" aria-label={`${caption}: ${center}`}>
        <circle cx="32" cy="32" r={r} fill="none" stroke="var(--border-subtle)" strokeWidth="5" />
        <circle
          cx="32"
          cy="32"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="5"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${c - filled}`}
          transform="rotate(-90 32 32)"
        />
        <text
          x="32"
          y="32"
          textAnchor="middle"
          dominantBaseline="central"
          fill={color}
          style={{ font: '600 13px ui-monospace, monospace' }}
        >
          {center}
        </text>
      </svg>
      <span className="text-center text-[10px] leading-3 text-tertiary">{caption}</span>
    </div>
  )
}

const DETAIL_LABELS: Record<string, string> = {
  as_owner: 'AS owner',
  asn: 'ASN',
  isp: 'ISP',
  usage_type: 'Usage',
  historical_domains: 'Domains hosted here',
  resolves_to: 'Resolves to',
  also_known_as: 'Also known as',
  claims_to_be: 'Claims to be',
  first_seen_in_wild: 'First seen in the wild',
  size_bytes: 'Size',
  community_reputation: 'Community reputation',
  distinct_reporters: 'Distinct reporters',
  final_url: 'Final URL',
  page_title: 'Page title',
}

function detailLabel(key: string): string {
  return DETAIL_LABELS[key] ?? key.replace(/_/g, ' ').replace(/^./, (m) => m.toUpperCase())
}

function detailValue(key: string, v: string | number | boolean | string[]): string {
  if (key === 'size_bytes' && typeof v === 'number') {
    return v > 1_048_576 ? `${(v / 1_048_576).toFixed(1)} MB` : `${(v / 1024).toFixed(1)} KB`
  }
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  return String(v)
}

function DetailGrid({ details }: { details: CTIFinding['details'] }) {
  const entries = Object.entries(details)
  if (entries.length === 0) return null
  return (
    <dl className="mt-2.5 grid gap-x-5 gap-y-1.5 border-t-[0.5px] border-subtle pt-2.5 sm:grid-cols-2">
      {entries.map(([key, v]) => (
        <div key={key} className="min-w-0">
          <dt className="text-[10px] uppercase leading-4 tracking-[0.08em] text-tertiary">
            {detailLabel(key)}
          </dt>
          {Array.isArray(v) ? (
            <dd className="mt-0.5 flex flex-wrap gap-1">
              {v.map((item) => (
                <span
                  key={item}
                  className="max-w-full truncate rounded-full border-[0.5px] border-subtle px-2 py-0.5 font-mono text-[11px] leading-4 text-secondary"
                  title={item}
                >
                  {item}
                </span>
              ))}
            </dd>
          ) : (
            <dd className="truncate font-mono text-data text-primary" title={detailValue(key, v)}>
              {detailValue(key, v)}
            </dd>
          )}
        </div>
      ))}
    </dl>
  )
}

function ringPropsFor(f: CTIFinding): { numerator?: number; denominator?: number; caption: string } {
  if (f.provider === 'virustotal') {
    const stats = (f.raw?.stats ?? {}) as Record<string, number>
    const total = Object.values(stats).reduce((a, b) => a + (b || 0), 0)
    if (total > 0) {
      return {
        numerator: (stats.malicious || 0) + (stats.suspicious || 0),
        denominator: total,
        caption: 'engines flagged',
      }
    }
    return { caption: 'engines flagged' }
  }
  if (f.provider === 'abuseipdb') return { caption: 'abuse confidence' }
  return { caption: 'confidence' }
}

function FindingCard({ finding: f }: { finding: CTIFinding }) {
  return (
    <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-card-title">{f.provider}</span>
        <span className={`text-label ${f.found ? 'text-accent' : 'text-tertiary'}`}>
          {f.found ? 'match' : 'no record'}
        </span>
      </div>
      <div className="mt-2.5 flex gap-4">
        {f.confidence !== null && <ScoreRing score={f.confidence} {...ringPropsFor(f)} />}
        <div className="min-w-0 flex-1">
          {f.summary && <p className="text-label text-secondary">{f.summary}</p>}
          {(f.malware.length > 0 || f.threat_actors.length > 0 || f.tags.length > 0) && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {f.malware.map((m) => (
                <span
                  key={m}
                  className="rounded-full bg-sev-critical/15 px-2 py-0.5 font-mono text-[11px] leading-4 text-sev-critical"
                >
                  {m}
                </span>
              ))}
              {f.threat_actors.map((a) => (
                <span
                  key={a}
                  className="rounded-full bg-sev-high/15 px-2 py-0.5 font-mono text-[11px] leading-4 text-sev-high"
                >
                  {a}
                </span>
              ))}
              {f.tags.map((t) => (
                <span
                  key={t}
                  className="rounded-full border-[0.5px] border-subtle px-2 py-0.5 text-[11px] leading-4 text-secondary"
                >
                  {t}
                </span>
              ))}
            </div>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] leading-4 text-tertiary">
            {f.first_seen && <span>first seen {f.first_seen}</span>}
            {f.last_seen && <span>last seen {f.last_seen}</span>}
            {f.reference_url && (
              <a
                href={f.reference_url}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 text-accent transition-colors duration-120 hover:text-accent-dim"
              >
                source <ExternalLink size={10} strokeWidth={1.5} />
              </a>
            )}
          </div>
        </div>
      </div>
      <DetailGrid details={f.details ?? {}} />
    </div>
  )
}

// A single standing lead from the autonomous hunter. Clicking opens the full
// live lookup for the indicator (same pivot as the manual hunt rows).
function AutoHuntRow({
  finding,
  onOpen,
}: {
  finding: CTIHuntFinding
  onOpen: () => void
}) {
  const summary = finding.finding.summary
  return (
    <button
      type="button"
      onClick={onOpen}
      title="Open full lookup"
      className="flex w-full items-start gap-3 rounded-control border-[0.5px] border-subtle bg-base px-3 py-2 text-left transition-colors duration-120 hover:bg-hover"
    >
      <span
        className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
        style={{ background: scoreColor(finding.confidence) }}
      />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="min-w-0 truncate font-mono text-data text-primary">
            {finding.value}
          </span>
          <span className="shrink-0 rounded-full border-[0.5px] border-subtle px-2 py-0.5 text-[11px] leading-4 text-secondary">
            {finding.indicator_type}
          </span>
        </span>
        {summary && (
          <span className="mt-0.5 block truncate text-[11px] leading-4 text-tertiary">
            {summary}
          </span>
        )}
      </span>
      <span className="flex shrink-0 flex-col items-end gap-0.5">
        <span
          className="font-mono text-[11px] leading-4"
          style={{ color: scoreColor(finding.confidence) }}
        >
          {finding.confidence}/100
        </span>
        <span className="text-[11px] leading-4 text-tertiary">
          {finding.provider} · {formatCount(finding.local_events)} events
        </span>
      </span>
    </button>
  )
}

export function ThreatIntel() {
  const { token } = useAuth()
  const [type, setType] = useState<IndicatorType>('ip')
  const [value, setValue] = useState('')
  const [result, setResult] = useState<CTILookup | null>(null)

  const lookup = useMutation({
    mutationFn: ({ t, v }: { t: IndicatorType; v: string }) => api.ctiLookup(token!, t, v),
    onSuccess: setResult,
  })
  // Durable leads from the autonomous hunter — present the moment the screen
  // opens, no click required. Polls slowly so a background sweep that lands
  // while the analyst is on this page appears on its own.
  const autoHunt = useQuery({
    queryKey: ['cti-hunt-findings'],
    queryFn: () => api.ctiHuntFindings(token!, 100),
    enabled: !!token,
    refetchInterval: 60_000,
  })
  const hunt = useMutation({
    mutationFn: () => api.ctiHunt(token!, 60),
    onSuccess: () => autoHunt.refetch(),
  })

  function runLookup(t: IndicatorType, v: string) {
    setType(t)
    setValue(v)
    setResult(null)
    lookup.mutate({ t, v })
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    if (value.trim()) runLookup(type, value.trim())
  }

  const placeholder = TYPES.find((t) => t.value === type)!.placeholder

  return (
    <div className="space-y-4 p-6">
      <h1 className="text-page-title">Threat intel</h1>
      <p className="max-w-xl text-label text-secondary">
        Look up an indicator across the connected CTI feeds. Every finding carries its source
        and a reference — provenance first.
      </p>

      <form onSubmit={submit} className="flex max-w-2xl flex-wrap gap-2">
        <div className="flex gap-1.5">
          {TYPES.map((t) => (
            <button
              key={t.value}
              type="button"
              onClick={() => setType(t.value)}
              className={`rounded-full px-3 py-1 text-label transition-colors duration-120 ${
                type === t.value
                  ? 'bg-accent-bg text-accent'
                  : 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="flex w-full gap-2">
          <label className="flex flex-1 items-center gap-2.5 rounded-control border-[0.5px] border-subtle bg-elevated px-3 py-2 transition-colors duration-120 focus-within:border-strong">
            <Search size={14} strokeWidth={1.5} className="text-tertiary" />
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              spellCheck={false}
              className="w-full bg-transparent font-mono text-data text-primary outline-none placeholder:text-tertiary"
            />
          </label>
          <button
            type="submit"
            disabled={lookup.isPending || !value.trim()}
            className="rounded-control bg-accent px-4 py-2 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
          >
            {lookup.isPending ? 'Looking up…' : 'Look up'}
          </button>
        </div>
      </form>

      {lookup.isPending && (
        <div className="flex items-center gap-3 py-6">
          <ArgusMark size={32} spinning className="opacity-50" />
          <span className="animate-pulse text-label text-secondary">
            Querying CTI providers…
          </span>
        </div>
      )}
      {lookup.isError && (
        <p className="text-label text-sev-critical">
          The lookup failed: {(lookup.error as Error).message}. Check the indicator and try
          again.
        </p>
      )}

      {result && !lookup.isPending && (
        <div className="max-w-2xl space-y-3">
          <div
            className={`rounded-card border-[0.5px] p-3 text-label ${
              result.any_found
                ? 'border-accent/40 bg-accent-bg/30 text-accent'
                : 'border-subtle bg-elevated text-secondary'
            }`}
          >
            {result.any_found ? '● Known indicator' : 'No provider recognizes this indicator'} ·{' '}
            <span className="font-mono text-data">{result.value}</span> ·{' '}
            {result.providers_queried} providers queried
          </div>

          {result.sightings && (
            <div className="rounded-card border-[0.5px] border-sev-high/40 bg-sev-high/10 p-3 text-label text-sev-high">
              <span className="font-medium">Seen in your telemetry</span> —{' '}
              {result.sightings.events > 0 ? (
                <>
                  {formatCount(result.sightings.events)} event(s)
                  {result.sightings.first_seen && (
                    <span className="font-mono text-[11px]">
                      {' '}
                      · {result.sightings.first_seen.slice(0, 10)} →{' '}
                      {result.sightings.last_seen?.slice(0, 10)}
                    </span>
                  )}
                </>
              ) : (
                'present in the evidence graph'
              )}
            </div>
          )}

          {result.findings.map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
        </div>
      )}

      <section className="max-w-2xl rounded-card border-[0.5px] border-accent/30 bg-accent-bg/20 p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-card-title">
              <Radar
                size={14}
                strokeWidth={1.5}
                className={`text-accent ${autoHunt.isFetching ? 'animate-pulse' : ''}`}
              />
              Autonomous hunter
            </h2>
            <p className="mt-1 text-label text-secondary">
              Runs on its own timer across every tenant, re-checking your indicators as threat
              intel changes. These are leads it surfaced while nobody was watching.
            </p>
          </div>
          <span className="shrink-0 text-[11px] leading-4 text-tertiary">
            {autoHunt.data?.last_swept
              ? `swept ${relativeTime(autoHunt.data.last_swept)}`
              : 'no sweep yet'}
          </span>
        </div>

        {autoHunt.data && autoHunt.data.findings.length > 0 ? (
          <div className="mt-3 space-y-2">
            {autoHunt.data.findings.map((f) => (
              <AutoHuntRow
                key={`${f.provider}:${f.indicator_type}:${f.value}`}
                finding={f}
                onOpen={() => runLookup(f.indicator_type, f.value)}
              />
            ))}
          </div>
        ) : (
          <p className="mt-3 text-label text-tertiary">
            {autoHunt.isLoading
              ? 'Loading standing leads…'
              : 'No standing leads yet — the hunter has not flagged anything in your data.'}
          </p>
        )}
      </section>

      <section className="max-w-2xl rounded-card border-[0.5px] border-subtle bg-elevated p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-card-title">
              <Crosshair size={14} strokeWidth={1.5} className="text-accent" />
              Hunt stored indicators
            </h2>
            <p className="mt-1 text-label text-secondary">
              Sweep every public IP, hash, domain and URL already in this tenant's telemetry
              through all CTI feeds. Cached 24h — repeat sweeps are cheap.
            </p>
          </div>
          <button
            type="button"
            onClick={() => hunt.mutate()}
            disabled={hunt.isPending}
            className="shrink-0 rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
          >
            {hunt.isPending ? 'Hunting…' : 'Run hunt'}
          </button>
        </div>

        {hunt.isPending && (
          <div className="mt-3 flex items-center gap-3">
            <ArgusMark size={24} spinning className="opacity-50" />
            <span className="animate-pulse text-label text-secondary">
              Checking your indicators against the feeds…
            </span>
          </div>
        )}
        {hunt.isError && (
          <p className="mt-3 text-label text-sev-critical">The hunt failed. Try again.</p>
        )}
        {hunt.data && !hunt.isPending && (
          <div className="mt-3 space-y-2">
            <p className="text-label text-secondary">
              Checked{' '}
              <span className="font-mono text-data text-primary">
                {hunt.data.indicators_checked}
              </span>{' '}
              indicators —{' '}
              {hunt.data.hits.length > 0 ? (
                <span className="text-sev-high">{hunt.data.hits.length} flagged</span>
              ) : (
                <span className="text-accent">none flagged by any feed</span>
              )}
            </p>
            {hunt.data.hits.map((h) => (
              <button
                key={`${h.indicator_type}:${h.value}`}
                type="button"
                onClick={() => runLookup(h.indicator_type, h.value)}
                title="Open full lookup"
                className="flex w-full items-center gap-3 rounded-control border-[0.5px] border-subtle bg-base px-3 py-2 text-left transition-colors duration-120 hover:bg-hover"
              >
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{ background: scoreColor(h.max_confidence) }}
                />
                <span className="min-w-0 flex-1 truncate font-mono text-data text-primary">
                  {h.value}
                </span>
                <span className="shrink-0 rounded-full border-[0.5px] border-subtle px-2 py-0.5 text-[11px] leading-4 text-secondary">
                  {h.indicator_type}
                </span>
                <span
                  className="shrink-0 font-mono text-[11px] leading-4"
                  style={{ color: scoreColor(h.max_confidence) }}
                >
                  {h.max_confidence}/100
                </span>
                <span className="shrink-0 font-mono text-[11px] leading-4 text-tertiary">
                  {formatCount(h.local_events)} events
                </span>
                <span className="shrink-0 text-[11px] leading-4 text-tertiary">
                  {h.findings.map((f) => f.provider).join(', ')}
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      {!result && !lookup.isPending && (
        <div className="flex flex-col items-center gap-3 py-6">
          <ArgusMark size={48} className="opacity-20" />
          <p className="text-label text-tertiary">
            No lookups yet. Paste an indicator from an investigation, or run a hunt over what
            the fleet has already seen.
          </p>
        </div>
      )}
    </div>
  )
}
