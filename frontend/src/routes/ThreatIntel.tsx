import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { ExternalLink, Search } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import { useAuth } from '../context/AuthContext'
import * as api from '../lib/api'
import type { CTILookup, IndicatorType } from '../lib/api'

const TYPES: { value: IndicatorType; label: string; placeholder: string }[] = [
  { value: 'ip', label: 'IP', placeholder: '185.220.101.42' },
  { value: 'domain', label: 'Domain', placeholder: 'evil.example.com' },
  { value: 'url', label: 'URL', placeholder: 'https://evil.example.com/payload' },
  { value: 'hash', label: 'Hash', placeholder: 'sha256 / md5 of a sample' },
  { value: 'cve', label: 'CVE', placeholder: 'CVE-2024-3400' },
]

export function ThreatIntel() {
  const { token } = useAuth()
  const [type, setType] = useState<IndicatorType>('ip')
  const [value, setValue] = useState('')
  const [result, setResult] = useState<CTILookup | null>(null)

  const lookup = useMutation({
    mutationFn: () => api.ctiLookup(token!, type, value.trim()),
    onSuccess: setResult,
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    if (value.trim()) lookup.mutate()
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

          {result.findings.map((f, i) => (
            <div key={i} className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
              <div className="flex items-center justify-between gap-2">
                <span className="text-card-title">{f.provider}</span>
                <span className={`text-label ${f.found ? 'text-accent' : 'text-tertiary'}`}>
                  {f.found ? 'match' : 'no record'}
                </span>
              </div>
              {f.summary && <p className="mt-1.5 text-label text-secondary">{f.summary}</p>}
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
                {f.confidence !== null && <span>confidence {f.confidence}</span>}
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
          ))}
        </div>
      )}

      {!result && !lookup.isPending && (
        <div className="flex flex-col items-center gap-3 py-10">
          <ArgusMark size={48} className="opacity-20" />
          <p className="text-label text-tertiary">
            No lookups yet. Paste an indicator from an investigation.
          </p>
        </div>
      )}
    </div>
  )
}
