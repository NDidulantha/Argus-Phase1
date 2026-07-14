import { useEffect, useMemo, useRef, useState } from 'react'
import { Pause, Play, ZoomOut } from 'lucide-react'
import { ArgusMark } from '../ArgusMark'
import { useAuthedQuery } from '../../hooks/useAuthedQuery'
import * as api from '../../lib/api'
import type { EventItem } from '../../lib/api'
import { formatUtcDateTime, formatUtcTime } from '../../lib/format'
import { eventSeverity } from '../../lib/severity'

const SEV_FILL: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
}

const W = 1000
const LANE_H = 34
const LABEL_W = 150
const AXIS_H = 26
const MAX_LANES = 6

const PRESETS = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
  { label: 'Latest', hours: null },
] as const

type LaneKey = 'host_name' | 'user_name'

interface TimelineViewProps {
  initialStart?: string
  initialEnd?: string
  hostFilter?: string[]
}

export function TimelineView({ initialStart, initialEnd, hostFilter }: TimelineViewProps) {
  const [laneKey, setLaneKey] = useState<LaneKey>('host_name')
  const [range, setRange] = useState<{ start: number; end: number } | null>(() =>
    initialStart && initialEnd
      ? { start: new Date(initialStart).getTime() - 60_000, end: new Date(initialEnd).getTime() + 60_000 }
      : null,
  )
  const [selected, setSelected] = useState<EventItem | null>(null)
  const [brush, setBrush] = useState<{ from: number; to: number } | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [playing, setPlaying] = useState(false)
  const svgRef = useRef<SVGSVGElement>(null)
  const reducedMotion = useMemo(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    [],
  )

  const events = useAuthedQuery(['timeline', 'events', range?.start, range?.end], (t) =>
    api.listEvents(t, {
      start: range ? new Date(range.start).toISOString() : undefined,
      end: range ? new Date(range.end).toISOString() : undefined,
      limit: 200,
    }),
  )
  const evidence = useAuthedQuery(['evidence', 'queue'], (t) => api.listEvidence(t, { limit: 200 }))

  const items = useMemo(() => {
    let list = events.data?.items ?? []
    if (hostFilter?.length) {
      const hosts = new Set(hostFilter.map((h) => h.toLowerCase()))
      list = list.filter((e) => e.host_name && hosts.has(e.host_name.toLowerCase()))
    }
    return list
  }, [events.data, hostFilter])

  // Time domain: explicit range, else the extent of the loaded events.
  const domain = useMemo(() => {
    if (range) return range
    if (items.length === 0) return null
    const times = items.map((e) => new Date(e.event_time).getTime())
    const min = Math.min(...times)
    const max = Math.max(...times)
    const pad = Math.max((max - min) * 0.03, 60_000)
    return { start: min - pad, end: max + pad }
  }, [range, items])

  const lanes = useMemo(() => {
    const counts = new Map<string, number>()
    for (const e of items) {
      const key = e[laneKey] ?? '(unknown)'
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_LANES)
      .map(([key]) => key)
  }, [items, laneKey])

  const laneIndex = new Map(lanes.map((l, i) => [l, i]))
  const height = lanes.length * LANE_H + AXIS_H
  const plotW = W - LABEL_W - 10

  const x = (t: number) =>
    domain ? LABEL_W + ((t - domain.start) / (domain.end - domain.start)) * plotW : LABEL_W

  const shown = useMemo(
    () =>
      items.filter((e) => {
        const lane = e[laneKey] ?? '(unknown)'
        if (!laneIndex.has(lane)) return false
        if (!domain) return false
        const t = new Date(e.event_time).getTime()
        return t >= domain.start && t <= domain.end
      }),
    [items, laneKey, domain], // eslint-disable-line react-hooks/exhaustive-deps
  )
  const hiddenCount = items.length - shown.length

  // Correlated evidence windows overlay (host lanes only — evidence is per host)
  const overlays = useMemo(() => {
    if (laneKey !== 'host_name' || !domain || !evidence.data) return []
    return evidence.data.items
      .filter((ev) => ev.host_name && laneIndex.has(ev.host_name))
      .map((ev) => ({
        id: ev.id,
        lane: laneIndex.get(ev.host_name!)!,
        from: new Date(ev.window_start).getTime(),
        to: new Date(ev.window_end).getTime(),
        score: ev.score,
      }))
      .filter((o) => o.to >= domain.start && o.from <= domain.end)
  }, [laneKey, domain, evidence.data]) // eslint-disable-line react-hooks/exhaustive-deps

  // Playback: sweep the cursor across the domain (§4.6); static under reduced motion.
  useEffect(() => {
    if (!playing || !domain) return
    let raf = 0
    const t0 = performance.now()
    const startAt = cursor && cursor > domain.start && cursor < domain.end ? cursor : domain.start
    const step = (now: number) => {
      const t = startAt + ((now - t0) / 8000) * (domain.end - domain.start)
      if (t >= domain.end) {
        setCursor(null)
        setPlaying(false)
        return
      }
      setCursor(t)
      raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [playing, domain]) // eslint-disable-line react-hooks/exhaustive-deps

  function clientXToTime(clientX: number): number | null {
    const svg = svgRef.current
    if (!svg || !domain) return null
    const rect = svg.getBoundingClientRect()
    const frac = ((clientX - rect.left) / rect.width) * W
    return domain.start + ((frac - LABEL_W) / plotW) * (domain.end - domain.start)
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {PRESETS.map((p) => (
          <button
            key={p.label}
            type="button"
            onClick={() => {
              setRange(
                p.hours === null ? null : { start: Date.now() - p.hours * 3_600_000, end: Date.now() },
              )
              setCursor(null)
            }}
            className="rounded-full border-[0.5px] border-subtle px-3 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            {p.label}
          </button>
        ))}
        <span className="mx-1 h-4 w-px bg-subtle" />
        {(['host_name', 'user_name'] as LaneKey[]).map((k) => (
          <button
            key={k}
            type="button"
            onClick={() => setLaneKey(k)}
            className={`rounded-full px-3 py-1 text-label transition-colors duration-120 ${
              laneKey === k
                ? 'bg-accent-bg text-accent'
                : 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
            }`}
          >
            by {k === 'host_name' ? 'host' : 'user'}
          </button>
        ))}
        <span className="flex-1" />
        {!reducedMotion && domain && shown.length > 0 && (
          <button
            type="button"
            onClick={() => setPlaying((v) => !v)}
            className="flex items-center gap-1.5 rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            {playing ? <Pause size={12} strokeWidth={1.5} /> : <Play size={12} strokeWidth={1.5} />}
            {playing ? 'Pause' : 'Replay'}
          </button>
        )}
        <button
          type="button"
          onClick={() => {
            setRange(null)
            setCursor(null)
          }}
          className="flex items-center gap-1.5 rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
        >
          <ZoomOut size={12} strokeWidth={1.5} />
          Reset
        </button>
      </div>

      <div className="overflow-x-auto rounded-card border-[0.5px] border-subtle bg-elevated p-3">
        {events.isLoading && (
          <div className="flex items-center justify-center py-16">
            <ArgusMark size={40} spinning className="opacity-40" />
          </div>
        )}
        {!events.isLoading && (shown.length === 0 || !domain) && (
          <div className="flex flex-col items-center gap-3 py-14">
            <ArgusMark size={44} className="opacity-20" />
            <p className="text-label text-tertiary">
              No events in this window. Widen the range or reset.
            </p>
          </div>
        )}
        {!events.isLoading && domain && shown.length > 0 && (
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${height}`}
            className="w-full cursor-crosshair select-none"
            style={{ minWidth: 640 }}
            onMouseDown={(e) => {
              const t = clientXToTime(e.clientX)
              if (t !== null) setBrush({ from: t, to: t })
            }}
            onMouseMove={(e) => {
              if (!brush) return
              const t = clientXToTime(e.clientX)
              if (t !== null) setBrush({ ...brush, to: t })
            }}
            onMouseUp={() => {
              if (brush && domain) {
                const [a, b] = [Math.min(brush.from, brush.to), Math.max(brush.from, brush.to)]
                // require a deliberate brush (>1.5% of the domain) to zoom
                if (b - a > (domain.end - domain.start) * 0.015) {
                  setRange({ start: a, end: b })
                  setCursor(null)
                }
              }
              setBrush(null)
            }}
            onMouseLeave={() => setBrush(null)}
          >
            {/* lanes */}
            {lanes.map((lane, i) => (
              <g key={lane}>
                <rect
                  x={LABEL_W}
                  y={i * LANE_H}
                  width={plotW}
                  height={LANE_H}
                  fill={i % 2 ? 'transparent' : 'rgba(30, 20, 54, 0.5)'}
                />
                <text
                  x={LABEL_W - 8}
                  y={i * LANE_H + LANE_H / 2 + 3.5}
                  textAnchor="end"
                  className="fill-(--text-secondary)"
                  style={{ font: "10.5px 'Geist Mono Variable', monospace" }}
                >
                  {lane.length > 22 ? `…${lane.slice(-21)}` : lane}
                </text>
              </g>
            ))}

            {/* correlated evidence windows */}
            {overlays.map((o) => (
              <rect
                key={o.id}
                x={x(Math.max(o.from, domain.start))}
                y={o.lane * LANE_H + 4}
                width={Math.max(x(Math.min(o.to, domain.end)) - x(Math.max(o.from, domain.start)), 3)}
                height={LANE_H - 8}
                rx={3}
                fill="rgba(47, 230, 160, 0.08)"
                stroke="rgba(47, 230, 160, 0.35)"
                strokeWidth={0.75}
              >
                <title>{`evidence #${o.id} · score ${o.score}`}</title>
              </rect>
            ))}

            {/* event markers */}
            {shown.map((e) => {
              const t = new Date(e.event_time).getTime()
              const lane = laneIndex.get(e[laneKey] ?? '(unknown)')!
              const sev = eventSeverity(e.severity)
              const dimmed = cursor !== null && t > cursor
              return (
                <circle
                  key={e.id}
                  cx={x(t)}
                  cy={lane * LANE_H + LANE_H / 2}
                  r={selected?.id === e.id ? 6 : 4}
                  fill={SEV_FILL[sev]}
                  opacity={dimmed ? 0.12 : selected && selected.id !== e.id ? 0.55 : 0.9}
                  stroke={selected?.id === e.id ? 'var(--accent)' : 'none'}
                  strokeWidth={1.5}
                  className="cursor-pointer"
                  onMouseDown={(ev) => ev.stopPropagation()}
                  onClick={() => setSelected(e)}
                >
                  <title>{`${e.action ?? e.category} · ${formatUtcTime(e.event_time)}`}</title>
                </circle>
              )
            })}

            {/* playback cursor */}
            {cursor !== null && (
              <line
                x1={x(cursor)}
                x2={x(cursor)}
                y1={0}
                y2={height - AXIS_H}
                stroke="var(--accent)"
                strokeWidth={1}
                strokeDasharray="4 3"
              />
            )}

            {/* brush selection */}
            {brush && (
              <rect
                x={Math.min(x(brush.from), x(brush.to))}
                y={0}
                width={Math.abs(x(brush.to) - x(brush.from))}
                height={height - AXIS_H}
                fill="rgba(127, 156, 242, 0.12)"
                stroke="rgba(127, 156, 242, 0.5)"
                strokeWidth={0.75}
              />
            )}

            {/* axis */}
            {Array.from({ length: 5 }, (_, i) => {
              const t = domain.start + ((domain.end - domain.start) * i) / 4
              const long = domain.end - domain.start > 48 * 3_600_000
              const d = new Date(t)
              const label = long
                ? `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`
                : formatUtcTime(t)
              return (
                <g key={i}>
                  <line
                    x1={x(t)}
                    x2={x(t)}
                    y1={0}
                    y2={height - AXIS_H + 4}
                    stroke="var(--border-subtle)"
                    strokeWidth={0.5}
                  />
                  <text
                    x={x(t)}
                    y={height - 8}
                    textAnchor="middle"
                    className="fill-(--text-tertiary)"
                    style={{ font: "9.5px 'Geist Mono Variable', monospace" }}
                  >
                    {label}
                  </text>
                </g>
              )
            })}
            <text
              x={W - 10}
              y={height - 8}
              textAnchor="end"
              className="fill-(--text-tertiary)"
              style={{ font: "9.5px 'Geist Mono Variable', monospace" }}
            >
              UTC
            </text>
          </svg>
        )}
      </div>

      {hiddenCount > 0 && (
        <p className="text-[11px] leading-4 text-tertiary">
          {hiddenCount} events fall outside the top {MAX_LANES} lanes or the current window.
        </p>
      )}

      {selected && (
        <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-label text-primary">{selected.action ?? selected.category}</div>
              <div className="mt-1 grid gap-x-6 gap-y-0.5 font-mono text-[11px] leading-5 text-secondary sm:grid-cols-2">
                <span>time: {formatUtcDateTime(selected.event_time)}</span>
                <span>severity: {selected.severity ?? '—'}</span>
                <span>host: {selected.host_name ?? '—'}</span>
                <span>user: {selected.user_name ?? '—'}</span>
                <span>src: {selected.src_ip ?? '—'}</span>
                <span>dst: {selected.dst_ip ?? '—'}</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="shrink-0 text-label text-tertiary transition-colors duration-120 hover:text-primary"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
