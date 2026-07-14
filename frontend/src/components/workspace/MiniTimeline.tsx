import { useMemo } from 'react'
import type { EventItem } from '../../lib/api'

const BUCKETS = 24

// Sparkline of event volume across the evidence window (§4.1 right rail).
export function MiniTimeline({
  events,
  windowStart,
  windowEnd,
}: {
  events: EventItem[]
  windowStart: string
  windowEnd: string
}) {
  const buckets = useMemo(() => {
    const start = new Date(windowStart).getTime()
    // Pad a zero-length window so single-burst evidence still renders.
    const end = Math.max(new Date(windowEnd).getTime(), start + 60_000)
    const counts = new Array<number>(BUCKETS).fill(0)
    for (const e of events) {
      const t = new Date(e.event_time).getTime()
      if (t < start || t > end) continue
      const i = Math.min(BUCKETS - 1, Math.floor(((t - start) / (end - start)) * BUCKETS))
      counts[i] += 1
    }
    return counts
  }, [events, windowStart, windowEnd])

  const max = Math.max(...buckets, 1)

  if (events.length === 0) {
    return <p className="text-label text-tertiary">No events in window.</p>
  }

  return (
    <svg
      viewBox={`0 0 ${BUCKETS * 5} 28`}
      className="h-7 w-full"
      preserveAspectRatio="none"
      role="img"
      aria-label={`Event volume across the window, peak ${max} per bucket`}
    >
      {buckets.map((count, i) => {
        const h = count === 0 ? 1.5 : 3 + (count / max) * 24
        return (
          <rect
            key={i}
            x={i * 5 + 0.75}
            y={28 - h}
            width={3.5}
            height={h}
            rx={1}
            fill={count === 0 ? 'var(--border-strong)' : 'var(--accent)'}
            opacity={count === 0 ? 0.6 : 0.4 + 0.6 * (count / max)}
          />
        )
      })}
    </svg>
  )
}
