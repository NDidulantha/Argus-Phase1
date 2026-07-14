import { ChevronRight } from 'lucide-react'
import type { TechniqueBrief } from '../../lib/api'
import { tacticRank as rankOne } from '../../lib/mitre'

function tacticRank(tactics: string[]): number {
  const ranks = tactics.map(rankOne)
  return ranks.length ? Math.min(...ranks) : Number.MAX_SAFE_INTEGER
}

export function AttackChain({ techniques }: { techniques: TechniqueBrief[] }) {
  const ordered = [...techniques].sort((a, b) => tacticRank(a.tactics) - tacticRank(b.tactics))

  if (ordered.length === 0) {
    return <p className="text-label text-tertiary">No mapped techniques.</p>
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {ordered.map((t, i) => (
        <span key={t.technique_id} className="flex items-center gap-1.5">
          {i > 0 && <ChevronRight size={12} strokeWidth={1.5} className="text-tertiary" />}
          <span
            className="rounded-control border-[0.5px] border-subtle bg-base px-2 py-1"
            title={t.tactics.join(', ')}
          >
            <span className="font-mono text-data text-primary">{t.technique_id}</span>
            {t.name && (
              <span className="ml-1.5 text-[11px] leading-4 text-secondary">{t.name}</span>
            )}
          </span>
        </span>
      ))}
    </div>
  )
}
