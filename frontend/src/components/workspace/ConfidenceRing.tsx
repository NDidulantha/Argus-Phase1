// Logo-derived ring (§2.3): dashed silver track echoing the scanning ring,
// emerald arc filling clockwise with the evidence score.
export function ConfidenceRing({ score, label }: { score: number; label: string }) {
  const r = 32
  const c = 2 * Math.PI * r
  const filled = (Math.min(100, Math.max(0, score)) / 100) * c

  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative h-20 w-20">
        <svg viewBox="0 0 80 80" className="h-full w-full -rotate-90">
          <circle
            cx="40"
            cy="40"
            r={r}
            fill="none"
            stroke="var(--border-strong)"
            strokeWidth="3"
            strokeDasharray="4 3"
          />
          <circle
            cx="40"
            cy="40"
            r={r}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={`${filled} ${c}`}
            className="transition-[stroke-dasharray] duration-500"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center font-mono text-[20px] font-medium text-primary">
          {score}
        </div>
      </div>
      <span className="text-label text-secondary">{label}</span>
    </div>
  )
}
