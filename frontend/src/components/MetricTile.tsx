interface MetricTileProps {
  label: string
  value: string | null
  valueClassName?: string
  hint?: string
}

export function MetricTile({ label, value, valueClassName, hint }: MetricTileProps) {
  return (
    <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
      <div className="text-label text-secondary">{label}</div>
      <div className={`mt-1 font-mono text-[22px] font-medium ${valueClassName ?? 'text-primary'}`}>
        {value ?? <span className="inline-block h-6 w-12 animate-pulse rounded bg-hover" />}
      </div>
      {hint && <div className="mt-0.5 text-label text-tertiary">{hint}</div>}
    </div>
  )
}
