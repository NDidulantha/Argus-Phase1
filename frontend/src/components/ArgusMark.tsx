interface ArgusMarkProps {
  size?: number
  spinning?: boolean
  className?: string
  /** Extra classes for the scanning ring, e.g. a one-shot rotation on login */
  ringClassName?: string
}

// The eye mark: segmented scanning ring + eye with emerald iris.
// Echoes the frozen logo geometry (ui-design.md §1) — never redesign it.
export function ArgusMark({ size = 32, spinning = false, className, ringClassName }: ArgusMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      aria-hidden="true"
      className={className}
    >
      <circle
        cx="20"
        cy="20"
        r="17.5"
        stroke="var(--silver)"
        strokeWidth="1.5"
        strokeDasharray="6 4"
        strokeLinecap="round"
        className={spinning ? 'animate-scan-ring origin-center' : ringClassName}
      />
      <path
        d="M6.5 20 Q20 9.5 33.5 20 Q20 30.5 6.5 20 Z"
        stroke="var(--silver)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <circle cx="20" cy="20" r="4.5" fill="var(--accent)" />
      <circle cx="20" cy="20" r="1.8" fill="var(--bg-base)" />
    </svg>
  )
}
