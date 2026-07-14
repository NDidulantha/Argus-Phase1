import { Check } from 'lucide-react'

export type StepState = 'done' | 'active' | 'pending'

export interface PipelineStep {
  label: string
  detail: string
  state: StepState
}

function StepMarker({ state }: { state: StepState }) {
  if (state === 'done') {
    return (
      <span className="flex h-4.5 w-4.5 items-center justify-center rounded-full bg-accent-bg">
        <Check size={11} strokeWidth={2} className="text-accent" />
      </span>
    )
  }
  if (state === 'active') {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
        <circle
          cx="9"
          cy="9"
          r="7"
          stroke="var(--accent)"
          strokeWidth="1.5"
          strokeDasharray="5 3.5"
          className="animate-scan-ring origin-center"
        />
      </svg>
    )
  }
  return <span className="h-4.5 w-4.5 rounded-full border-[0.5px] border-strong" />
}

export function PipelineSteps({ steps }: { steps: PipelineStep[] }) {
  return (
    <ol className="space-y-3">
      {steps.map((step) => (
        <li key={step.label} className="flex items-start gap-2.5">
          <StepMarker state={step.state} />
          <div className="min-w-0">
            <div
              className={`text-label ${step.state === 'pending' ? 'text-tertiary' : 'text-primary'}`}
            >
              {step.label}
            </div>
            <div className="truncate text-[11px] leading-4 text-tertiary">{step.detail}</div>
          </div>
        </li>
      ))}
    </ol>
  )
}
