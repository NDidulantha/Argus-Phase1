import { useState, type FormEvent, type ReactNode } from 'react'
import { SendHorizonal } from 'lucide-react'
import { formatUtcTime } from '../../lib/format'

export type AgentTag =
  | 'Scope'
  | 'Collector'
  | 'Correlation'
  | 'MITRE'
  | 'Reasoning'
  | 'Grounding'
  | 'Planner'

export interface StreamEntry {
  id: string
  time: number
  agent: AgentTag
  body: ReactNode
}

// Colored agent tags (§4.1): emerald is reserved for the AI itself.
const tagStyles: Record<AgentTag, string> = {
  Scope: 'text-sev-info bg-sev-info/15',
  Collector: 'text-silver bg-silver/15',
  Correlation: 'text-sev-medium bg-sev-medium/15',
  MITRE: 'text-sev-high bg-sev-high/15',
  Reasoning: 'text-accent bg-accent-bg',
  Grounding: 'text-accent bg-accent-bg',
  Planner: 'text-secondary bg-hover',
}

const entryTime = formatUtcTime

interface ReasoningStreamProps {
  entries: StreamEntry[]
  thinking: string | null
  onSteer: (message: string) => void
}

export function ReasoningStream({ entries, thinking, onSteer }: ReasoningStreamProps) {
  const [draft, setDraft] = useState('')

  function submit(e: FormEvent) {
    e.preventDefault()
    const message = draft.trim()
    if (!message) return
    onSteer(message)
    setDraft('')
  }

  return (
    <div className="flex h-full min-h-0 flex-col rounded-card border-[0.5px] border-subtle bg-elevated">
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
        {/* Entries arrive pre-ordered causally (pipeline stage, then time). */}
        {entries.map((entry) => (
            <div key={entry.id}>
              <div className="mb-1.5 flex items-center gap-2">
                <span
                  className={`rounded-full px-2 py-0.5 text-[11px] leading-4 ${tagStyles[entry.agent]}`}
                >
                  {entry.agent}
                </span>
                <span className="font-mono text-[11px] leading-4 text-tertiary">
                  {entryTime(entry.time)}
                </span>
              </div>
              <div className="pl-1">{entry.body}</div>
            </div>
          ))}

        {thinking && (
          <div className="flex items-center gap-2.5">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <circle
                cx="8"
                cy="8"
                r="6.5"
                stroke="var(--accent)"
                strokeWidth="1.5"
                strokeDasharray="5 3.5"
                className="animate-scan-ring origin-center"
              />
            </svg>
            <span className="animate-pulse text-label text-secondary">{thinking}</span>
          </div>
        )}
      </div>

      <form onSubmit={submit} className="border-t-[0.5px] border-subtle p-3">
        <label className="flex items-center gap-2.5 rounded-control border-[0.5px] border-subtle bg-base px-3 py-2 transition-colors duration-120 focus-within:border-strong">
          <input
            type="text"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Ask ARGUS — direct the investigation…"
            className="w-full bg-transparent text-label text-primary outline-none placeholder:text-tertiary"
          />
          <button
            type="submit"
            aria-label="Send"
            className="text-tertiary transition-colors duration-120 hover:text-accent"
          >
            <SendHorizonal size={15} strokeWidth={1.5} />
          </button>
        </label>
      </form>
    </div>
  )
}
