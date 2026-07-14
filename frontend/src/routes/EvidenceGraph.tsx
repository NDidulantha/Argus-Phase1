import { Suspense } from 'react'
import { ArgusMark } from '../components/ArgusMark'
import { GraphExplorer } from '../components/graph/lazy'

export function EvidenceGraph() {
  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <h1 className="text-page-title">Evidence graph</h1>
      <div className="min-h-0 flex-1">
        <Suspense
          fallback={
            <div className="flex h-full items-center justify-center">
              <ArgusMark size={44} spinning className="opacity-40" />
            </div>
          }
        >
          <GraphExplorer />
        </Suspense>
      </div>
    </div>
  )
}
