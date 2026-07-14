import { lazy } from 'react'

// The force-graph stack is heavy; load it only when a graph is on screen.
export const GraphExplorer = lazy(() =>
  import('./GraphExplorer').then((m) => ({ default: m.GraphExplorer })),
)
