import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D, { type ForceGraphMethods, type NodeObject } from 'react-force-graph-2d'
import { Search } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { useAuthedQuery } from '../../hooks/useAuthedQuery'
import * as api from '../../lib/api'
import type { GraphEdge, GraphEntity } from '../../lib/api'
import { formatUtcDateTime } from '../../lib/format'
import { ArgusMark } from '../ArgusMark'

// Node color by entity type — brand family, never severity (§4.5).
const TYPE_COLORS: Record<string, string> = {
  host: '#7F9CF2',
  user: '#A79FC4',
  process: '#9C7BF0',
  ip: '#5EEAB4',
}
const FALLBACK_COLOR = '#B8B5C9'

interface GNode extends NodeObject {
  id: number
  key: string
  type: string
  firstSeen: string
  lastSeen: string
}

interface GLink {
  source: number | GNode
  target: number | GNode
  relation: string
  count: number
}

function nodeId(end: number | GNode): number {
  return typeof end === 'object' ? end.id : end
}

function toNode(e: GraphEntity): GNode {
  return {
    id: e.id,
    key: e.entity_key,
    type: e.entity_type,
    firstSeen: e.first_seen,
    lastSeen: e.last_seen,
  }
}

function toLink(e: GraphEdge): GLink {
  return {
    source: e.src_entity_id,
    target: e.dst_entity_id,
    relation: e.relation,
    count: e.observation_count,
  }
}

export function GraphExplorer({ initialSearch = '' }: { initialSearch?: string }) {
  const { token } = useAuth()
  const [search, setSearch] = useState(initialSearch)
  const [submittedSearch, setSubmittedSearch] = useState(initialSearch)
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [nodes, setNodes] = useState<GNode[]>([])
  const [links, setLinks] = useState<GLink[]>([])
  const [hoverId, setHoverId] = useState<number | null>(null)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const expandedIds = useRef<Set<number>>(new Set())
  const lastClick = useRef<{ id: number; at: number }>({ id: 0, at: 0 })

  const containerRef = useRef<HTMLDivElement>(null)
  const graphRef = useRef<ForceGraphMethods<GNode, GLink>>(undefined)
  const [size, setSize] = useState({ w: 600, h: 480 })

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver(() =>
      setSize({ w: el.clientWidth, h: Math.max(el.clientHeight, 320) }),
    )
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const overview = useAuthedQuery(['graph', 'overview', submittedSearch], (t) =>
    api.getGraphOverview(t, { search: submittedSearch || undefined, limit: 200 }),
  )

  useEffect(() => {
    if (!overview.data) return
    expandedIds.current = new Set()
    setNodes(overview.data.entities.map(toNode))
    setLinks(overview.data.edges.map(toLink))
    setSelectedId(null)
  }, [overview.data])

  const adjacency = useMemo(() => {
    const map = new Map<number, Set<number>>()
    for (const l of links) {
      const s = nodeId(l.source)
      const t = nodeId(l.target)
      if (!map.has(s)) map.set(s, new Set())
      if (!map.has(t)) map.set(t, new Set())
      map.get(s)!.add(t)
      map.get(t)!.add(s)
    }
    return map
  }, [links])

  const visibleTypes = useMemo(() => [...new Set(nodes.map((n) => n.type))].sort(), [nodes])
  const shownNodes = useMemo(
    () => nodes.filter((n) => !hiddenTypes.has(n.type)),
    [nodes, hiddenTypes],
  )
  const shownIds = useMemo(() => new Set(shownNodes.map((n) => n.id)), [shownNodes])
  const shownLinks = useMemo(
    () => links.filter((l) => shownIds.has(nodeId(l.source)) && shownIds.has(nodeId(l.target))),
    [links, shownIds],
  )

  const focusId = hoverId ?? selectedId
  const focusSet = useMemo(() => {
    if (focusId === null) return null
    return new Set([focusId, ...(adjacency.get(focusId) ?? [])])
  }, [focusId, adjacency])

  const expandNode = useCallback(
    async (id: number) => {
      if (expandedIds.current.has(id) || !token) return
      expandedIds.current.add(id)
      const nb = await api.getNeighborhood(token, id)
      setNodes((prev) => {
        const known = new Set(prev.map((n) => n.id))
        return [...prev, ...nb.entities.filter((e) => !known.has(e.id)).map(toNode)]
      })
      setLinks((prev) => {
        const known = new Set(prev.map((l) => `${nodeId(l.source)}-${nodeId(l.target)}-${l.relation}`))
        return [
          ...prev,
          ...nb.edges
            .filter((e) => !known.has(`${e.src_entity_id}-${e.dst_entity_id}-${e.relation}`))
            .map(toLink),
        ]
      })
    },
    [token],
  )

  const onNodeClick = useCallback(
    (node: GNode) => {
      const now = Date.now()
      if (lastClick.current.id === node.id && now - lastClick.current.at < 350) {
        void expandNode(node.id)
      }
      lastClick.current = { id: node.id, at: now }
      setSelectedId(node.id)
    },
    [expandNode],
  )

  const paintNode = useCallback(
    (node: GNode, ctx: CanvasRenderingContext2D, scale: number) => {
      const dimmed = focusSet !== null && !focusSet.has(node.id)
      const color = TYPE_COLORS[node.type] ?? FALLBACK_COLOR
      const r = node.id === selectedId ? 6 : 4.5

      ctx.globalAlpha = dimmed ? 0.15 : 1
      if (node.id === selectedId) {
        // eye-highlight: soft elliptical glow, not a hard box (§2.3)
        ctx.shadowColor = 'rgba(47, 230, 160, 0.9)'
        ctx.shadowBlur = 14
      }
      ctx.beginPath()
      ctx.arc(node.x!, node.y!, r, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
      ctx.shadowBlur = 0

      if (node.id === selectedId || node.id === hoverId || scale > 2.4) {
        ctx.font = `${Math.max(10 / scale, 2.4)}px 'Geist Mono Variable', monospace`
        ctx.textAlign = 'center'
        ctx.fillStyle = dimmed ? 'rgba(167,159,196,0.3)' : '#EDEBF5'
        ctx.fillText(node.key, node.x!, node.y! + r + Math.max(11 / scale, 3))
      }
      ctx.globalAlpha = 1
    },
    [focusSet, selectedId, hoverId],
  )

  const selected = selectedId !== null ? nodes.find((n) => n.id === selectedId) : undefined
  const selectedEdges = useMemo(() => {
    if (selectedId === null) return []
    return shownLinks
      .filter((l) => nodeId(l.source) === selectedId || nodeId(l.target) === selectedId)
      .map((l) => {
        const outbound = nodeId(l.source) === selectedId
        const peerId = outbound ? nodeId(l.target) : nodeId(l.source)
        const peer = nodes.find((n) => n.id === peerId)
        return { relation: l.relation, outbound, peer, count: l.count }
      })
  }, [selectedId, shownLinks, nodes])

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* Left drawer: filters (§4.5) */}
      <aside className="w-52 shrink-0 space-y-4 overflow-y-auto rounded-card border-[0.5px] border-subtle bg-elevated p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            setSubmittedSearch(search.trim())
          }}
        >
          <label className="flex items-center gap-2 rounded-control border-[0.5px] border-subtle bg-base px-2.5 py-1.5 transition-colors duration-120 focus-within:border-strong">
            <Search size={13} strokeWidth={1.5} className="text-tertiary" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter entities…"
              className="w-full bg-transparent text-label text-primary outline-none placeholder:text-tertiary"
            />
          </label>
        </form>
        <div>
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
            Entity types
          </div>
          <div className="space-y-1">
            {visibleTypes.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() =>
                  setHiddenTypes((prev) => {
                    const next = new Set(prev)
                    if (next.has(t)) next.delete(t)
                    else next.add(t)
                    return next
                  })
                }
                className={`flex w-full items-center gap-2 rounded-control px-2 py-1 text-label transition-colors duration-120 hover:bg-hover ${
                  hiddenTypes.has(t) ? 'text-tertiary line-through' : 'text-primary'
                }`}
              >
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ background: TYPE_COLORS[t] ?? FALLBACK_COLOR }}
                />
                {t}
              </button>
            ))}
          </div>
        </div>
        <p className="text-[11px] leading-4 text-tertiary">
          Click selects · double-click expands one hop
          {overview.data && nodes.length < overview.data.total_entities && (
            <>
              {' '}
              · showing {nodes.length} of {overview.data.total_entities} entities
            </>
          )}
        </p>
      </aside>

      {/* Canvas */}
      <div
        ref={containerRef}
        className="relative min-h-80 min-w-0 flex-1 overflow-hidden rounded-card border-[0.5px] border-subtle bg-surface"
      >
        {overview.isLoading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <ArgusMark size={44} spinning className="opacity-40" />
          </div>
        )}
        {!overview.isLoading && shownNodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3">
            <ArgusMark size={44} className="opacity-20" />
            <p className="text-label text-tertiary">
              No entities yet. They appear as telemetry is ingested.
            </p>
          </div>
        )}
        <ForceGraph2D
          ref={graphRef}
          width={size.w}
          height={size.h}
          graphData={{ nodes: shownNodes, links: shownLinks }}
          backgroundColor="rgba(0,0,0,0)"
          nodeCanvasObject={paintNode}
          nodePointerAreaPaint={(node, color, ctx) => {
            ctx.beginPath()
            ctx.arc(node.x!, node.y!, 8, 0, 2 * Math.PI)
            ctx.fillStyle = color
            ctx.fill()
          }}
          linkColor={(l: GLink) => {
            const active =
              focusSet !== null &&
              (focusSet.has(nodeId(l.source)) || focusSet.has(nodeId(l.target))) &&
              (focusId === nodeId(l.source) || focusId === nodeId(l.target))
            if (focusSet === null) return 'rgba(61, 42, 94, 0.9)'
            return active ? 'rgba(47, 230, 160, 0.55)' : 'rgba(61, 42, 94, 0.25)'
          }}
          linkWidth={(l: GLink) => Math.min(1 + Math.log1p(l.count) * 0.6, 3)}
          linkDirectionalArrowLength={3}
          linkDirectionalArrowRelPos={0.9}
          onNodeClick={onNodeClick}
          onNodeHover={(n) => setHoverId(n ? (n as GNode).id : null)}
          onBackgroundClick={() => setSelectedId(null)}
          d3VelocityDecay={0.55}
          cooldownTime={4000}
        />
      </div>

      {/* Right drawer: selected node detail (§4.5) */}
      {selected && (
        <aside className="w-64 shrink-0 space-y-4 overflow-y-auto rounded-card border-[0.5px] border-subtle bg-elevated p-4">
          <div>
            <div className="flex items-center gap-2">
              <span
                className="h-2.5 w-2.5 rounded-full"
                style={{ background: TYPE_COLORS[selected.type] ?? FALLBACK_COLOR }}
              />
              <span className="text-label text-tertiary">{selected.type}</span>
            </div>
            <div className="mt-1 break-all font-mono text-data text-primary">{selected.key}</div>
          </div>
          <dl className="space-y-1.5 text-[11px] leading-4">
            <div className="flex justify-between gap-2">
              <dt className="text-tertiary">First seen</dt>
              <dd className="font-mono text-secondary">{formatUtcDateTime(selected.firstSeen)}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-tertiary">Last seen</dt>
              <dd className="font-mono text-secondary">{formatUtcDateTime(selected.lastSeen)}</dd>
            </div>
          </dl>
          <div>
            <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
              Relationships
            </div>
            <ul className="space-y-1">
              {selectedEdges.length === 0 && (
                <li className="text-label text-tertiary">No edges in view.</li>
              )}
              {selectedEdges.map((e, i) => (
                <li key={i} className="text-[11px] leading-4 text-secondary">
                  {e.outbound ? '→' : '←'} <span className="text-tertiary">{e.relation}</span>{' '}
                  <button
                    type="button"
                    onClick={() => e.peer && setSelectedId(e.peer.id)}
                    className="break-all font-mono text-primary hover:text-accent"
                  >
                    {e.peer?.key ?? '?'}
                  </button>
                </li>
              ))}
            </ul>
          </div>
          <button
            type="button"
            onClick={() => void expandNode(selected.id)}
            className="w-full rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            Expand one hop
          </button>
        </aside>
      )}
    </div>
  )
}
