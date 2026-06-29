import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ChevronLeft, Search } from 'lucide-react'
import { useTrace } from '../hooks/useTrace'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'

const AGENT_COLOUR = {
  orchestrator:     'bg-blue-500',
  cve_lookup:       'bg-violet-500',
  asset_discovery:  'bg-violet-500',
  planning:         'bg-emerald-500',
  executor:         'bg-amber-500',
}

function dot(agentName) {
  return AGENT_COLOUR[agentName] ?? 'bg-slate-500'
}

export default function TraceViewer() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { events, isLoading } = useTrace(id)
  const [expanded, setExpanded] = useState(new Set())
  const [filter,   setFilter]   = useState('')
  const [search,   setSearch]   = useState('')

  if (isLoading) return <PageSpinner />

  const agents  = [...new Set(events.map(e => e.agent))]
  const searchLower = search.trim().toLowerCase()
  const visible = events.filter(e => {
    if (filter && e.agent !== filter) return false
    if (!searchLower) return true
    return (
      e.action?.toLowerCase().includes(searchLower) ||
      e.rationale?.toLowerCase().includes(searchLower) ||
      e.agent?.toLowerCase().includes(searchLower) ||
      e.event_type?.toLowerCase().includes(searchLower)
    )
  })

  return (
    <div>
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1 text-xs text-theme-secondary hover:text-blue-400 transition-colors mb-4"
      >
        <ChevronLeft size={14}/> Back
      </button>
      <div className="flex items-center justify-between mb-5">
        <h1 className="text-base font-semibold text-theme-primary">
          Reasoning Trace
          <span className="ml-2 text-xs text-theme-muted font-normal">{visible.length} of {events.length} events</span>
        </h1>
        <div className="flex gap-2 items-center">
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-2 text-theme-muted" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search traces…"
              className="bg-theme-raised border border-theme text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-40"
            />
          </div>
          <div className="flex gap-1.5">
          <button onClick={() => setFilter('')}
            className={cn('px-2.5 py-1 text-xs rounded', !filter ? 'bg-blue-600 text-white' : 'bg-theme-raised text-theme-secondary')}>
            All
          </button>
          {agents.map(a => (
            <button key={a} onClick={() => setFilter(a)}
              className={cn('px-2.5 py-1 text-xs rounded', filter===a ? 'bg-blue-600 text-white' : 'bg-theme-raised text-theme-secondary')}>
              {a}
            </button>
          ))}
        </div>
      </div>
      </div>

      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-3 top-0 bottom-0 w-px bg-theme-raised" />

        <div className="space-y-1">
          {visible.map((e) => {
            const open = expanded.has(e.event_id)
            return (
              <div key={e.event_id} className="pl-9 relative">
                {/* Dot */}
                <div className={cn('absolute left-1.5 top-3 w-3 h-3 rounded-full border-2 border-theme-base', dot(e.agent))} />

                <div
                  className="bg-theme-surface border border-theme rounded-lg p-3 cursor-pointer hover:bg-theme-raised transition-colors"
                  onClick={() => setExpanded(prev => {
                    const next = new Set(prev)
                    next.has(e.event_id) ? next.delete(e.event_id) : next.add(e.event_id)
                    return next
                  })}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold text-theme-primary">{e.agent}</span>
                      <span className="text-xs text-theme-muted">{e.action}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-theme-muted">
                      {e.duration_ms && <span>{e.duration_ms}ms</span>}
                      <span>{timeAgo(e.timestamp)}</span>
                    </div>
                  </div>

                  {open && (
                    <div className="mt-3 space-y-2 text-xs border-t border-theme pt-3">
                      {e.rationale && (
                        <div>
                          <p className="text-theme-muted mb-0.5">Rationale</p>
                          <p className="text-theme-secondary">{e.rationale}</p>
                        </div>
                      )}
                      {e.confidence != null && (
                        <div className="flex items-center gap-2">
                          <span className="text-theme-muted">Confidence</span>
                          <div className="flex-1 bg-theme-raised rounded-full h-1">
                            <div className="bg-blue-500 h-1 rounded-full" style={{width:`${e.confidence*100}%`}} />
                          </div>
                          <span className="text-theme-secondary">{(e.confidence*100).toFixed(0)}%</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}