import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ShieldOff, Filter, RefreshCw, ChevronRight, Search } from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'
import { useAuthStore } from '../store/auth'

const PRIORITY_ROW = {
  critical: 'border-l-2 border-l-red-500',
  high:     'border-l-2 border-l-amber-500',
  medium:   'border-l-2 border-l-blue-500',
  low:      '',
}

function useMyAlerts(filters) {
  const params = new URLSearchParams()
  if (filters.priority) params.set('priority', filters.priority)
  if (filters.status)   params.set('status',   filters.status)
  return useQuery({
    queryKey: ['alerts', 'my', filters],
    queryFn: () => api.get(`/alerts/my?${params.toString()}`).then(r => r.data),
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

export default function MyAlerts() {
  const navigate = useNavigate()
  const username = useAuthStore(s => s.userName)
  const [filters, setFilters] = useState({ priority: '', status: '' })
  const [search, setSearch] = useState('')

  const { data, isLoading, refetch, isFetching } = useMyAlerts(filters)
  const searchLower = search.trim().toLowerCase()
  const alerts = (data?.items ?? []).filter(a => {
    if (!searchLower) return true
    return (
      a.classification?.toLowerCase().includes(searchLower) ||
      a.alert_id?.toLowerCase().includes(searchLower) ||
      a.src_ip?.toLowerCase().includes(searchLower) ||
      a.dst_ip?.toLowerCase().includes(searchLower)
    )
  })

  if (isLoading) return <PageSpinner />

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-theme-primary flex items-center gap-2">
            <AlertCircle size={16} className="text-blue-400" />
            My Alerts
            <span className="text-theme-muted font-normal text-xs ml-1">
              {data?.total ?? 0} total
            </span>
          </h1>
          <p className="text-xs text-theme-muted mt-0.5">
            Alerts assigned to <span className="text-blue-400 font-medium">{username}</span>
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="p-1.5 text-theme-muted hover:text-theme-primary transition-colors disabled:opacity-50"
          title="Refresh"
        >
          <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Filter size={13} className="text-theme-muted" />
        {/* Text search */}
        <div className="relative">
          <Search size={12} className="absolute left-2.5 top-2 text-theme-muted" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search classification, IP, ID…"
            className="bg-theme-raised border border-theme text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-48"
          />
        </div>
        <select
          id="my-alerts-priority-filter"
          value={filters.priority}
          onChange={e => setFilters(f => ({ ...f, priority: e.target.value }))}
          className="bg-theme-raised border border-theme text-xs text-theme-primary rounded px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
        >
          <option value="">All priorities</option>
          {['critical', 'high', 'medium', 'low'].map(p => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <select
          id="my-alerts-status-filter"
          value={filters.status}
          onChange={e => setFilters(f => ({ ...f, status: e.target.value }))}
          className="bg-theme-raised border border-theme text-xs text-theme-primary rounded px-2.5 py-1.5 focus:outline-none focus:border-blue-500"
        >
          <option value="">All statuses</option>
          {['pending', 'approved', 'rejected', 'executed', 'closed'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        {(filters.priority || filters.status) && (
          <button
            onClick={() => setFilters({ priority: '', status: '' })}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Alerts Table */}
      <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <ShieldOff size={32} className="text-theme-muted opacity-40" />
            <p className="text-sm text-theme-muted">
              {search.trim() || filters.priority || filters.status
                ? 'No alerts match your filters'
                : 'No alerts are currently assigned to you'}
            </p>
            {!filters.priority && !filters.status && (
              <p className="text-xs text-theme-muted opacity-60">
                Alerts you're assigned to will appear here
              </p>
            )}
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-theme-raised text-theme-muted text-left">
                {['Time', 'Classification', 'Priority', 'Status', 'Src IP', 'Dst Port', ''].map(h => (
                  <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr
                  key={alert.alert_id}
                  onClick={() => navigate(`/alerts/${alert.alert_id}`)}
                  className={cn(
                    'border-t border-theme hover:bg-theme-raised cursor-pointer transition-colors',
                    PRIORITY_ROW[alert.priority]
                  )}
                >
                  <td className="px-4 py-3 text-theme-muted whitespace-nowrap">
                    {timeAgo(alert.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    <p className="text-theme-primary font-mono font-medium truncate max-w-[200px]">
                      {alert.classification}
                    </p>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="priority" value={alert.priority}>
                      {alert.priority}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="status" value={alert.approval_status}>
                      {alert.approval_status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-theme-secondary font-mono">
                    {alert.src_ip || '—'}
                  </td>
                  <td className="px-4 py-3 text-theme-secondary font-mono">
                    {alert.dst_port || '—'}
                  </td>
                  <td className="px-4 py-3">
                    <ChevronRight size={13} className="text-theme-muted" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination hint */}
      {data?.total > data?.limit && (
        <p className="text-xs text-theme-muted text-center">
          Showing {alerts.length} of {data.total} alerts
        </p>
      )}
    </div>
  )
}
