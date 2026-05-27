import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldAlert, ArrowUpCircle, CheckCircle, Clock, User,
  RefreshCw, ChevronRight, Info
} from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'
import { useAuthStore } from '../store/auth'
import { useToastStore } from '../components/ui/Toast'
import { useWebSocket } from '../hooks/useWebSocket'

// ── Data hooks ────────────────────────────────────────────────────────────────

function useEscalations() {
  return useQuery({
    queryKey: ['escalations'],
    queryFn: () => api.get('/plans/escalations').then(r => r.data),
    staleTime: 10_000,
    refetchInterval: 20_000,
  })
}

function usePickupEscalation() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  const navigate = useNavigate()
  return useMutation({
    mutationFn: (escalationId) =>
      api.post(`/plans/escalations/${escalationId}/pickup`).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['escalations'] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alert', data.alert_id] })
      toast({
        type: 'success',
        title: 'Escalation picked up',
        message: `Alert reassigned to you. Redirecting to plan review…`,
      })
      // Navigate directly to the plan review for immediate action
      setTimeout(() => navigate(data.redirect_to), 800)
    },
    onError: (err) => {
      toast({
        type: 'error',
        title: 'Pick-up failed',
        message: err?.response?.data?.detail || 'Could not pick up this escalation',
      })
    },
  })
}

// ── Priority badge colours ────────────────────────────────────────────────────
const PRIORITY_RING = {
  critical: 'border-l-2 border-l-red-500',
  high:     'border-l-2 border-l-amber-500',
  medium:   'border-l-2 border-l-blue-500',
  low:      '',
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function EscalatedAlerts() {
  const navigate   = useNavigate()
  const role       = useAuthStore(s => s.role)
  const username   = useAuthStore(s => s.userName)
  const toast      = useToastStore(s => s.push)
  const qc         = useQueryClient()

  const { data, isLoading, refetch, isFetching } = useEscalations()
  const pickup = usePickupEscalation()

  // Live updates
  const onMessage = useCallback((msg) => {
    if (['escalation_request', 'escalation_picked_up'].includes(msg.type)) {
      qc.invalidateQueries({ queryKey: ['escalations'] })
      if (msg.type === 'escalation_request') {
        toast({
          type: 'warning',
          title: '⬆ New Escalation',
          message: `${msg.requested_by} escalated "${msg.classification}" (${msg.priority})`,
        })
      }
      if (msg.type === 'escalation_picked_up' && msg.original_analyst === username) {
        toast({
          type: 'info',
          title: 'Escalation picked up',
          message: `${msg.picked_up_by} has taken over your escalated alert`,
        })
        qc.invalidateQueries({ queryKey: ['alerts'] })
      }
    }
  }, [qc, toast, username])

  useWebSocket('/ws/alerts', onMessage)

  if (isLoading) return <PageSpinner />

  const escalations = data?.items ?? []
  const isElevated  = role === 'admin' || role === 'senior_analyst'

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-base font-semibold text-theme-primary flex items-center gap-2">
            <ShieldAlert size={15} className="text-red-400" />
            Escalated Alerts
            {escalations.length > 0 && (
              <span className="bg-red-500 text-white text-[10px] font-bold rounded-full px-1.5 py-0.5 leading-none">
                {escalations.length}
              </span>
            )}
          </h1>
          <p className="text-xs text-theme-muted mt-0.5">
            {isElevated
              ? 'Plans awaiting your review — pick one up to take ownership and approve'
              : 'Escalations you have submitted'}
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="p-1.5 text-theme-muted hover:text-theme-primary transition-colors disabled:opacity-50"
          title="Refresh"
        >
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Info banner for elevated roles */}
      {isElevated && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-950/30 border border-blue-700/40 text-xs">
          <Info size={13} className="text-blue-400 shrink-0 mt-0.5" />
          <p className="text-blue-300 leading-relaxed">
            Click <strong>Pick Up</strong> to take ownership of an escalated alert.
            The original analyst will be unassigned and you will be directed to the plan
            review page to approve or reject it.
          </p>
        </div>
      )}

      {/* Empty state */}
      {escalations.length === 0 ? (
        <div className="bg-theme-surface border border-theme rounded-lg">
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <div className="w-12 h-12 rounded-full bg-theme-raised flex items-center justify-center">
              <ShieldAlert size={22} className="text-theme-muted opacity-40" />
            </div>
            <p className="text-sm text-theme-muted">No pending escalations</p>
            <p className="text-xs text-theme-muted opacity-60">
              {isElevated
                ? 'All caught up — no analysts are waiting for approval'
                : 'You have no escalated plans at this time'}
            </p>
          </div>
        </div>
      ) : (
        <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-theme-raised text-theme-secondary text-left">
                <th className="px-4 py-3 font-medium">Alert</th>
                <th className="px-4 py-3 font-medium">Priority</th>
                <th className="px-4 py-3 font-medium">Escalated By</th>
                <th className="px-4 py-3 font-medium">Reason</th>
                <th className="px-4 py-3 font-medium">Actions in Plan</th>
                <th className="px-4 py-3 font-medium">Waiting</th>
                {isElevated && <th className="px-4 py-3 font-medium">Action</th>}
              </tr>
            </thead>
            <tbody>
              {escalations.map(esc => (
                <tr
                  key={esc.id}
                  className={cn(
                    'border-t border-theme transition-colors hover:bg-theme-raised',
                    PRIORITY_RING[esc.priority]
                  )}
                >
                  {/* Classification — clickable */}
                  <td
                    className="px-4 py-3 cursor-pointer"
                    onClick={() => navigate(`/alerts/${esc.alert_id}`)}
                  >
                    <p className="font-mono font-medium text-theme-primary hover:text-blue-400 transition-colors flex items-center gap-1">
                      {esc.classification}
                      <ChevronRight size={11} className="text-theme-muted" />
                    </p>
                    <p className="text-theme-muted mt-0.5 text-[10px] font-mono">
                      {esc.alert_id}
                    </p>
                  </td>

                  {/* Priority */}
                  <td className="px-4 py-3">
                    <Badge variant="priority" value={esc.priority}>{esc.priority}</Badge>
                  </td>

                  {/* Escalated by */}
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1.5 text-theme-secondary">
                      <User size={11} className="text-theme-muted" />
                      {esc.escalated_by}
                      {esc.escalated_by === username && (
                        <span className="text-theme-muted">(you)</span>
                      )}
                    </span>
                  </td>

                  {/* Reason */}
                  <td className="px-4 py-3 max-w-[200px]">
                    <p
                      className="text-theme-secondary truncate"
                      title={esc.reason}
                    >
                      {esc.reason}
                    </p>
                  </td>

                  {/* Destructive actions list */}
                  <td className="px-4 py-3">
                    <div className="space-y-0.5">
                      {(esc.actions ?? []).map((a, i) => (
                        <div key={i} className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                          <span className="font-mono text-red-400 text-[11px]">
                            {a.action_type}
                          </span>
                          <span className="text-theme-muted text-[11px]">
                            → {a.target}
                          </span>
                        </div>
                      ))}
                    </div>
                  </td>

                  {/* Waiting since */}
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1 text-theme-muted">
                      <Clock size={11} />
                      {timeAgo(esc.created_at)}
                    </span>
                  </td>

                  {/* Pick up button (elevated only) */}
                  {isElevated && (
                    <td className="px-4 py-3">
                      <button
                        id={`pickup-escalation-${esc.id}`}
                        onClick={() => pickup.mutate(esc.id)}
                        disabled={pickup.isPending}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold
                                   bg-emerald-700 hover:bg-emerald-600 text-white rounded
                                   transition-colors disabled:opacity-50 whitespace-nowrap"
                      >
                        <CheckCircle size={12} />
                        Pick Up
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
