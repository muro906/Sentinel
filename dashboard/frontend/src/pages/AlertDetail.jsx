import { useState, useEffect, useRef } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ChevronLeft, ChevronRight, FileText, Activity, Shield,
  UserCheck, ArrowRightLeft, CheckCircle, XCircle,
  Lock, User, ChevronDown, ChevronUp, Loader2
} from 'lucide-react'
import { useAlert } from '../hooks/useAlerts'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { PageSpinner, Spinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'
import { useAuthStore } from '../store/auth'
import { useToastStore } from '../components/ui/Toast'

const PRIORITY_LEVEL   = { low: 1, medium: 2, high: 3, critical: 4 }
const ANALYST_CAP      = 2
const HISTORY_STATUSES = new Set(['approved', 'rejected', 'executed', 'closed'])

function usePlans(alertId) {
  return useQuery({
    queryKey: ['plans', alertId],
    queryFn: () => api.get(`/plans/${alertId}/plans`).then(r => r.data),
    enabled: !!alertId,
    // Poll every 8s until plans arrive, then stop
    refetchInterval: (query) =>
      (query.state.data?.plans?.length ?? 0) > 0 ? false : 8_000,
  })
}

// Traces poll while investigation is running (triaged) or plan is executing (approved).
// Stops the moment execution completes or is closed — no perpetual re-polling.
const TRACE_ACTIVE_STATUSES = new Set(['triaged', 'approved'])

function useTraces(alertId, alertStatus) {
  return useQuery({
    queryKey: ['traces', alertId],
    queryFn: () => api.get(`/traces/${alertId}/trace`).then(r => r.data),
    enabled: !!alertId,
    refetchInterval: TRACE_ACTIVE_STATUSES.has(alertStatus) ? 5000 : false,
  })
}

function useApprovalRecord(alertId, enabled) {
  return useQuery({
    queryKey: ['approval', alertId],
    queryFn: () => api.get(`/alerts/${alertId}/approval`).then(r => r.data),
    enabled: !!alertId && enabled,
    retry: false,
  })
}

function useSelfAssign(alertId) {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (id) => api.post(`/alerts/${alertId}/assign`, { analyst_id: id }).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert', alertId] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast({ type: 'success', title: 'Assigned', message: 'Alert assigned to you' })
    },
    onError: (err) => toast({ type: 'error', title: 'Failed', message: err?.response?.data?.detail || 'Could not assign' }),
  })
}

function useStartInvestigation(alertId) {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: () => api.post(`/alerts/${alertId}/investigate`).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert', alertId] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast({ type: 'success', title: 'Investigation started', message: 'Plans will appear shortly.' })
    },
    onError: (err) => toast({ type: 'error', title: 'Failed', message: err?.response?.data?.detail || 'Could not start' }),
  })
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MetaRow({ label, value }) {
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-theme last:border-0">
      <span className="text-xs text-theme-muted">{label}</span>
      <span className="text-xs text-theme-primary font-mono">{value ?? '—'}</span>
    </div>
  )
}

const TRACE_COLORS = {
  alert_received: 'text-blue-400', agent_dispatched: 'text-purple-400',
  agent_result: 'text-purple-400', llm_prompt: 'text-amber-400',
  llm_response: 'text-amber-400', plan_scored: 'text-emerald-400',
  plan_published: 'text-emerald-400', execution_started: 'text-orange-400',
  action_started: 'text-orange-400', commands_generated: 'text-orange-400',
  action_completed: 'text-emerald-400', action_failed: 'text-red-400',
  verification_started: 'text-blue-400', verification_check: 'text-blue-400',
  verification_failed: 'text-red-400', execution_completed: 'text-emerald-400',
  commands_simulated: 'text-sky-400', verification_simulated: 'text-sky-400',
  agent_error: 'text-red-400',
}

function TraceEntry({ trace, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  const color = TRACE_COLORS[trace.event_type] || 'text-theme-secondary'
  return (
    <div className="border-b border-theme last:border-0">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 px-4 py-2.5 hover:bg-theme-raised transition-colors text-left"
      >
        <div className={cn('w-2 h-2 rounded-full bg-current mt-1.5 shrink-0', color)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn('text-[10px] font-mono font-semibold uppercase tracking-wide', color)}>
              {trace.event_type}
            </span>
            <span className="text-[10px] text-theme-muted">{trace.agent}</span>
            {trace.duration_ms > 0 && <span className="text-[10px] text-theme-muted">{trace.duration_ms}ms</span>}
            {trace.confidence != null && (
              <span className="text-[10px] text-blue-400">{(trace.confidence * 100).toFixed(0)}% conf</span>
            )}
          </div>
          <p className="text-xs text-theme-primary mt-0.5 truncate">{trace.action}</p>
          {!open && trace.rationale && (
            <p className="text-[11px] text-theme-muted mt-0.5 truncate italic">{trace.rationale}</p>
          )}
        </div>
        <div className="shrink-0 text-theme-muted mt-1">
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </div>
      </button>
      {open && (
        <div className="px-7 pb-3 space-y-1">
          {trace.rationale && <p className="text-xs text-theme-secondary italic">{trace.rationale}</p>}
          {trace.input_summary && (
            <p className="text-[11px] text-theme-muted">
              <span className="font-semibold text-theme-secondary">In: </span>{trace.input_summary}
            </p>
          )}
          {trace.output_summary && (
            <p className="text-[11px] text-theme-muted">
              <span className="font-semibold text-theme-secondary">Out: </span>{trace.output_summary}
            </p>
          )}
          {trace.error && <p className="text-[11px] text-red-400 font-mono">{trace.error}</p>}
          <p className="text-[10px] text-theme-muted">{new Date(trace.timestamp).toLocaleTimeString()}</p>
        </div>
      )}
    </div>
  )
}

function ResolutionBanner({ approval }) {
  if (!approval) return null
  const ok = approval.decision === 'approved'
  return (
    <div className={cn('rounded-xl border p-4', ok ? 'bg-emerald-950/30 border-emerald-700/50' : 'bg-red-950/30 border-red-700/50')}>
      <div className="flex items-center gap-2 mb-3">
        {ok ? <CheckCircle size={14} className="text-emerald-400" /> : <XCircle size={14} className="text-red-400" />}
        <h2 className={cn('text-sm font-semibold', ok ? 'text-emerald-300' : 'text-red-300')}>
          {ok ? 'Plan Approved & Executed' : 'Plan Rejected'}
        </h2>
        <Lock size={11} className="text-theme-muted ml-1" />
        {ok && approval.execution_status === 'simulated' && (
          <span className="ml-2 text-xs text-sky-400 border border-sky-700/40 rounded px-1.5 py-0.5">
            SIMULATED
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
        <div>
          <p className="text-theme-muted mb-0.5">Decision by</p>
          <p className="text-theme-primary font-semibold flex items-center gap-1"><User size={11} />{approval.approved_by}</p>
        </div>
        <div>
          <p className="text-theme-muted mb-0.5">Resolved at</p>
          <p className="text-theme-primary font-semibold">
            {approval.created_at ? new Date(approval.created_at).toLocaleString() : '—'}
          </p>
        </div>
        {approval.notes && (
          <div className="col-span-2 sm:col-span-1">
            <p className="text-theme-muted mb-0.5">Notes</p>
            <p className="text-theme-secondary">{approval.notes}</p>
          </div>
        )}
      </div>
      {ok && Array.isArray(approval.actions) && approval.actions.length > 0 && (
        <div className="mt-3 pt-3 border-t border-emerald-800/40 space-y-1">
          <p className="text-xs text-theme-muted mb-1">Executed actions</p>
          {approval.actions.map((a, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
              <span className="font-mono font-semibold text-emerald-300">{a.action_type}</span>
              <span className="text-theme-muted">→ {a.target}</span>
              {a.rationale && <span className="text-theme-muted italic truncate">· {a.rationale}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function AlertDetail() {
  const { id }   = useParams()
  const navigate = useNavigate()
  const role     = useAuthStore(s => s.role)
  const userName = useAuthStore(s => s.userName)
  const toast    = useToastStore(s => s.push)
  const [tracesExpanded, setTracesExpanded] = useState(false)

  const { data: alert, isLoading, error: alertError } = useAlert(id)
  const { data: plansData, isLoading: loadingPlans }  = usePlans(id)
  const alertStatus = alert?.approval_status ?? ''
  const { data: rawTraces = [] }                       = useTraces(id, alertStatus)
  const traces = Array.isArray(rawTraces) ? rawTraces : []
  const isHistory = HISTORY_STATUSES.has(alertStatus)
  const { data: approval } = useApprovalRecord(id, isHistory)

  const selfAssign         = useSelfAssign(id)
  const startInvestigation = useStartInvestigation(id)

  // Detect approved → closed transition (execution finished) and notify the user
  const prevStatusRef = useRef('')
  useEffect(() => {
    const prev = prevStatusRef.current
    prevStatusRef.current = alertStatus
    if (prev !== 'approved' || alertStatus !== 'closed') return

    const succeeded = alert?.execution_status !== 'failed'
    toast({
      type: succeeded ? 'success' : 'warning',
      title: succeeded ? 'Plan executed successfully' : 'Execution completed with issues',
      message: succeeded
        ? 'All actions ran and the threat has been mitigated.'
        : 'Actions ran but mitigation could not be fully verified — manual review recommended.',
    })
    navigate('/alerts')
  }, [alertStatus])

  if (isLoading)  return <PageSpinner />
  if (alertError) return (
    <div className="p-8 text-center">
      <p className="text-red-400 text-sm">Error loading alert.</p>
      <button onClick={() => navigate(-1)} className="mt-4 text-blue-400 text-sm">Go back</button>
    </div>
  )
  if (!alert) return (
    <div className="p-8 text-center">
      <p className="text-theme-muted text-sm">Alert not found.</p>
      <button onClick={() => navigate('/alerts')} className="mt-4 text-blue-400 text-sm">All alerts</button>
    </div>
  )

  const cves   = Array.isArray(alert.cve_matches)    ? alert.cve_matches    : []
  const assets = Array.isArray(alert.affected_assets) ? alert.affected_assets : []
  const plans  = Array.isArray(plansData?.plans)      ? plansData.plans      : []
  const status = alert.approval_status

  const priorityLevel     = PRIORITY_LEVEL[(alert.priority || 'low').toLowerCase()] ?? 0
  const isAlreadyMine     = alert.assigned_to === userName
  const priorityBlocked   = role === 'analyst' && priorityLevel > ANALYST_CAP
  const alreadyTaken      = !!alert.assigned_to && !isAlreadyMine && role === 'analyst'
  const selfAssignBlocked = isHistory || priorityBlocked || alreadyTaken
  const blockReason = isHistory         ? 'Alert is read-only.'
    : priorityBlocked                   ? 'Analysts can only self-assign up to medium priority.'
    : alreadyTaken                      ? `Assigned to ${alert.assigned_to}.`
    : null
  const isExecuting = status === 'approved'

  const visibleTraces = tracesExpanded ? traces : traces.slice(-5)

  return (
    <div className="space-y-4">
      <button onClick={() => navigate(-1)} className="flex items-center gap-1 text-xs text-theme-secondary hover:text-blue-400 transition-colors">
        <ChevronLeft size={14} /> Back
      </button>

      {isHistory && (
        <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-950/20 border border-amber-700/40 px-3 py-2 rounded-lg">
          <Lock size={12} />
          <span>This alert is in <strong>History</strong> — read-only.</span>
        </div>
      )}

      {isHistory && <ResolutionBanner approval={approval} />}

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <p className="text-xs text-theme-muted">{alert.created_at ? timeAgo(alert.created_at) : ''}</p>
          <h1 className="text-base font-semibold text-theme-primary font-mono">{alert.classification || 'Unknown Alert'}</h1>
          {alert.assigned_to && (
            <p className="text-xs text-theme-muted mt-0.5 flex items-center gap-1">
              <UserCheck size={11} className="text-emerald-400" />
              {isHistory ? 'Handled by' : 'Assigned to'}{' '}
              <span className="text-emerald-400 font-medium">{alert.assigned_to}</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="priority" value={alert.priority}>{alert.priority}</Badge>
          <Badge variant="status"   value={status}>{status}</Badge>
          {!isHistory && (
            <>
              {status === 'received' && (
                <button
                  onClick={() => startInvestigation.mutate()}
                  disabled={startInvestigation.isPending}
                  className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 transition-colors"
                >
                  {startInvestigation.isPending ? <Spinner className="h-3 w-3" /> : <Activity size={12} />}
                  Start Investigation
                </button>
              )}
              {isAlreadyMine ? (
                <>
                  <span className="flex items-center gap-1 text-xs text-emerald-400 px-2 py-1 bg-emerald-900/20 rounded">
                    <UserCheck size={12} /> Mine
                  </span>
                  <button
                    onClick={() => navigate('/transfers', { state: { alertId: id } })}
                    className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 transition-colors"
                  >
                    <ArrowRightLeft size={12} /> Transfer
                  </button>
                </>
              ) : (
                <div className="relative group">
                  <button
                    onClick={() => {
                      if (selfAssignBlocked) { toast({ type: 'error', title: 'Cannot assign', message: blockReason }); return }
                      selfAssign.mutate(userName)
                    }}
                    disabled={selfAssign.isPending || selfAssignBlocked}
                    className={cn(
                      'flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded transition-colors',
                      selfAssignBlocked ? 'bg-theme-raised text-theme-muted cursor-not-allowed opacity-60'
                                        : 'bg-blue-600/20 hover:bg-blue-600/30 text-blue-400'
                    )}
                  >
                    {selfAssign.isPending ? <Spinner className="h-3 w-3" /> : <UserCheck size={12} />}
                    Assign to me
                  </button>
                  {selfAssignBlocked && blockReason && (
                    <div className="absolute right-0 top-9 z-10 w-56 hidden group-hover:block bg-theme-surface border border-theme rounded-lg p-2 text-xs text-theme-muted shadow-lg">
                      {blockReason}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Metadata + CVEs + Assets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader><CardTitle>Alert Metadata</CardTitle></CardHeader>
          <div className="px-4 pb-4">
            <MetaRow label="Alert ID"      value={alert.alert_id || id} />
            <MetaRow label="Source IP"     value={alert.src_ip} />
            <MetaRow label="Destination"   value={alert.dst_ip ? `${alert.dst_ip}:${alert.dst_port}` : null} />
            <MetaRow label="Anomaly Score" value={alert.anomaly_score != null ? alert.anomaly_score.toFixed(3) : null} />
            <MetaRow label="Timestamp"     value={alert.timestamp ? new Date(alert.timestamp).toLocaleString() : null} />
          </div>
        </Card>

        <Card>
          <CardHeader><CardTitle>CVE Matches ({cves.length})</CardTitle></CardHeader>
          <div className="px-4 pb-4">
            {cves.length === 0
              ? <p className="text-xs text-theme-muted">No CVE matches</p>
              : <ul className="space-y-2">
                  {cves.map((c) => (
                    <li
                      key={c.cve_id}
                      onClick={() => navigate('/cves')}
                      className="text-xs border-b border-theme pb-2 last:border-0 cursor-pointer hover:bg-theme-raised rounded px-1.5 py-1 -mx-1.5 transition-colors group"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-blue-400 group-hover:underline">{c.cve_id}</span>
                        <span className={cn('font-bold',
                          (c.cvss_v3_score ?? c.cvss_score) >= 9  ? 'text-red-400'
                          : (c.cvss_v3_score ?? c.cvss_score) >= 7 ? 'text-amber-400'
                          : 'text-slate-300'
                        )}>
                          {(c.cvss_v3_score ?? c.cvss_score)?.toFixed(1) ?? '?'}
                        </span>
                      </div>
                      <p className="text-theme-muted text-[11px] truncate mt-0.5">{c.affected_product}</p>
                      {c.exploit_available && <span className="text-red-400 text-[10px]">⚡ Exploit available</span>}
                    </li>
                  ))}
                </ul>
            }
          </div>
        </Card>

        <Card>
          <CardHeader><CardTitle>Affected Assets ({assets.length})</CardTitle></CardHeader>
          <div className="px-4 pb-4">
            {assets.length === 0
              ? <p className="text-xs text-theme-muted">No assets resolved</p>
              : <ul className="space-y-2">
                  {assets.map((a, i) => (
                    <li
                      key={i}
                      onClick={() => navigate('/assets')}
                      className="text-xs border-b border-theme pb-2 last:border-0 cursor-pointer hover:bg-theme-raised rounded px-1.5 py-1 -mx-1.5 transition-colors group"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-theme-primary font-medium group-hover:text-blue-400 transition-colors">{a.hostname || 'Unknown'}</span>
                        <span className="font-mono text-theme-muted">{a.ip}</span>
                      </div>
                      <div className="flex gap-1.5 mt-1">
                        {a.criticality_tier && <Badge variant="default">Tier {a.criticality_tier}</Badge>}
                        {a.zone && <Badge variant="default">{a.zone}</Badge>}
                      </div>
                    </li>
                  ))}
                </ul>
            }
          </div>
        </Card>
      </div>

      {/* Plans — active alerts only; history shows ResolutionBanner instead */}
      {!isHistory && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText size={14} className="text-blue-400" />
                <CardTitle>{isExecuting ? 'Executing Plan…' : `Execution Plans (${plans.length})`}</CardTitle>
              </div>
              {plans.length > 0 && isAlreadyMine && !isExecuting && (
                <button
                  onClick={() => navigate(`/alerts/${id}/plans`)}
                  className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-600/20 transition-colors"
                >
                  Review & Approve <ChevronRight size={13} />
                </button>
              )}
            </div>
          </CardHeader>
          {isExecuting ? (
            <div className="px-4 pb-5 flex items-center gap-3 text-sm text-theme-secondary">
              <Loader2 size={16} className="animate-spin text-blue-400" />
              Agent is executing the approved plan — this page will update automatically.
            </div>
          ) : loadingPlans ? (
            <div className="px-4 py-4"><Spinner size="sm" /></div>
          ) : plans.length === 0 ? (
            <div className="px-4 py-6 text-center">
              <FileText size={22} className="text-theme-muted mx-auto mb-2 opacity-40" />
              <p className="text-xs text-theme-muted">
                {status === 'received' && 'Click "Start Investigation" above to generate plans.'}
                {status === 'triaged'  && 'Investigation in progress — plans will appear shortly.'}
                {!['received','triaged'].includes(status) && 'No plans generated.'}
              </p>
            </div>
          ) : (
            <div className="space-y-2.5 px-4 pb-4">
              {plans.map((plan, idx) => (
                <div
                  key={plan.plan_id || idx}
                  onClick={() => navigate(`/alerts/${id}/plans`)}
                  className="bg-theme-base border border-theme rounded-lg p-3 cursor-pointer hover:border-blue-500/50 hover:bg-blue-950/10 transition-all group"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-theme-primary">Plan {idx + 1}</span>
                      <Badge variant={plan.automation_tier === 'conservative' ? 'success' : plan.automation_tier === 'aggressive' ? 'error' : 'warning'}>
                        {plan.automation_tier}
                      </Badge>
                      <Badge variant="priority" value={plan.risk_level}>{plan.risk_level}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      {plan.confidence != null && (
                        <span className="text-xs text-theme-muted">{(plan.confidence * 100).toFixed(0)}% conf</span>
                      )}
                      <ChevronRight size={13} className="text-theme-muted group-hover:text-blue-400 transition-colors" />
                    </div>
                  </div>
                  <p className="text-xs text-theme-secondary mb-2">{plan.rationale}</p>
                  <div className="flex flex-wrap gap-1">
                    {(plan.actions ?? []).map((a, ai) => (
                      <span key={ai} className="text-[10px] bg-theme-surface px-2 py-0.5 rounded text-theme-secondary flex items-center gap-1">
                        <Shield size={9} />{a.action_type} → {a.target}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* Reasoning Traces */}
      {(traces.length > 0 || ['triaged','plans_generated'].includes(status) || isHistory) && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity size={14} className="text-purple-400" />
                <CardTitle>Agent Reasoning Traces ({traces.length})</CardTitle>
              </div>
              <button
                onClick={() => navigate(`/alerts/${id}/trace`)}
                className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-colors"
              >
                Full Timeline <ChevronRight size={12} />
              </button>
            </div>
          </CardHeader>
          {traces.length === 0 ? (
            <p className="px-4 pb-4 text-xs text-theme-muted">
              {status === 'triaged' ? 'Investigation running — traces will appear here…' : 'No traces yet.'}
            </p>
          ) : (
            <>
              <div className="divide-y divide-theme">
                {visibleTraces.map((t, i) => (
                  <TraceEntry key={t.event_id || i} trace={t} defaultOpen={i === visibleTraces.length - 1} />
                ))}
              </div>
              {traces.length > 5 && (
                <button
                  onClick={() => setTracesExpanded(e => !e)}
                  className="w-full py-2 text-xs text-theme-muted hover:text-theme-secondary flex items-center justify-center gap-1 border-t border-theme transition-colors"
                >
                  {tracesExpanded
                    ? <><ChevronUp size={12} /> Show less</>
                    : <><ChevronDown size={12} /> Show all {traces.length} traces</>}
                </button>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  )
}
