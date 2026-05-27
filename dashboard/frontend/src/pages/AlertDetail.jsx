import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ChevronLeft, ChevronRight, FileText, Activity, Shield,
  Clock, Server, UserCheck, Info, ArrowRightLeft,
  CheckCircle, XCircle, Lock, User, AlertTriangle
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

// Priority levels above which analysts cannot self-assign
const ANALYST_MAX_PRIORITY = { low: 1, medium: 2, high: 3, critical: 4 }
const ANALYST_CAP_LEVEL = 2  // medium

// Statuses that mean the alert is closed / no longer actionable
const HISTORY_STATUSES = new Set(['approved', 'rejected', 'executed', 'closed'])

function usePlans(alertId) {
  return useQuery({
    queryKey: ['plans', alertId],
    queryFn: () => api.get(`/plans/${alertId}/plans`).then(r => r.data),
    enabled: !!alertId,
  })
}

function useTraces(alertId) {
  return useQuery({
    queryKey: ['traces', alertId],
    queryFn: () => api.get(`/traces/${alertId}/trace`).then(r => r.data),
    enabled: !!alertId,
  })
}

function useApprovalRecord(alertId, isHistory) {
  return useQuery({
    queryKey: ['approval', alertId],
    queryFn: () => api.get(`/alerts/${alertId}/approval`).then(r => r.data),
    enabled: !!alertId && isHistory,
    retry: false,           // 404 is expected for new alerts
  })
}

function useSelfAssign(alertId) {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (analystId) =>
      api.post(`/alerts/${alertId}/assign`, { analyst_id: analystId }).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert', alertId] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alerts', 'my'] })
      toast({ type: 'success', title: 'Alert assigned', message: 'This alert is now assigned to you' })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Assignment failed', message: err?.response?.data?.detail || 'Could not assign alert' })
    },
  })
}

// ── Resolution banner shown for history alerts ────────────────────────────────

function ResolutionBanner({ approval, alert }) {
  if (!approval) return null
  const isApproved = approval.decision === 'approved'

  return (
    <div className={cn(
      'rounded-xl border p-4 mb-2',
      isApproved
        ? 'bg-emerald-950/30 border-emerald-700/50'
        : 'bg-red-950/30 border-red-700/50'
    )}>
      <div className="flex items-center gap-2 mb-3">
        {isApproved
          ? <CheckCircle size={15} className="text-emerald-400" />
          : <XCircle size={15} className="text-red-400" />}
        <h2 className={cn('text-sm font-semibold', isApproved ? 'text-emerald-300' : 'text-red-300')}>
          {isApproved ? 'Plan Approved & Executed' : 'Plan Rejected'}
        </h2>
        <Lock size={12} className="text-theme-muted ml-1" title="This alert is read-only" />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div>
          <p className="text-theme-muted mb-0.5">Decision by</p>
          <p className="text-theme-primary font-semibold flex items-center gap-1">
            <User size={11} /> {approval.approved_by}
          </p>
        </div>
        <div>
          <p className="text-theme-muted mb-0.5">Resolved at</p>
          <p className="text-theme-primary font-semibold">
            {approval.created_at
              ? new Date(approval.created_at).toLocaleString()
              : (alert.approved_at ? new Date(alert.approved_at).toLocaleString() : '—')}
          </p>
        </div>
        <div>
          <p className="text-theme-muted mb-0.5">Plan ID</p>
          <p className="text-theme-primary font-mono text-[11px] truncate" title={approval.plan_id}>
            {approval.plan_id ?? '—'}
          </p>
        </div>
        {approval.notes && (
          <div className="col-span-2 sm:col-span-1">
            <p className="text-theme-muted mb-0.5">Notes</p>
            <p className="text-theme-secondary">{approval.notes}</p>
          </div>
        )}
      </div>

      {/* Approved actions list */}
      {isApproved && Array.isArray(approval.actions) && approval.actions.length > 0 && (
        <div className="mt-3 pt-3 border-t border-emerald-800/40">
          <p className="text-xs text-theme-muted mb-2">Executed actions</p>
          <div className="space-y-1.5">
            {approval.actions.map((a, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                <span className="font-mono font-semibold text-emerald-300">{a.action_type}</span>
                <span className="text-theme-muted">→</span>
                <span className="text-theme-secondary">{a.target}</span>
                {a.rationale && (
                  <span className="text-theme-muted italic truncate" title={a.rationale}>
                    · {a.rationale}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Locked read-only notice ───────────────────────────────────────────────────

function ReadOnlyNotice() {
  return (
    <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-950/20 border border-amber-700/40 px-3 py-2 rounded-lg">
      <Lock size={12} />
      <span>This alert is in the <strong>History</strong> — it is read-only. Assignment and plan execution are disabled.</span>
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function AlertDetail() {
  const { id }    = useParams()
  const navigate  = useNavigate()
  const role      = useAuthStore(s => s.role)
  const userName  = useAuthStore(s => s.userName)
  const toast     = useToastStore(s => s.push)

  const { data: alert, isLoading: loadingAlert, error: alertError } = useAlert(id)
  const { data: plansData, isLoading: loadingPlans } = usePlans(id)
  const { data: traces, isLoading: loadingTraces } = useTraces(id)
  const selfAssign = useSelfAssign(id)

  // Determine if this is a historical (resolved) alert
  const isHistory = alert ? HISTORY_STATUSES.has(alert.approval_status) : false

  const { data: approvalRecord } = useApprovalRecord(id, isHistory)

  if (loadingAlert) return <PageSpinner />
  if (alertError) return (
    <div className="p-8 text-center">
      <p className="text-red-400 text-sm">Error loading alert: {alertError.message}</p>
      <button onClick={() => navigate(-1)} className="mt-4 text-blue-400 text-sm">Go Back</button>
    </div>
  )
  if (!alert) return (
    <div className="p-8 text-center">
      <p className="text-theme-muted text-sm">Alert not found.</p>
      <button onClick={() => navigate('/alerts')} className="mt-4 text-blue-400 text-sm">View All Alerts</button>
    </div>
  )

  const cves   = alert.cve_matches   ?? []
  const assets = alert.affected_assets ?? []
  const plans  = plansData?.plans ?? []

  // Assignment logic — fully blocked for history alerts
  const alertPriorityLevel = ANALYST_MAX_PRIORITY[(alert.priority || 'low').toLowerCase()] ?? 0
  const isAlreadyMine  = alert.assigned_to === userName
  const priorityBlocked = role === 'analyst' && alertPriorityLevel > ANALYST_CAP_LEVEL
  const alreadyTaken   = !!alert.assigned_to && !isAlreadyMine && role === 'analyst'
  const selfAssignBlocked = isHistory || priorityBlocked || alreadyTaken

  const blockReason = isHistory
    ? 'This alert has been resolved and is read-only.'
    : priorityBlocked
    ? `Analysts can only self-assign up to medium priority. This is a ${alert.priority} alert.`
    : alreadyTaken
    ? `This alert is already assigned to ${alert.assigned_to}. Only a Senior Analyst or Admin can reassign it.`
    : null

  const handleSelfAssign = () => {
    if (selfAssignBlocked) {
      toast({ type: 'error', title: 'Cannot self-assign', message: blockReason })
      return
    }
    selfAssign.mutate(userName)
  }

  const handleTransfer = () => navigate('/transfers', { state: { alertId: id } })

  return (
    <div className="space-y-4">
      {/* Back button */}
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1 text-xs text-theme-secondary hover:text-blue-400 transition-colors mb-1"
      >
        <ChevronLeft size={14}/> Back
      </button>

      {/* Read-only notice for history alerts */}
      {isHistory && <ReadOnlyNotice />}

      {/* Resolution banner — only for history */}
      {isHistory && <ResolutionBanner approval={approvalRecord} alert={alert} />}

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <p className="text-xs text-theme-muted mb-0.5">{alert.created_at ? timeAgo(alert.created_at) : 'Unknown'}</p>
          <h1 className="text-base font-semibold text-theme-primary font-mono">{alert.classification || 'Unknown Alert'}</h1>
          {alert.assigned_to && (
            <p className="text-xs text-theme-muted mt-0.5 flex items-center gap-1">
              <UserCheck size={11} className="text-emerald-400" />
              {isHistory ? 'Was handled by' : 'Assigned to'}{' '}
              <span className="text-emerald-400 font-medium">{alert.assigned_to}</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="priority" value={alert.priority || 'medium'}>{alert.priority || 'medium'}</Badge>
          <Badge variant="status" value={alert.approval_status || 'unknown'}>{alert.approval_status || 'unknown'}</Badge>

          {/* Assignment controls — hidden for history alerts */}
          {!isHistory && (
            isAlreadyMine ? (
              <>
                <span className="flex items-center gap-1 text-xs text-emerald-400 font-medium px-2 py-1 bg-emerald-900/20 rounded">
                  <UserCheck size={12} /> Assigned to me
                </span>
                <button
                  id="transfer-alert-btn"
                  onClick={handleTransfer}
                  className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded transition-colors bg-amber-600/20 hover:bg-amber-600/30 text-amber-400"
                  title="Transfer this alert to another analyst"
                >
                  <ArrowRightLeft size={12} /> Transfer
                </button>
              </>
            ) : (
              <div className="relative group">
                <button
                  id="self-assign-btn"
                  onClick={handleSelfAssign}
                  disabled={selfAssign.isPending || selfAssignBlocked}
                  className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded transition-colors ${
                    selfAssignBlocked
                      ? 'bg-theme-raised text-theme-muted cursor-not-allowed opacity-60'
                      : 'bg-blue-600/20 hover:bg-blue-600/30 text-blue-400'
                  }`}
                >
                  {selfAssign.isPending ? <Spinner className="h-3 w-3" /> : <UserCheck size={12} />}
                  Assign to me
                </button>
                {selfAssignBlocked && blockReason && (
                  <div className="absolute right-0 top-8 z-10 w-64 hidden group-hover:block bg-theme-surface border border-theme rounded-lg p-2.5 text-xs text-theme-muted shadow-lg">
                    <Info size={11} className="inline mr-1 text-amber-400" />
                    {blockReason}
                  </div>
                )}
              </div>
            )
          )}
        </div>
      </div>

      {/* 3-column metadata grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Metadata */}
        <Card>
          <CardHeader><CardTitle>Alert Metadata</CardTitle></CardHeader>
          <dl className="space-y-2 text-xs">
            {[
              ['Alert ID',  alert.alert_id || id],
              ['Src IP',    alert.src_ip || 'N/A'],
              ['Dst IP',    alert.dst_ip || 'N/A'],
              ['Dst Port',  alert.dst_port || 'N/A'],
              ['Anomaly Score', alert.anomaly_score != null ? alert.anomaly_score.toFixed(3) : 'N/A'],
            ].map(([k,v]) => (
              <div key={k} className="flex justify-between">
                <dt className="text-theme-muted">{k}</dt>
                <dd className="text-theme-primary font-mono">{v}</dd>
              </div>
            ))}
          </dl>
        </Card>

        {/* CVE Matches */}
        <Card>
          <CardHeader><CardTitle>CVE Matches ({cves.length})</CardTitle></CardHeader>
          {cves.length === 0
            ? <p className="text-xs text-theme-muted">No CVE matches</p>
            : <ul className="space-y-2">
                {cves.map((c) => (
                  <li key={c.cve_id} className="text-xs border-b border-theme pb-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-blue-400">{c.cve_id}</span>
                      <span className={`font-bold ${c.cvss_score >= 9 ? 'text-red-400' : c.cvss_score >= 7 ? 'text-amber-400' : 'text-slate-300'}`}>
                        {c.cvss_score?.toFixed(1)}
                      </span>
                    </div>
                    {c.exploit_available && <span className="text-red-400">⚡ Exploit available</span>}
                  </li>
                ))}
              </ul>
          }
        </Card>

        {/* Affected Assets */}
        <Card>
          <CardHeader><CardTitle>Affected Assets ({assets.length})</CardTitle></CardHeader>
          {assets.length === 0
            ? <p className="text-xs text-theme-muted">No assets resolved</p>
            : <ul className="space-y-2">
                {assets.map((a) => (
                  <li key={a.ip} className="text-xs border-b border-theme pb-2">
                    <div className="flex items-center justify-between">
                      <span className="text-theme-primary font-medium">{a.hostname}</span>
                      <span className="text-theme-secondary font-mono">{a.ip}</span>
                    </div>
                    <div className="flex gap-2 mt-1">
                      <Badge variant="default">Tier {a.criticality_tier}</Badge>
                      <Badge variant="default">{a.zone}</Badge>
                    </div>
                  </li>
                ))}
              </ul>
          }
        </Card>
      </div>

      {/* Plans Section */}
      <Card className="mt-4">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText size={14} className="text-blue-400" />
              <CardTitle>
                {isHistory ? 'Executed Plan' : `Execution Plans (${plans.length})`}
              </CardTitle>
            </div>
            {/* Only show Review link for active alerts */}
            {!isHistory && (
              <button
                onClick={() => navigate(`/alerts/${id}/plans`)}
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
              >
                Review & Approve <ChevronRight size={12} />
              </button>
            )}
          </div>
        </CardHeader>

        {isHistory ? (
          /* History view: show the approved plan's actions from the approval record */
          approvalRecord ? (
            <div className="space-y-3 px-4 pb-4">
              <div className="bg-theme-base border border-theme rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  {approvalRecord.decision === 'approved'
                    ? <CheckCircle size={13} className="text-emerald-400" />
                    : <XCircle size={13} className="text-red-400" />}
                  <span className="text-xs font-semibold text-theme-primary capitalize">
                    {approvalRecord.decision} plan
                  </span>
                  <span className="text-[10px] font-mono text-theme-muted">{approvalRecord.plan_id}</span>
                </div>

                {approvalRecord.decision === 'approved' && Array.isArray(approvalRecord.actions) && approvalRecord.actions.length > 0 ? (
                  <div className="space-y-1.5">
                    {approvalRecord.actions.map((a, i) => (
                      <div key={i} className="flex flex-col gap-0.5 border-l-2 border-emerald-700/50 pl-3 py-0.5">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="font-mono font-semibold text-emerald-300">{a.action_type}</span>
                          <span className="text-theme-muted">→</span>
                          <span className="text-theme-secondary">{a.target}</span>
                          {a.parameters && Object.keys(a.parameters).length > 0 && (
                            <span className="text-[10px] font-mono text-theme-muted">
                              {JSON.stringify(a.parameters)}
                            </span>
                          )}
                        </div>
                        {a.rationale && (
                          <p className="text-[11px] text-theme-muted italic">{a.rationale}</p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-theme-muted">
                    {approvalRecord.decision === 'rejected'
                      ? 'Plan was rejected — no actions were executed.'
                      : 'No action details recorded.'}
                  </p>
                )}

                {approvalRecord.notes && (
                  <div className="mt-2 pt-2 border-t border-theme">
                    <p className="text-[11px] text-theme-muted">Notes from approver:</p>
                    <p className="text-xs text-theme-secondary italic mt-0.5">{approvalRecord.notes}</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <p className="px-4 py-4 text-xs text-theme-muted">No plan record found for this alert.</p>
          )
        ) : (
          /* Active view: show generated plans summary */
          loadingPlans ? (
            <div className="px-4 py-4"><Spinner size="sm" /></div>
          ) : plans.length === 0 ? (
            <p className="px-4 py-4 text-xs text-theme-muted">No plans generated for this alert</p>
          ) : (
            <div className="space-y-3 px-4 pb-4">
              {plans.map((plan, idx) => (
                <div key={plan.plan_id || idx} className="bg-theme-base border border-theme rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-theme-primary">Plan {idx + 1}</span>
                      <Badge variant={plan.automation_tier === 'L1' ? 'success' : 'warning'}>
                        {plan.automation_tier}
                      </Badge>
                    </div>
                    <span className="text-xs text-theme-muted">
                      {plan.estimated_duration_seconds}s
                    </span>
                  </div>
                  <p className="text-xs text-theme-secondary mb-2">{plan.description}</p>
                  {plan.steps && plan.steps.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {plan.steps.map((step, sidx) => (
                        <span key={sidx} className="text-[10px] bg-theme-surface px-2 py-1 rounded text-theme-secondary flex items-center gap-1">
                          <Shield size={10} />
                          {step.action?.replace('_', ' ')}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )
        )}
      </Card>

      {/* Reasoning Traces */}
      <Card className="mt-4">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity size={14} className="text-purple-400" />
              <CardTitle>Agent Reasoning Traces ({traces?.length || 0})</CardTitle>
            </div>
            <button
              onClick={() => navigate(`/alerts/${id}/trace`)}
              className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1"
            >
              Full Timeline <ChevronRight size={12} />
            </button>
          </div>
        </CardHeader>
        {loadingTraces ? (
          <div className="px-4 py-4"><Spinner size="sm" /></div>
        ) : !traces || traces.length === 0 ? (
          <p className="px-4 py-4 text-xs text-theme-muted">No traces available for this alert</p>
        ) : (
          <div className="px-4 pb-4 space-y-2">
            {/* For history alerts, show all traces; for active, cap at 5 */}
            {(isHistory ? traces : traces.slice(0, 5)).map((trace, idx) => (
              <div key={trace.trace_id || idx} className="flex items-start gap-3 text-xs">
                <div className="mt-0.5">
                  {trace.agent_name === 'orchestrator' && <Server size={12} className="text-blue-400" />}
                  {trace.agent_name === 'cve_lookup' && <Shield size={12} className="text-amber-400" />}
                  {trace.agent_name === 'planning' && <FileText size={12} className="text-emerald-400" />}
                  {!['orchestrator', 'cve_lookup', 'planning'].includes(trace.agent_name) && <Activity size={12} className="text-theme-muted" />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-theme-primary capitalize">{trace.agent_name?.replace('_', ' ')}</span>
                    <span className="text-theme-muted">•</span>
                    <span className="text-theme-secondary">{trace.action?.replace('_', ' ')}</span>
                    {trace.duration_ms && (
                      <>
                        <span className="text-theme-muted">•</span>
                        <Clock size={10} className="text-theme-muted" />
                        <span className="text-theme-muted">{trace.duration_ms}ms</span>
                      </>
                    )}
                  </div>
                  {trace.details && (
                    <p className="text-theme-muted mt-0.5 text-[10px] break-all">
                      {typeof trace.details === 'string' ? trace.details : JSON.stringify(trace.details)}
                    </p>
                  )}
                </div>
              </div>
            ))}
            {!isHistory && traces.length > 5 && (
              <p className="text-xs text-theme-muted text-center pt-2">
                +{traces.length - 5} more —{' '}
                <button
                  onClick={() => navigate(`/alerts/${id}/trace`)}
                  className="text-purple-400 hover:underline"
                >
                  view full timeline
                </button>
              </p>
            )}
          </div>
        )}
      </Card>

      {/* Action buttons — only for active alerts */}
      {!isHistory && (
        <div className="flex gap-3 mt-4 flex-wrap">
          <button
            onClick={() => navigate(`/alerts/${id}/plans`)}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-4 py-2 rounded transition-colors"
          >
            Review Plans <ChevronRight size={13} />
          </button>
          <button
            onClick={() => navigate(`/alerts/${id}/trace`)}
            className="flex items-center gap-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-semibold px-4 py-2 rounded transition-colors"
          >
            View Full Trace <ChevronRight size={13} />
          </button>
          {!isAlreadyMine && !selfAssignBlocked && (
            <button
              onClick={handleSelfAssign}
              disabled={selfAssign.isPending}
              className="flex items-center gap-1.5 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded transition-colors"
            >
              <UserCheck size={13} />
              {selfAssign.isPending ? 'Assigning…' : 'Assign to Me'}
            </button>
          )}
        </div>
      )}

      {/* History: only Full Trace button */}
      {isHistory && (
        <div className="flex gap-3 mt-4">
          <button
            onClick={() => navigate(`/alerts/${id}/trace`)}
            className="flex items-center gap-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-semibold px-4 py-2 rounded transition-colors"
          >
            <Activity size={13} /> View Full Reasoning Trace
          </button>
        </div>
      )}
    </div>
  )
}