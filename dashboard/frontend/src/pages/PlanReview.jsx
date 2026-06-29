import { useState, useCallback } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ChevronLeft, CheckCircle, XCircle, AlertTriangle,
  ArrowUpCircle, Lock, Pencil, Plus, Trash2, Save, RefreshCw
} from 'lucide-react'
import { useMutation } from '@tanstack/react-query'
import { usePlans, useApprovePlan, useRejectPlan } from '../hooks/usePlans'
import { useAlert } from '../hooks/useAlerts'
import { Badge } from '../components/ui/Badge'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { PageSpinner, Spinner } from '../components/ui/Spinner'
import { useAuthStore } from '../store/auth'
import { useToastStore } from '../components/ui/Toast'
import api from '../lib/api'

const DESTRUCTIVE = new Set(['isolate_host','firewall_block','firewall_unblock','restore_host','credential_rotate'])
const ACTION_TYPES = ['firewall_block','firewall_unblock','isolate_host','restore_host','patch','notify','deep_inspect','rate_limit','credential_rotate']
const HISTORY_STATUSES = new Set(['approved','rejected','executed','closed'])

// ── Replan mutation ──────────────────────────────────────────────────────────
function useReplan(alertId, { onDone } = {}) {
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (reason) =>
      api.post(`/plans/${alertId}/replan`, { reason }).then(r => r.data),
    onSuccess: () => {
      toast({ type: 'info', title: 'Replan requested', message: 'New investigation running — plans will update shortly.' })
      onDone?.('replan')
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Replan failed', message: err?.response?.data?.detail || 'Could not trigger replan' })
    },
  })
}

// ── Escalate mutation ────────────────────────────────────────────────────────
function useEscalate(alertId, { onDone } = {}) {
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ planId, reason, actions }) =>
      api.post(`/plans/${alertId}/escalate`, { plan_id: planId, reason, actions }).then(r => r.data),
    onSuccess: (data) => {
      toast({ type: 'success', title: 'Escalation sent', message: `Notified ${data.notified_admins} admin(s). Returning to alerts…` })
      onDone?.('escalated')
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Escalation failed', message: err?.response?.data?.detail || 'Could not send escalation' })
    },
  })
}

// ── Inline plan editor ───────────────────────────────────────────────────────
function PlanEditor({ plan, onSave, onCancel }) {
  const [actions, setActions] = useState(
    (plan.actions ?? []).map((a, i) => ({ ...a, _key: i }))
  )

  const update = (idx, field, val) =>
    setActions(prev => prev.map((a, i) => i === idx ? { ...a, [field]: val } : a))

  const addAction = () =>
    setActions(prev => [...prev, { _key: Date.now(), action_type: 'notify', target: '', parameters: {}, rationale: '' }])

  const remove = (idx) =>
    setActions(prev => prev.filter((_, i) => i !== idx))

  const handleSave = () => {
    const cleaned = actions.map(({ _key, ...rest }) => ({
      action_type: rest.action_type,
      target: rest.target || '',
      parameters: rest.parameters ?? {},
      rationale: rest.rationale || '',
    }))
    onSave({ ...plan, actions: cleaned })
  }

  return (
    <div className="space-y-3">
      <p className="text-xs font-medium text-theme-secondary">Edit actions for this plan:</p>
      {actions.map((a, i) => (
        <div key={a._key} className="bg-theme-base border border-theme rounded-lg p-3 space-y-2">
          <div className="flex gap-2 items-center">
            <input
              value={a.action_type}
              onChange={e => update(i, 'action_type', e.target.value)}
              placeholder="Action type (e.g., firewall_block, isolate_host)"
              className="flex-1 bg-theme-surface border border-theme rounded px-2 py-1 text-xs text-theme-primary focus:outline-none focus:border-blue-500"
            />
            {DESTRUCTIVE.has(a.action_type) && (
              <span className="text-[10px] text-red-400 font-medium uppercase">destructive</span>
            )}
            <button onClick={() => remove(i)} className="text-theme-muted hover:text-red-400 transition-colors">
              <Trash2 size={12} />
            </button>
          </div>
          <input
            value={a.target}
            onChange={e => update(i, 'target', e.target.value)}
            placeholder="Target (IP, hostname, user…)"
            className="w-full bg-theme-surface border border-theme rounded px-2 py-1 text-xs text-theme-primary focus:outline-none focus:border-blue-500"
          />
          <input
            value={a.rationale}
            onChange={e => update(i, 'rationale', e.target.value)}
            placeholder="Rationale (optional)"
            className="w-full bg-theme-surface border border-theme rounded px-2 py-1 text-xs text-theme-muted focus:outline-none focus:border-blue-500"
          />
        </div>
      ))}
      <button
        onClick={addAction}
        className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
      >
        <Plus size={12} /> Add action
      </button>
      <div className="flex justify-end gap-2 pt-2">
        <button onClick={onCancel} className="px-3 py-1.5 text-xs rounded bg-theme-raised text-theme-secondary hover:bg-theme-base transition-colors">
          Cancel
        </button>
        <button
          onClick={handleSave}
          className="px-3 py-1.5 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold transition-colors flex items-center gap-1.5"
        >
          <Save size={11} /> Save Changes
        </button>
      </div>
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────
export default function PlanReview() {
  const { id }   = useParams()
  const navigate = useNavigate()
  const role     = useAuthStore(s => s.role)
  const userName = useAuthStore(s => s.userName)

  const onDone = useCallback((action) => {
    setTimeout(() => navigate('/alerts'), 900)
  }, [navigate])

  const { data, isLoading }                        = usePlans(id)
  const { data: alert, isLoading: loadingAlert }   = useAlert(id)
  const approve  = useApprovePlan(id, { onDone })
  const reject   = useRejectPlan(id,  { onDone })
  const escalate = useEscalate(id,    { onDone })
  const replan   = useReplan(id,      { onDone })

  // Local state
  const [editingPlan,    setEditingPlan]    = useState(null)
  const [editedPlans,    setEditedPlans]    = useState({})
  const [confirmPlan,    setConfirmPlan]    = useState(null)
  const [pendingApprove, setPendingApprove] = useState(null)
  const [rejectPlan,     setRejectPlan]     = useState(null)
  const [rejectReason,   setRejectReason]   = useState('')
  const [escalatePlan,   setEscalatePlan]   = useState(null)
  const [escalateReason, setEscalateReason] = useState('')
  const [replanReason,   setReplanReason]   = useState('')
  const [showReplan,     setShowReplan]     = useState(false)

  if (isLoading || loadingAlert) return <PageSpinner />

  const rawPlans   = data?.plans ?? []
  // Merge any locally-edited versions on top of originals
  const plans = rawPlans.map(p => editedPlans[p.plan_id] ?? p)

  const isAnalyst  = role === 'analyst'

  // ── Already resolved? ──────────────────────────────────────────────────────
  const isResolved = alert ? HISTORY_STATUSES.has(alert.approval_status) : false

  // ── Ownership ──────────────────────────────────────────────────────────────
  // Only the assigned analyst can act on plans. Unassigned = view-only.
  const assignedTo = alert?.assigned_to ?? null
  const isMyAlert  = assignedTo === userName
  const canAct     = !isResolved && isMyAlert

  const lockedReason = isResolved
    ? `This alert has already been ${alert.approval_status}. No further plan actions are available.`
    : !canAct
    ? assignedTo
      ? `This alert is assigned to '${assignedTo}'. Only the assigned analyst can review plans.`
      : 'This alert is not assigned to anyone. Assign it to yourself before reviewing plans.'
    : null

  // ── Handlers ───────────────────────────────────────────────────────────────
  const resolvedPlan = (plan) => editedPlans[plan.plan_id] ?? plan

  const handleApprove = (plan) => {
    const p = resolvedPlan(plan)
    const actions = p.actions ?? []
    const hasDestructive = actions.some(a => DESTRUCTIVE.has(a.action_type))
    if (hasDestructive && isAnalyst) { setEscalatePlan(p); return }
    if (hasDestructive)              { setConfirmPlan(p);  return }
    setPendingApprove(p)
  }

  const doApprove = (plan) => {
    approve.mutate({
      plan_id: plan.plan_id,
      actions: (plan.actions ?? []).map(a => ({
        action_type: a.action_type,
        target:      a.target,
        parameters:  a.parameters ?? {},
        rationale:   a.rationale ?? '',
      })),
    })
  }

  const doEscalate = () => {
    if (!escalatePlan || !escalateReason.trim()) return
    escalate.mutate({
      planId:  escalatePlan.plan_id,
      reason:  escalateReason,
      actions: (escalatePlan.actions ?? []).map(a => ({
        action_type: a.action_type,
        target:      a.target,
        parameters:  a.parameters ?? {},
      })),
    })
    setEscalatePlan(null); setEscalateReason('')
  }

  const saveEdit = (modifiedPlan) => {
    setEditedPlans(prev => ({ ...prev, [modifiedPlan.plan_id]: modifiedPlan }))
    setEditingPlan(null)
  }

  return (
    <div>
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1 text-xs text-theme-secondary hover:text-blue-400 transition-colors mb-4"
      >
        <ChevronLeft size={14}/> Back
      </button>
      <h1 className="text-base font-semibold text-theme-primary mb-5">Plan Review</h1>

      {/* Locked banner (resolved or not owner) */}
      {lockedReason && (
        <div className="mb-4 flex items-start gap-2 p-3 rounded-lg bg-red-950/30 border border-red-700/40 text-xs">
          <Lock size={14} className="text-red-400 mt-0.5 shrink-0" />
          <div className="flex-1">
            <p className="text-red-300 font-medium">
              {isResolved ? 'Alert already resolved' : 'Plan actions are locked'}
            </p>
            <p className="text-red-400/70 mt-0.5">{lockedReason}</p>
          </div>
          {/* Allow the assigned analyst to replan even from a rejected/plans_generated state */}
          {!isResolved && isMyAlert && (
            <button
              onClick={() => setShowReplan(true)}
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 shrink-0 transition-colors"
            >
              <RefreshCw size={11} /> Replan
            </button>
          )}
        </div>
      )}

      {/* Analyst destructive-actions warning */}
      {isAnalyst && canAct && plans.some(p => (p.actions ?? []).some(a => DESTRUCTIVE.has(a.action_type))) && (
        <div className="mb-4 flex items-start gap-2 p-3 rounded-lg bg-amber-900/20 border border-amber-700/40 text-xs">
          <AlertTriangle size={14} className="text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-amber-300 font-medium">Destructive actions require elevated approval</p>
            <p className="text-amber-400/70 mt-0.5">
              Plans with firewall changes, host isolation, or credential rotation must be escalated to a Senior Analyst or Admin.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {plans.map((plan) => {
          const actions        = plan.actions ?? []
          const hasDestructive = actions.some(a => DESTRUCTIVE.has(a.action_type))
          const isBeingEdited  = editingPlan === plan.plan_id
          const wasEdited      = !!editedPlans[plan.plan_id]

          return (
            <Card key={plan.plan_id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle>{plan.automation_tier}</CardTitle>
                  {/* Modify button — only when canAct and not editing */}
                  {canAct && !isBeingEdited && (
                    <button
                      onClick={() => setEditingPlan(plan.plan_id)}
                      className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      title="Modify plan actions before approving"
                    >
                      <Pencil size={11} /> {wasEdited ? 'Re-edit' : 'Modify'}
                    </button>
                  )}
                </div>
                <div className="flex gap-1.5 mt-1">
                  <Badge variant="priority" value={plan.risk_level}>{plan.risk_level}</Badge>
                  <span className="text-xs text-theme-muted">
                    {plan.confidence != null ? `${(plan.confidence * 100).toFixed(0)}% conf.` : ''}
                  </span>
                  {wasEdited && (
                    <span className="text-[10px] text-blue-400 font-medium uppercase tracking-wide">modified</span>
                  )}
                </div>
              </CardHeader>

              {isBeingEdited ? (
                /* ── Editor mode ── */
                <PlanEditor
                  plan={plan}
                  onSave={saveEdit}
                  onCancel={() => setEditingPlan(null)}
                />
              ) : (
                <>
                  <p className="text-xs text-theme-secondary mb-3">{plan.rationale ?? plan.description}</p>

                  <ul className="space-y-1.5 mb-4">
                    {actions.map((a, i) => (
                      <li key={i} className="text-xs flex items-start gap-2 text-theme-secondary">
                        <span className="mt-0.5 shrink-0 text-blue-400">›</span>
                        <span>
                          <span className={`font-mono font-semibold ${DESTRUCTIVE.has(a.action_type) ? 'text-red-400' : 'text-theme-primary'}`}>
                            {a.action_type}
                          </span>
                          {' '}<span className="text-theme-muted">→ {a.target}</span>
                          {DESTRUCTIVE.has(a.action_type) && (
                            <span className="ml-1 text-red-400 text-[10px] font-medium uppercase tracking-wide">destructive</span>
                          )}
                          {a.rationale && (
                            <p className="text-[11px] text-theme-muted mt-0.5 italic">{a.rationale}</p>
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>

                  <div className="flex gap-2 pt-3 border-t border-theme">
                    {!canAct ? (
                      <div className="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs text-theme-muted">
                        <Lock size={12} /> {isResolved ? 'Resolved' : 'Actions locked'}
                      </div>
                    ) : isAnalyst && hasDestructive ? (
                      <button
                        id={`escalate-plan-${plan.plan_id}`}
                        onClick={() => setEscalatePlan(plan)}
                        disabled={escalate.isPending}
                        className="flex-1 flex items-center justify-center gap-1.5 bg-amber-700 hover:bg-amber-600
                                   disabled:opacity-50 text-white text-xs font-semibold rounded py-1.5 transition-colors"
                      >
                        <ArrowUpCircle size={12}/> Escalate
                      </button>
                    ) : (
                      <button
                        id={`approve-plan-${plan.plan_id}`}
                        onClick={() => handleApprove(plan)}
                        disabled={approve.isPending}
                        className="flex-1 flex items-center justify-center gap-1.5 bg-emerald-700 hover:bg-emerald-600
                                   disabled:opacity-50 text-white text-xs font-semibold rounded py-1.5 transition-colors"
                      >
                        <CheckCircle size={12}/>
                        {approve.isPending ? 'Approving…' : 'Approve'}
                      </button>
                    )}
                    {canAct && (
                      <button
                        id={`reject-plan-${plan.plan_id}`}
                        onClick={() => setRejectPlan(plan.plan_id)}
                        className="flex-1 flex items-center justify-center gap-1.5 bg-theme-raised hover:bg-theme-base
                                   text-theme-secondary text-xs font-semibold rounded py-1.5 transition-colors"
                      >
                        <XCircle size={12}/> Reject
                      </button>
                    )}
                  </div>
                </>
              )}
            </Card>
          )
        })}
      </div>

      {/* Standard approve confirm dialog */}
      <ConfirmDialog
        open={!!pendingApprove}
        title="Approve Plan for Execution"
        description="This will queue the plan for automated execution. The actions listed will be carried out by the response engine."
        confirmLabel="Approve & Execute"
        cancelLabel="Cancel"
        onConfirm={() => { if (pendingApprove) { doApprove(pendingApprove); setPendingApprove(null) } }}
        onCancel={() => setPendingApprove(null)}
      >
        {pendingApprove && (
          <div className="rounded-lg border border-theme bg-theme-base p-3 space-y-1.5">
            <p className="text-xs font-medium text-theme-secondary mb-1">Actions to be executed:</p>
            {(pendingApprove.actions ?? []).map((a, i) => (
              <div key={i} className="text-xs flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0" />
                <span className="font-mono font-semibold text-theme-primary">{a.action_type}</span>
                <span className="text-theme-muted">→ {a.target}</span>
              </div>
            ))}
          </div>
        )}
      </ConfirmDialog>

      {/* Destructive confirm dialog (senior/admin) */}
      <ConfirmDialog
        open={!!confirmPlan}
        title="Approve Destructive Plan"
        description="This plan contains destructive actions that cannot be easily undone. Review carefully before confirming."
        confirmLabel="Yes, Approve Plan"
        cancelLabel="Go Back"
        danger
        onConfirm={() => { if (confirmPlan) { doApprove(confirmPlan); setConfirmPlan(null) } }}
        onCancel={() => setConfirmPlan(null)}
      >
        {confirmPlan && (
          <div className="rounded-lg border border-red-700/40 bg-red-950/30 p-3 space-y-2">
            <p className="text-xs font-semibold text-red-400 flex items-center gap-1.5">
              <AlertTriangle size={12} /> Destructive actions in this plan:
            </p>
            {(confirmPlan.actions ?? []).map((a, i) => (
              <div key={i} className={`text-xs flex items-center gap-2 ${DESTRUCTIVE.has(a.action_type) ? '' : 'opacity-40'}`}>
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DESTRUCTIVE.has(a.action_type) ? 'bg-red-500' : 'bg-theme-muted'}`} />
                <span className={`font-mono font-semibold ${DESTRUCTIVE.has(a.action_type) ? 'text-red-400' : 'text-theme-muted'}`}>
                  {a.action_type}
                </span>
                <span className="text-theme-muted">→ {a.target}</span>
              </div>
            ))}
          </div>
        )}
      </ConfirmDialog>

      {/* Escalation dialog */}
      {escalatePlan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-theme-surface border border-theme rounded-xl w-full max-w-md p-6 shadow-2xl">
            <div className="flex items-center gap-2 mb-4">
              <ArrowUpCircle size={18} className="text-amber-400" />
              <h2 className="text-sm font-semibold text-theme-primary">Escalate for Admin Approval</h2>
            </div>
            <p className="text-xs text-theme-secondary mb-3 leading-relaxed">
              This plan contains <span className="text-red-400 font-medium">destructive actions</span> requiring
              Senior Analyst or Admin approval. Provide a reason and notify them.
            </p>
            <div className="bg-theme-base border border-theme rounded-lg p-3 mb-3 space-y-1">
              {(escalatePlan.actions ?? []).filter(a => DESTRUCTIVE.has(a.action_type)).map((a, i) => (
                <div key={i} className="text-xs flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                  <span className="font-mono text-red-400">{a.action_type}</span>
                  <span className="text-theme-muted">→ {a.target}</span>
                </div>
              ))}
            </div>
            <textarea
              className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-xs text-theme-primary
                         focus:outline-none focus:border-blue-500 resize-none mb-3"
              rows={3}
              placeholder="Reason for escalation…"
              value={escalateReason}
              onChange={e => setEscalateReason(e.target.value)}
              autoFocus
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => { setEscalatePlan(null); setEscalateReason('') }}
                className="px-4 py-1.5 text-xs rounded bg-theme-raised text-theme-secondary hover:bg-theme-base transition-colors"
              >
                Cancel
              </button>
              <button
                id="confirm-escalate-btn"
                onClick={doEscalate}
                disabled={!escalateReason.trim() || escalate.isPending}
                className="px-4 py-1.5 text-xs rounded bg-amber-600 hover:bg-amber-500 disabled:opacity-50
                           text-white font-semibold transition-colors flex items-center gap-1.5"
              >
                {escalate.isPending ? <Spinner className="h-3 w-3" /> : <ArrowUpCircle size={12} />}
                Send Escalation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reject dialog — with optional replan offer */}
      {rejectPlan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-theme-surface border border-theme rounded-xl w-full max-w-md mx-4 p-6">
            <h2 className="text-sm font-semibold text-theme-primary mb-3">Reject Plan</h2>
            <textarea
              className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-xs text-theme-primary
                         focus:outline-none focus:border-blue-500 resize-none"
              rows={3}
              placeholder="Reason for rejection…"
              value={rejectReason}
              onChange={e => setRejectReason(e.target.value)}
              autoFocus
            />
            {/* Replan toggle */}
            <label className="flex items-center gap-2 mt-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={showReplan}
                onChange={e => setShowReplan(e.target.checked)}
                className="accent-blue-500"
              />
              <span className="text-xs text-theme-secondary">
                Also request a re-investigation (agent restrategizes with your feedback)
              </span>
            </label>
            {showReplan && (
              <textarea
                className="w-full mt-2 bg-theme-base border border-blue-600/40 rounded px-3 py-2 text-xs
                           text-theme-primary focus:outline-none focus:border-blue-500 resize-none"
                rows={2}
                placeholder="What should the agent do differently? (e.g. 'plans are too aggressive — prefer network isolation over full block')"
                value={replanReason}
                onChange={e => setReplanReason(e.target.value)}
              />
            )}
            <div className="flex justify-end gap-2 mt-3">
              <button onClick={() => { setRejectPlan(null); setRejectReason(''); setShowReplan(false); setReplanReason('') }}
                className="px-4 py-1.5 text-xs rounded bg-theme-raised text-theme-secondary">Cancel</button>
              <button
                id="confirm-reject-btn"
                onClick={() => {
                  reject.mutate({ plan_id: rejectPlan, reason: rejectReason })
                  if (showReplan && replanReason.trim()) {
                    replan.mutate(replanReason.trim())
                  }
                  setRejectPlan(null); setRejectReason(''); setShowReplan(false); setReplanReason('')
                }}
                className="px-4 py-1.5 text-xs rounded bg-red-700 hover:bg-red-600 text-white font-semibold flex items-center gap-1.5"
              >
                {showReplan && replanReason.trim()
                  ? <><XCircle size={12} /> Reject & Replan</>
                  : <><XCircle size={12} /> Reject</>}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Standalone replan dialog (triggered from locked-state banner) */}
      {!rejectPlan && showReplan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-theme-surface border border-theme rounded-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center gap-2 mb-4">
              <RefreshCw size={16} className="text-blue-400" />
              <h2 className="text-sm font-semibold text-theme-primary">Request Re-investigation</h2>
            </div>
            <p className="text-xs text-theme-secondary mb-3">
              Tell the agent what was wrong with the previous plans and how to adjust its strategy.
            </p>
            <textarea
              className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-xs text-theme-primary
                         focus:outline-none focus:border-blue-500 resize-none"
              rows={4}
              placeholder="e.g. 'Plans were too aggressive — the affected server is production-critical. Prefer deep inspection before any blocking actions.'"
              value={replanReason}
              onChange={e => setReplanReason(e.target.value)}
              autoFocus
            />
            <div className="flex justify-end gap-2 mt-3">
              <button onClick={() => { setShowReplan(false); setReplanReason('') }}
                className="px-4 py-1.5 text-xs rounded bg-theme-raised text-theme-secondary">Cancel</button>
              <button
                id="confirm-replan-btn"
                onClick={() => {
                  if (replanReason.trim()) {
                    replan.mutate(replanReason.trim())
                    setShowReplan(false); setReplanReason('')
                  }
                }}
                disabled={!replanReason.trim() || replan.isPending}
                className="px-4 py-1.5 text-xs rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50
                           text-white font-semibold flex items-center gap-1.5"
              >
                {replan.isPending ? <Spinner className="h-3 w-3" /> : <RefreshCw size={12} />}
                Replan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}