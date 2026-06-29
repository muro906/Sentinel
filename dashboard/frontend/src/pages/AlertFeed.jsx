import { useCallback, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldOff, History, Zap, ArrowUpCircle, User, Clock, Search } from 'lucide-react'
import { useAlerts } from "../hooks/useAlerts";
import { useWebSocket } from "../hooks/useWebSocket";
import { useAlertsStore } from '../store/alerts'
import { Badge } from '../components/ui/Badge'
import { timeAgo, cn } from '../lib/utils'
import { PageSpinner } from '../components/ui/Spinner'
import { useToastStore } from '../components/ui/Toast'
import { useAuthStore } from '../store/auth'

// Statuses that mean the alert is still active / needs attention
const ACTIVE_STATUSES = new Set(['received', 'triaged', 'plans_generated', 'pending'])
// Statuses that mean the alert is resolved
const HISTORY_STATUSES = new Set(['approved', 'rejected', 'executed', 'closed'])

const ROW_PRIORITY = {
    critical: 'border-l-2 border-l-red-500',
    high:     'border-l-2 border-l-amber-500',
    medium:   'border-l-2 border-l-blue-500',
    low:      '',
}

function isNew(isoDate) {
    return Date.now() - new Date(isoDate).getTime() < 60_000
}

function formatDateTime(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
    })
}

// ── Escalation Notification Banner ────────────────────────────────────────────
function EscalationBanner({ escalations, onDismiss, navigate }) {
    if (escalations.length === 0) return null
    return (
        <div className="rounded-lg border border-amber-600/40 bg-amber-950/30 divide-y divide-amber-800/30 mb-4">
            <div className="px-4 py-2.5 flex items-center gap-2">
                <ArrowUpCircle size={14} className="text-amber-400 shrink-0" />
                <p className="text-xs font-semibold text-amber-300 flex-1">
                    Escalation Requests — require your review
                </p>
                <button
                    onClick={onDismiss}
                    className="text-xs text-amber-500 hover:text-amber-300 transition-colors"
                >
                    Dismiss all
                </button>
            </div>
            {escalations.map((e, i) => (
                <div
                    key={i}
                    className="px-4 py-2.5 flex items-center gap-3 hover:bg-amber-900/20 transition-colors cursor-pointer"
                    onClick={() => navigate(`/alerts/${e.alert_id}/plans`)}
                >
                    <div className="flex-1 min-w-0">
                        <p className="text-xs text-amber-200 font-medium truncate">{e.classification}</p>
                        <p className="text-xs text-amber-400/70 mt-0.5">
                            Escalated by <span className="font-semibold">{e.requested_by}</span>
                            {' · '}{e.reason}
                        </p>
                    </div>
                    <Badge variant="priority" value={e.priority}>{e.priority}</Badge>
                    <ArrowUpCircle size={12} className="text-amber-400 shrink-0" />
                </div>
            ))}
        </div>
    )
}

export default function AlertFeed() {
    const [searchParams] = useSearchParams()
    const [tab, setTab] = useState(searchParams.get('tab') === 'history' ? 'history' : 'active')
    const [priority, setPriority] = useState(searchParams.get('priority') || '')
    const [search, setSearch] = useState('')
    const navigate = useNavigate()
    const qc = useQueryClient()
    const push = useAlertsStore(state => state.pushNotification)
    const toast = useToastStore(s => s.push)
    const role = useAuthStore(s => s.role)
    const canSeeEscalations = role === 'admin' || role === 'senior_analyst'

    // All alerts — we split on the frontend so both tabs stay in sync
    const { data, isLoading } = useAlerts({ priority: priority || undefined })

    // Escalation requests from analysts (for senior/admin only)
    const [escalations, setEscalations] = useState([])

    const onMessage = useCallback((msg) => {
        if (msg.type === 'new_plans') {
            push({ ...msg, received_at: new Date().toISOString() })
            qc.invalidateQueries({ queryKey: ['alerts'] })
            toast({ type: 'warning', title: 'New alert plans ready', message: `Alert ${msg.alert_id} has new plans awaiting review.` })
        }
        if (msg.type === 'new_alert') {
            push({ ...msg, received_at: new Date().toISOString() })
            qc.invalidateQueries({ queryKey: ['alerts'] })
            toast({ type: 'info', title: 'New alert received', message: `Alert ${msg.alert_id} (${msg.classification}) requires investigation.` })
        }
        if (msg.type === 'investigation_started') {
            qc.invalidateQueries({ queryKey: ['alerts'] })
            toast({ type: 'info', title: 'Investigation started', message: `Alert ${msg.alert_id} investigation in progress.` })
        }

        // Show escalation requests to senior analysts and admins
        if (msg.type === 'escalation_request' && canSeeEscalations) {
            setEscalations(prev => [...prev, msg])
            toast({
                type: 'warning',
                title: '⬆ Escalation Request',
                message: `${msg.requested_by} needs approval on a destructive plan for alert ${msg.alert_id}`
            })
        }

        // Refresh when a plan is approved / assigned
        if (['plan_approved', 'alert_assigned', 'alert_unassigned'].includes(msg.type)) {
            qc.invalidateQueries({ queryKey: ['alerts'] })
        }
    }, [push, qc, toast, canSeeEscalations])

    useWebSocket('/ws/alerts', onMessage)

    if (isLoading) return <PageSpinner />

    const allAlerts = data?.items ?? []
    const activeAlerts  = allAlerts.filter(a => ACTIVE_STATUSES.has(a.approval_status))
    const historyAlerts = allAlerts.filter(a => HISTORY_STATUSES.has(a.approval_status))

    const shownAlerts = tab === 'active' ? activeAlerts : historyAlerts

    // Apply priority filter and search client-side
    const searchLower = search.trim().toLowerCase()
    const filtered = shownAlerts.filter(a => {
      const matchesPriority = !priority || a.priority === priority
      const matchesSearch = !searchLower ||
        a.classification?.toLowerCase().includes(searchLower) ||
        a.alert_id?.toLowerCase().includes(searchLower) ||
        a.src_ip?.toLowerCase().includes(searchLower) ||
        a.dst_ip?.toLowerCase().includes(searchLower) ||
        a.assigned_to?.toLowerCase().includes(searchLower)
      return matchesPriority && matchesSearch
    })

    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-base font-semibold text-theme-primary">Alert Feed</h1>
                    <p className="text-xs text-theme-muted mt-0.5">
                        {activeAlerts.length} active · {historyAlerts.length} resolved
                    </p>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
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
                    {/* Priority filter */}
                    <select
                        value={priority}
                        onChange={e => setPriority(e.target.value)}
                        className="bg-theme-raised border border-theme text-xs text-theme-primary rounded px-2 py-1.5"
                    >
                        <option value="">All priorities</option>
                        {['critical', 'high', 'medium', 'low'].map(p => (
                            <option key={p} value={p}>{p}</option>
                        ))}
                    </select>

                    {/* Active / History tabs */}
                    <div className="flex bg-theme-surface border border-theme rounded-lg overflow-hidden">
                        <button
                            onClick={() => setTab('active')}
                            className={cn(
                                'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors',
                                tab === 'active'
                                    ? 'bg-blue-600 text-blue-100'
                                    : 'text-theme-secondary hover:text-theme-primary'
                            )}
                        >
                            <Zap size={11} />
                            Active
                            {activeAlerts.length > 0 && (
                                <span className={cn(
                                    'rounded-full px-1.5 py-0.5 text-[10px] font-bold leading-none',
                                    tab === 'active' ? 'bg-blue-400/30 text-blue-100' : 'bg-red-500 text-white'
                                )}>
                                    {activeAlerts.length}
                                </span>
                            )}
                        </button>
                        <button
                            onClick={() => setTab('history')}
                            className={cn(
                                'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors',
                                tab === 'history'
                                    ? 'bg-blue-600 text-blue-100'
                                    : 'text-theme-secondary hover:text-theme-primary'
                            )}
                        >
                            <History size={11} />
                            History
                            {historyAlerts.length > 0 && (
                                <span className={cn(
                                    'rounded-full px-1.5 py-0.5 text-[10px] font-bold leading-none',
                                    tab === 'history' ? 'bg-blue-400/30 text-blue-100' : 'bg-theme-muted text-theme-primary'
                                )}>
                                    {historyAlerts.length}
                                </span>
                            )}
                        </button>
                    </div>
                </div>
            </div>

            {/* Escalation banners (senior/admin only) */}
            {canSeeEscalations && (
                <EscalationBanner
                    escalations={escalations}
                    onDismiss={() => setEscalations([])}
                    navigate={navigate}
                />
            )}

            {/* Alert table */}
            <div className="rounded-lg overflow-hidden bg-theme-surface border border-theme">
                <table className="w-full text-xs">
                    <thead>
                        <tr className="bg-theme-raised text-theme-muted text-left">
                            {tab === 'active' ? (
                                ['Time', 'Classification', 'Priority', 'Src IP', 'Dst IP', 'Port', 'Status', 'Assigned To'].map(h => (
                                    <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
                                ))
                            ) : (
                                ['Classification', 'Priority', 'Outcome', 'Resolved By', 'Resolved At', 'Assigned To'].map(h => (
                                    <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
                                ))
                            )}
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.length === 0 && (
                            <tr>
                                <td colSpan={8}>
                                    <div className="flex flex-col items-center justify-center py-16 gap-2">
                                        <ShieldOff size={32} className="text-theme-muted opacity-40" />
                                        <p className="text-sm text-theme-muted">
                                            {search.trim() ? 'No alerts match your search' : tab === 'active' ? 'No active alerts' : 'No resolved alerts yet'}
                                        </p>
                                        <p className="text-xs text-theme-muted opacity-60">
                                            {tab === 'active'
                                                ? 'All alerts have been resolved'
                                                : 'Approved or executed alerts will appear here'}
                                        </p>
                                    </div>
                                </td>
                            </tr>
                        )}
                        {filtered.map(a => (
                            <tr
                                key={a.alert_id}
                                onClick={() => navigate(`/alerts/${a.alert_id}`)}
                                className={cn(
                                    'border-t border-theme hover:bg-theme-raised cursor-pointer transition-colors',
                                    ROW_PRIORITY[a.priority]
                                )}
                            >
                                {tab === 'active' ? (
                                    <>
                                        <td className="px-4 py-2.5 text-theme-muted whitespace-nowrap">
                                            <span className="flex items-center gap-1.5">
                                                {isNew(a.created_at) && (
                                                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse shrink-0" />
                                                )}
                                                {timeAgo(a.created_at)}
                                            </span>
                                        </td>
                                        <td className="px-4 py-2.5 text-theme-primary font-mono">{a.classification}</td>
                                        <td className="px-4 py-2.5">
                                            <Badge variant="priority" value={a.priority}>{a.priority}</Badge>
                                        </td>
                                        <td className="px-4 py-2.5 text-theme-secondary font-mono">{a.src_ip || '—'}</td>
                                        <td className="px-4 py-2.5 text-theme-secondary font-mono">{a.dst_ip || '—'}</td>
                                        <td className="px-4 py-2.5 text-theme-secondary font-mono">{a.dst_port || '—'}</td>
                                        <td className="px-4 py-2.5">
                                            <Badge variant="status" value={a.approval_status}>{a.approval_status}</Badge>
                                        </td>
                                        <td className="px-4 py-2.5">
                                            {a.assigned_to
                                                ? <span className="flex items-center gap-1 text-theme-secondary">
                                                    <User size={11} className="text-emerald-400" />{a.assigned_to}
                                                  </span>
                                                : <span className="text-theme-muted italic">Unassigned</span>
                                            }
                                        </td>
                                    </>
                                ) : (
                                    <>
                                        <td className="px-4 py-2.5 text-theme-primary font-mono">{a.classification}</td>
                                        <td className="px-4 py-2.5">
                                            <Badge variant="priority" value={a.priority}>{a.priority}</Badge>
                                        </td>
                                        <td className="px-4 py-2.5">
                                            <Badge variant="status" value={a.approval_status}>{a.approval_status}</Badge>
                                        </td>
                                        <td className="px-4 py-2.5">
                                            {a.approved_by
                                                ? <span className="flex items-center gap-1 text-emerald-400">
                                                    <User size={11} />{a.approved_by}
                                                  </span>
                                                : <span className="text-theme-muted">—</span>
                                            }
                                        </td>
                                        <td className="px-4 py-2.5 text-theme-secondary">
                                            <span className="flex items-center gap-1">
                                                <Clock size={11} className="text-theme-muted shrink-0" />
                                                {formatDateTime(a.approved_at)}
                                            </span>
                                        </td>
                                        <td className="px-4 py-2.5 text-theme-secondary">
                                            {a.assigned_to || '—'}
                                        </td>
                                    </>
                                )}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
