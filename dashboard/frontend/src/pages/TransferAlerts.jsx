import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowRightLeft, CheckCircle, XCircle, Clock, ChevronRight,
  RefreshCw, User, AlertCircle, X, Search
} from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'
import { useAuthStore } from '../store/auth'
import { useToastStore } from '../components/ui/Toast'
import { useWebSocket } from '../hooks/useWebSocket'

// ── Data hooks ────────────────────────────────────────────────────────────────

function useTransfers(statusFilter) {
  return useQuery({
    queryKey: ['transfers', statusFilter],
    queryFn: () => api.get('/transfers', { params: statusFilter ? { status: statusFilter } : {} }).then(r => r.data),
    staleTime: 10_000,
    refetchInterval: 20_000,
  })
}

function useAnalysts() {
  return useQuery({
    queryKey: ['admin', 'analysts'],
    queryFn: () => api.get('/admin/analysts').then(r => r.data.analysts),
    staleTime: 60_000,
  })
}

function useRequestTransfer() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (body) => api.post('/transfers', body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['transfers'] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast({ type: 'success', title: 'Transfer requested', message: 'The recipient will be notified' })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Transfer failed', message: err?.response?.data?.detail || 'Could not create transfer request' })
    },
  })
}

function useRespondTransfer() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ transferId, accept }) =>
      api.post(`/transfers/${transferId}/respond`, { accept }).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['transfers'] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alerts', 'my'] })
      toast({
        type: data.accepted ? 'success' : 'info',
        title: data.accepted ? 'Transfer accepted' : 'Transfer declined',
        message: data.accepted
          ? `Alert ${data.alert_id} is now assigned to you`
          : 'Transfer request declined',
      })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Action failed', message: err?.response?.data?.detail || 'Could not respond to transfer' })
    },
  })
}

function useCancelTransfer() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (transferId) => api.delete(`/transfers/${transferId}`).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['transfers'] })
      toast({ type: 'success', title: 'Transfer cancelled' })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Cancel failed', message: err?.response?.data?.detail || 'Could not cancel' })
    },
  })
}

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_STYLE = {
  pending:   'bg-amber-950/60 text-amber-300 border border-amber-700/40',
  accepted:  'bg-emerald-950/60 text-emerald-300 border border-emerald-700/40',
  declined:  'bg-red-950/60 text-red-300 border border-red-700/40',
  cancelled: 'bg-slate-700/60 text-slate-400 border border-slate-600/40',
}
const STATUS_ICON = {
  pending:   <Clock size={11} />,
  accepted:  <CheckCircle size={11} />,
  declined:  <XCircle size={11} />,
  cancelled: <X size={11} />,
}

function TransferStatusBadge({ status }) {
  return (
    <span className={cn('inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full', STATUS_STYLE[status] ?? STATUS_STYLE.cancelled)}>
      {STATUS_ICON[status]}
      {status}
    </span>
  )
}

// ── New Transfer Dialog ───────────────────────────────────────────────────────

function NewTransferDialog({ onClose, analysts, currentUser }) {
  const [alertId, setAlertId] = useState('')
  const [toUser, setToUser] = useState('')
  const [reason, setReason] = useState('')
  const requestTransfer = useRequestTransfer()

  const { data: myAlerts } = useQuery({
    queryKey: ['alerts', 'my', { priority: '', status: '' }],
    queryFn: () => api.get('/alerts/my').then(r => r.data),
    staleTime: 15_000,
  })

  const assignedAlerts = (myAlerts?.items ?? []).filter(
    a => !['approved', 'rejected', 'closed', 'executed'].includes(a.approval_status)
  )

  const handleSubmit = (e) => {
    e.preventDefault()
    requestTransfer.mutate({ alert_id: alertId, to_user: toUser, reason }, {
      onSuccess: () => onClose(),
    })
  }

  const otherAnalysts = (analysts ?? []).filter(a => a.id !== currentUser)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-theme-surface border border-theme rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-6 pt-6 pb-4">
          <h2 className="text-sm font-semibold text-theme-primary flex items-center gap-2">
            <ArrowRightLeft size={14} className="text-blue-400" /> Request Alert Transfer
          </h2>
          <button onClick={onClose} className="text-theme-muted hover:text-theme-primary transition-colors">
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 pb-6 space-y-4">
          {/* Alert to transfer */}
          <div>
            <label className="text-xs text-theme-secondary block mb-1.5">Alert to Transfer</label>
            <select
              id="transfer-alert-select"
              value={alertId}
              onChange={e => setAlertId(e.target.value)}
              className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
              required
            >
              <option value="">Select an alert…</option>
              {assignedAlerts.map(a => (
                <option key={a.alert_id} value={a.alert_id}>
                  {a.classification} ({a.priority})
                </option>
              ))}
            </select>
            {assignedAlerts.length === 0 && (
              <p className="text-xs text-amber-400 mt-1">No active alerts assigned to you</p>
            )}
          </div>

          {/* Recipient */}
          <div>
            <label className="text-xs text-theme-secondary block mb-1.5">Transfer To</label>
            <select
              id="transfer-to-select"
              value={toUser}
              onChange={e => setToUser(e.target.value)}
              className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
              required
            >
              <option value="">Select analyst…</option>
              {otherAnalysts.map(a => (
                <option key={a.id} value={a.id}>{a.name ?? a.id}</option>
              ))}
            </select>
          </div>

          {/* Reason */}
          <div>
            <label className="text-xs text-theme-secondary block mb-1.5">Reason for Transfer</label>
            <textarea
              id="transfer-reason"
              value={reason}
              onChange={e => setReason(e.target.value)}
              rows={3}
              placeholder="Explain why you're transferring this alert…"
              className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500 resize-none"
              required
            />
          </div>

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 text-xs rounded bg-theme-raised text-theme-secondary hover:bg-theme-base transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              id="submit-transfer-btn"
              disabled={requestTransfer.isPending || !alertId || !toUser || !reason.trim()}
              className="px-4 py-1.5 text-xs rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold transition-colors flex items-center gap-1.5"
            >
              <ArrowRightLeft size={12} />
              {requestTransfer.isPending ? 'Sending…' : 'Send Request'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function TransferAlerts() {
  const navigate = useNavigate()
  const username = useAuthStore(s => s.userName)
  const toast = useToastStore(s => s.push)
  const qc = useQueryClient()

  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [showNewDialog, setShowNewDialog] = useState(false)

  const { data, isLoading, refetch, isFetching } = useTransfers(statusFilter)
  const { data: analysts } = useAnalysts()
  const respond = useRespondTransfer()
  const cancel = useCancelTransfer()

  // Live updates via WebSocket
  const onMessage = useCallback((msg) => {
    if (['transfer_request', 'transfer_responded'].includes(msg.type)) {
      qc.invalidateQueries({ queryKey: ['transfers'] })
      if (msg.type === 'transfer_request' && msg.to_user === username) {
        toast({
          type: 'info',
          title: '↔ Transfer Request',
          message: `${msg.from_user} wants to transfer "${msg.alert_classification}" to you`,
        })
      }
    }
  }, [qc, toast, username])

  useWebSocket('/ws/alerts', onMessage)

  if (isLoading) return <PageSpinner />

  const searchLower = search.trim().toLowerCase()
  const transfers = (data?.items ?? []).filter(t => {
    if (!searchLower) return true
    return (
      t.classification?.toLowerCase().includes(searchLower) ||
      t.alert_id?.toLowerCase().includes(searchLower) ||
      t.from_user?.toLowerCase().includes(searchLower) ||
      t.to_user?.toLowerCase().includes(searchLower) ||
      t.reason?.toLowerCase().includes(searchLower)
    )
  })
  const incoming = transfers.filter(t => t.to_user === username && t.status === 'pending')

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-base font-semibold text-theme-primary flex items-center gap-2">
            <ArrowRightLeft size={15} className="text-blue-400" />
            Alert Transfers
            {incoming.length > 0 && (
              <span className="bg-amber-500 text-white text-[10px] font-bold rounded-full px-1.5 py-0.5 leading-none">
                {incoming.length} pending
              </span>
            )}
          </h1>
          <p className="text-xs text-theme-muted mt-0.5">Peer-to-peer alert handoff requests</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-2 text-theme-muted" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search classification, user…"
              className="bg-theme-raised border border-theme text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-48"
            />
          </div>
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-theme-raised border border-theme text-xs text-theme-primary rounded px-2.5 py-1.5 focus:outline-none"
          >
            <option value="">All statuses</option>
            {['pending', 'accepted', 'declined', 'cancelled'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-1.5 text-theme-muted hover:text-theme-primary transition-colors disabled:opacity-50"
          >
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
          </button>
          <button
            id="new-transfer-btn"
            onClick={() => setShowNewDialog(true)}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-3 py-1.5 rounded transition-colors"
          >
            <ArrowRightLeft size={12} /> New Transfer
          </button>
        </div>
      </div>

      {/* Incoming pending — prominent callout */}
      {incoming.length > 0 && (
        <div className="bg-amber-950/20 border border-amber-700/40 rounded-lg overflow-hidden">
          <div className="px-4 py-2.5 border-b border-amber-800/30 flex items-center gap-2">
            <AlertCircle size={13} className="text-amber-400" />
            <p className="text-xs font-semibold text-amber-300">Pending incoming transfers — your response required</p>
          </div>
          {incoming.map(t => (
            <div key={t.id} className="px-4 py-3 flex items-center gap-3 border-b border-amber-900/20 last:border-0">
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-theme-primary">
                  {t.classification}
                  <Badge variant="priority" value={t.priority} className="ml-2">{t.priority}</Badge>
                </p>
                <p className="text-xs text-theme-muted mt-0.5">
                  From <span className="text-blue-400 font-medium">{t.from_user}</span>
                  {' · '}<span className="italic">{t.reason}</span>
                </p>
                <p className="text-xs text-theme-muted mt-0.5">{timeAgo(t.created_at)}</p>
              </div>
              <div className="flex gap-2 shrink-0">
                <button
                  id={`accept-transfer-${t.id}`}
                  onClick={() => respond.mutate({ transferId: t.id, accept: true })}
                  disabled={respond.isPending}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 text-white rounded transition-colors disabled:opacity-50"
                >
                  <CheckCircle size={11} /> Accept
                </button>
                <button
                  id={`decline-transfer-${t.id}`}
                  onClick={() => respond.mutate({ transferId: t.id, accept: false })}
                  disabled={respond.isPending}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold bg-theme-raised hover:bg-theme-base text-theme-secondary rounded transition-colors disabled:opacity-50"
                >
                  <XCircle size={11} /> Decline
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Full history table */}
      <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-theme-raised text-theme-secondary text-left">
              {['Alert', 'Priority', 'From', 'To', 'Reason', 'Status', 'Time', ''].map(h => (
                <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {transfers.length === 0 ? (
              <tr>
                <td colSpan={8}>
                  <div className="flex flex-col items-center justify-center py-16 gap-2">
                    <ArrowRightLeft size={28} className="text-theme-muted opacity-30" />
                    <p className="text-sm text-theme-muted">
                      {search.trim() ? 'No transfers match your search' : 'No transfer requests yet'}
                    </p>
                    {!search.trim() && (
                      <p className="text-xs text-theme-muted opacity-60">
                        Use "New Transfer" to handoff an alert to a colleague
                      </p>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              transfers.map(t => (
                <tr
                  key={t.id}
                  className="border-t border-theme hover:bg-theme-raised transition-colors"
                >
                  <td
                    className="px-4 py-3 text-theme-primary font-mono cursor-pointer hover:text-blue-400 transition-colors"
                    onClick={() => navigate(`/alerts/${t.alert_id}`)}
                  >
                    <span className="flex items-center gap-1">
                      {t.classification}
                      <ChevronRight size={11} className="text-theme-muted" />
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="priority" value={t.priority}>{t.priority}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn('flex items-center gap-1', t.from_user === username ? 'text-blue-400' : 'text-theme-secondary')}>
                      <User size={11} /> {t.from_user}
                      {t.from_user === username && <span className="text-theme-muted">(you)</span>}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn('flex items-center gap-1', t.to_user === username ? 'text-blue-400' : 'text-theme-secondary')}>
                      <User size={11} /> {t.to_user}
                      {t.to_user === username && <span className="text-theme-muted">(you)</span>}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-theme-muted max-w-50">
                    <span className="truncate block" title={t.reason}>{t.reason}</span>
                  </td>
                  <td className="px-4 py-3">
                    <TransferStatusBadge status={t.status} />
                  </td>
                  <td className="px-4 py-3 text-theme-muted whitespace-nowrap">
                    {timeAgo(t.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    {/* Actions: respond if incoming pending, cancel if outgoing pending */}
                    {t.status === 'pending' && t.to_user === username && (
                      <div className="flex gap-1">
                        <button
                          onClick={() => respond.mutate({ transferId: t.id, accept: true })}
                          disabled={respond.isPending}
                          className="p-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded transition-colors disabled:opacity-50"
                          title="Accept"
                        >
                          <CheckCircle size={13} />
                        </button>
                        <button
                          onClick={() => respond.mutate({ transferId: t.id, accept: false })}
                          disabled={respond.isPending}
                          className="p-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded transition-colors disabled:opacity-50"
                          title="Decline"
                        >
                          <XCircle size={13} />
                        </button>
                      </div>
                    )}
                    {t.status === 'pending' && t.from_user === username && (
                      <button
                        onClick={() => cancel.mutate(t.id)}
                        disabled={cancel.isPending}
                        className="p-1 bg-theme-raised hover:bg-theme-base text-theme-muted hover:text-red-400 rounded transition-colors disabled:opacity-50"
                        title="Cancel transfer"
                      >
                        <X size={13} />
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* New transfer dialog */}
      {showNewDialog && (
        <NewTransferDialog
          onClose={() => setShowNewDialog(false)}
          analysts={analysts}
          currentUser={username}
        />
      )}
    </div>
  )
}
