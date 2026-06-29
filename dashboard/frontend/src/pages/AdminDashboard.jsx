import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users, ChevronRight, UserX, UserCheck,
  CheckCircle, XCircle, Trash2, Shield, Clock
} from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'
import { useToastStore } from '../components/ui/Toast'

const PRIORITY_RING = {
  critical: 'border-l-2 border-l-red-500',
  high:     'border-l-2 border-l-amber-500',
  medium:   'border-l-2 border-l-blue-500',
  low:      '',
}

// ── Data hooks ────────────────────────────────────────────────────────────────

function useAnalysts() {
  return useQuery({
    queryKey: ['admin', 'analysts'],
    queryFn: () => api.get('/admin/analysts').then(r => r.data.analysts),
    staleTime: 30_000,
  })
}

function useAdminAlerts() {
  return useQuery({
    queryKey: ['alerts', {}],
    queryFn: () => api.get('/alerts').then(r => r.data),
    staleTime: 15_000,
  })
}

function useAssignAlert() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ alertId, analystId }) =>
      api.post(`/alerts/${alertId}/assign`, { analyst_id: analystId }).then(r => r.data),
    onSuccess: (_, { analystId, analysts }) => {
      qc.invalidateQueries({ queryKey: ['alerts'], refetchType: 'all' })
      qc.invalidateQueries({ queryKey: ['admin', 'analysts'] })
      const name = analysts?.find(a => a.id === analystId)?.name ?? analystId
      toast({ type: 'success', title: analystId ? 'Alert assigned' : 'Alert unassigned', message: analystId ? `Assigned to ${name}` : 'Alert is now unassigned' })
    },
    onError: () => toast({ type: 'error', title: 'Assignment failed', message: 'Could not assign alert.' }),
  })
}

function usePendingUsers() {
  return useQuery({
    queryKey: ['admin', 'pending-users'],
    queryFn: () => api.get('/auth/pending-users').then(r => r.data.users),
    refetchInterval: 15_000,
  })
}

function useApproveUser() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ userId, role }) =>
      api.post(`/auth/approve-user/${userId}`, { role }).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['admin', 'pending-users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'analysts'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      toast({ type: 'success', title: 'User approved', message: `${data.username} can now log in as ${data.role.replace('_', ' ')}` })
    },
    onError: () => toast({ type: 'error', title: 'Approval failed', message: 'Could not approve user' }),
  })
}

function useDenyUser() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ userId, reason }) =>
      api.post(`/auth/deny-user/${userId}`, { reason }).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['admin', 'pending-users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      toast({ type: 'info', title: 'Registration denied', message: `${data.username}'s account request was rejected` })
    },
    onError: () => toast({ type: 'error', title: 'Action failed', message: 'Could not deny user' }),
  })
}

function useAllUsers() {
  return useQuery({
    queryKey: ['admin', 'users'],
    queryFn: () => api.get('/admin/users').then(r => r.data.users),
    staleTime: 30_000,
  })
}

function useDeleteUser() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (username) => api.delete(`/admin/users/${username}`).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'analysts'] })
      toast({ type: 'success', title: 'User deactivated', message: `${data.username} account deactivated` })
    },
    onError: (err) => toast({ type: 'error', title: 'Delete failed', message: err?.response?.data?.detail || 'Could not delete user' }),
  })
}

function useUpdateUserRole() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ username, role }) =>
      api.post(`/admin/users/${username}/role`, { role }).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'analysts'] })
      toast({ type: 'success', title: 'Role updated', message: `${data.username} is now ${data.role.replace('_', ' ')}` })
    },
    onError: () => toast({ type: 'error', title: 'Update failed', message: 'Could not update role' }),
  })
}

function useRoleChangeRequests() {
  return useQuery({
    queryKey: ['admin', 'role-requests'],
    queryFn: () => api.get('/admin/role-requests?status=pending').then(r => r.data.requests),
    refetchInterval: 15_000,
  })
}

function useProcessRoleRequest() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: ({ requestId, approve, notes }) =>
      api.post(`/admin/role-requests/${requestId}/process`, { approve, notes }).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['admin', 'role-requests'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'analysts'] })
      toast({ type: 'success', title: data.status === 'approved' ? 'Request approved' : 'Request denied', message: `${data.username}'s role request ${data.status}` })
    },
    onError: (err) => toast({ type: 'error', title: 'Action failed', message: err?.response?.data?.detail || 'Could not process request' }),
  })
}

// ── Approvals Tab ─────────────────────────────────────────────────────────────

const ROLES = [
  { value: 'analyst',        label: 'Analyst',        color: 'bg-blue-600 hover:bg-blue-500' },
  { value: 'senior_analyst', label: 'Senior Analyst',  color: 'bg-purple-600 hover:bg-purple-500' },
  { value: 'admin',          label: 'Admin',            color: 'bg-red-700 hover:bg-red-600' },
]

function ApprovalsTab({ pendingUsers, approveUser, denyUser }) {
  const [expandedUser, setExpandedUser] = useState(null)
  const [denyingUser, setDenyingUser]   = useState(null)
  const [denyReason, setDenyReason]     = useState('')

  const handleDeny = (userId) => {
    denyUser.mutate({ userId, reason: denyReason.trim() || undefined })
    setDenyingUser(null)
    setDenyReason('')
  }

  if (pendingUsers.length === 0) {
    return (
      <div className="bg-theme-surface border border-theme rounded-lg p-12 text-center">
        <UserCheck size={32} className="text-emerald-400 mx-auto mb-3 opacity-60" />
        <p className="text-sm font-medium text-theme-primary">No pending approvals</p>
        <p className="text-xs text-theme-muted mt-1">All registration requests have been reviewed</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {pendingUsers.map(user => (
        <div key={user.id} className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-full bg-amber-600/20 border border-amber-600/40 flex items-center justify-center text-sm font-bold text-amber-300">
                {user.username[0].toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-semibold text-theme-primary">{user.username}</p>
                <p className="text-xs text-theme-muted">{user.email}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1 text-xs text-theme-muted">
                <Clock size={11} />
                {timeAgo(user.requested_at)}
              </div>
              <span className="px-2 py-0.5 text-[10px] font-medium bg-amber-900/30 text-amber-400 border border-amber-700/40 rounded-full">
                Pending
              </span>
              <button
                onClick={() => setExpandedUser(expandedUser === user.id ? null : user.id)}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors"
              >
                {expandedUser === user.id ? 'Cancel' : 'Review'}
              </button>
            </div>
          </div>

          {expandedUser === user.id && (
            <div className="border-t border-theme px-4 py-3 bg-theme-base space-y-3">
              {denyingUser === user.id ? (
                /* Deny flow */
                <div className="space-y-2">
                  <p className="text-xs font-medium text-red-400">Deny registration for <span className="font-bold">{user.username}</span></p>
                  <textarea
                    className="w-full bg-theme-surface border border-theme rounded px-3 py-2 text-xs text-theme-primary focus:outline-none focus:border-red-500 resize-none"
                    rows={3}
                    placeholder="Reason for denial (optional, will be emailed to user)"
                    value={denyReason}
                    onChange={e => setDenyReason(e.target.value)}
                    autoFocus
                  />
                  <div className="flex gap-2 justify-end">
                    <button
                      onClick={() => { setDenyingUser(null); setDenyReason('') }}
                      className="px-3 py-1.5 text-xs rounded bg-theme-raised text-theme-secondary hover:bg-theme-surface transition-colors"
                    >
                      Back
                    </button>
                    <button
                      onClick={() => handleDeny(user.id)}
                      disabled={denyUser.isPending}
                      className="px-3 py-1.5 text-xs rounded bg-red-700 hover:bg-red-600 text-white font-semibold disabled:opacity-50 transition-colors"
                    >
                      Confirm Denial
                    </button>
                  </div>
                </div>
              ) : (
                /* Approve flow */
                <div className="space-y-2">
                  <p className="text-xs text-theme-muted">Assign a role and approve, or deny the request:</p>
                  <div className="flex items-center gap-2 flex-wrap">
                    {ROLES.map(r => (
                      <button
                        key={r.value}
                        onClick={() => { approveUser.mutate({ userId: user.id, role: r.value }); setExpandedUser(null) }}
                        disabled={approveUser.isPending}
                        className={`px-3 py-1.5 text-xs rounded text-white font-semibold disabled:opacity-50 transition-colors flex items-center gap-1.5 ${r.color}`}
                      >
                        <CheckCircle size={12} /> Approve as {r.label}
                      </button>
                    ))}
                    <button
                      onClick={() => setDenyingUser(user.id)}
                      className="px-3 py-1.5 text-xs rounded bg-theme-raised hover:bg-red-950/40 text-red-400 border border-red-800/40 font-medium transition-colors flex items-center gap-1.5"
                    >
                      <XCircle size={12} /> Deny
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function AdminDashboard() {
  const navigate = useNavigate()
  const [selectedAnalyst, setSelectedAnalyst] = useState(null)
  const [activeTab, setActiveTab]             = useState('alerts')

  const { data: analysts = [],       isLoading: loadingAnalysts }      = useAnalysts()
  const { data: alertData,           isLoading: loadingAlerts }        = useAdminAlerts()
  const { data: pendingUsers = [],   isLoading: loadingPending }       = usePendingUsers()
  const { data: allUsers = [],       isLoading: loadingUsers }         = useAllUsers()
  const { data: roleRequests = [],   isLoading: loadingRoleRequests }  = useRoleChangeRequests()

  const assign            = useAssignAlert()
  const approveUser       = useApproveUser()
  const denyUser          = useDenyUser()
  const deleteUser        = useDeleteUser()
  const updateRole        = useUpdateUserRole()
  const processRoleReq    = useProcessRoleRequest()

  if (loadingAnalysts || loadingAlerts || loadingPending || loadingUsers || loadingRoleRequests) {
    return <PageSpinner />
  }

  const alerts      = alertData?.items ?? []
  const unassigned  = alerts.filter(a => !a.assigned_to)
  const focusedAlerts = selectedAnalyst ? alerts.filter(a => a.assigned_to === selectedAnalyst) : alerts

  const byAnalyst = analysts.map(analyst => ({
    ...analyst,
    alerts: alerts.filter(a => a.assigned_to === analyst.id),
  }))

  const TABS = [
    { key: 'alerts',       label: 'Alerts' },
    { key: 'approvals',    label: 'Approvals',     badge: pendingUsers.length },
    { key: 'users',        label: `Users (${allUsers.filter(u => u.is_active).length})` },
    { key: 'role-requests', label: 'Role Requests', badge: roleRequests.length },
  ]

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-base font-semibold text-theme-primary flex items-center gap-2">
            <Users size={16} className="text-blue-400" /> Admin Dashboard
          </h1>
          <p className="text-xs text-theme-muted mt-0.5">Manage users, approvals, and alert assignments</p>
        </div>
        <div className="flex items-center gap-2">
          {selectedAnalyst && (
            <button
              onClick={() => setSelectedAnalyst(null)}
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              ← All analysts
            </button>
          )}
          <div className="flex bg-theme-surface border border-theme rounded-lg overflow-hidden">
            {TABS.map(tab => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={cn(
                  'relative px-3 py-1.5 text-xs font-medium transition-colors',
                  activeTab === tab.key
                    ? 'bg-blue-600 text-white'
                    : 'text-theme-secondary hover:text-theme-primary'
                )}
              >
                {tab.label}
                {tab.badge > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center">
                    {tab.badge > 9 ? '9+' : tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Approvals Tab ── */}
      {activeTab === 'approvals' && (
        <ApprovalsTab
          pendingUsers={pendingUsers}
          approveUser={approveUser}
          denyUser={denyUser}
        />
      )}

      {/* ── Role Requests Tab ── */}
      {activeTab === 'role-requests' && (
        <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-theme flex items-center gap-2">
            <Shield size={13} className="text-purple-400" />
            <h2 className="text-xs font-semibold text-theme-primary">
              Pending Role Requests
              {roleRequests.length > 0 && <span className="ml-1.5 text-purple-400">({roleRequests.length})</span>}
            </h2>
          </div>
          {roleRequests.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-theme-muted">No pending role change requests</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-theme-raised">
                  <tr>
                    {['User', 'Current Role', 'Requested Role', 'Reason', 'Requested', 'Actions'].map(h => (
                      <th key={h} className="px-4 py-2 text-left text-theme-secondary font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-theme">
                  {roleRequests.map(req => (
                    <tr key={req.id} className="hover:bg-theme-base">
                      <td className="px-4 py-2.5 font-medium text-theme-primary">{req.username}</td>
                      <td className="px-4 py-2.5">
                        <Badge variant="role" value={req.current_role}>{req.current_role.replace('_', ' ')}</Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge variant="priority" value={req.requested_role === 'admin' ? 'critical' : 'high'}>
                          {req.requested_role.replace('_', ' ')}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5 max-w-xs">
                        <p className="text-theme-secondary truncate" title={req.reason}>{req.reason}</p>
                      </td>
                      <td className="px-4 py-2.5 text-theme-muted">{timeAgo(req.created_at)}</td>
                      <td className="px-4 py-2.5">
                        <div className="flex gap-1">
                          <button
                            onClick={() => {
                              const notes = prompt('Optional notes for approval:')
                              processRoleReq.mutate({ requestId: req.id, approve: true, notes })
                            }}
                            disabled={processRoleReq.isPending}
                            className="p-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded transition-colors"
                            title="Approve"
                          >
                            <CheckCircle size={14} />
                          </button>
                          <button
                            onClick={() => {
                              const notes = prompt('Reason for denial (required):')
                              if (notes) processRoleReq.mutate({ requestId: req.id, approve: false, notes })
                            }}
                            disabled={processRoleReq.isPending}
                            className="p-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded transition-colors"
                            title="Deny"
                          >
                            <XCircle size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Users Tab ── */}
      {activeTab === 'users' && (
        <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-theme flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield size={13} className="text-purple-400" />
              <h2 className="text-xs font-semibold text-theme-primary">User Management</h2>
            </div>
            <p className="text-xs text-theme-muted">Change role via dropdown · trash icon deactivates account</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-theme-raised">
                <tr>
                  {['Username', 'Email', 'Role', 'Status', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-2 text-left text-xs font-medium text-theme-secondary">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-theme">
                {allUsers.filter(u => u.is_active).map(user => (
                  <tr key={user.username} className="hover:bg-theme-base">
                    <td className="px-4 py-2.5 text-xs font-medium text-theme-primary">{user.username}</td>
                    <td className="px-4 py-2.5 text-xs text-theme-secondary">{user.email || '—'}</td>
                    <td className="px-4 py-2.5">
                      <select
                        value={user.role}
                        onChange={e => updateRole.mutate({ username: user.username, role: e.target.value })}
                        disabled={updateRole.isPending}
                        className="text-xs bg-theme-base border border-theme rounded px-2 py-1 text-theme-primary focus:outline-none focus:border-blue-500"
                      >
                        <option value="analyst">Analyst</option>
                        <option value="senior_analyst">Senior Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant={user.status === 'approved' ? 'success' : 'warning'}>{user.status}</Badge>
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => {
                          if (confirm(`Deactivate ${user.username}'s account?`)) deleteUser.mutate(user.username)
                        }}
                        disabled={deleteUser.isPending || user.role === 'admin'}
                        className="p-1.5 text-red-400 hover:bg-red-950/40 rounded disabled:opacity-30 transition-colors"
                        title={user.role === 'admin' ? 'Cannot deactivate admin accounts' : 'Deactivate user'}
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Alerts Tab ── */}
      {activeTab === 'alerts' && (
        <>
          {/* Analyst workload cards */}
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
            {byAnalyst.map(analyst => {
              const active = analyst.alerts.filter(al => ['received','triaged','plans_generated'].includes(al.approval_status)).length
              const isSelected = selectedAnalyst === analyst.id
              return (
                <button
                  key={analyst.id}
                  onClick={() => setSelectedAnalyst(isSelected ? null : analyst.id)}
                  className={cn(
                    'bg-theme-surface border rounded-lg p-3 text-left transition-all',
                    isSelected ? 'border-blue-500 ring-1 ring-blue-500/40' : 'border-theme hover:border-blue-400'
                  )}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-8 h-8 rounded-full bg-blue-600/30 border border-blue-500/40 flex items-center justify-center text-xs font-bold text-blue-300">
                      {analyst.avatar}
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-theme-primary truncate">{analyst.name}</p>
                      <p className="text-xs text-theme-muted capitalize">{analyst.role.replace('_', ' ')}</p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-theme-muted">{analyst.alerts.length} total</span>
                    {active > 0
                      ? <span className="text-amber-400 font-semibold">{active} active</span>
                      : <span className="text-emerald-400">clear</span>
                    }
                  </div>
                </button>
              )
            })}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Alert table */}
            <div className="lg:col-span-2 bg-theme-surface border border-theme rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-theme">
                <h2 className="text-xs font-semibold text-theme-primary">
                  {selectedAnalyst
                    ? `Alerts — ${analysts.find(a => a.id === selectedAnalyst)?.name}`
                    : 'All Alerts'}
                  <span className="ml-2 font-normal text-theme-muted">({focusedAlerts.length})</span>
                </h2>
              </div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-theme-raised text-theme-muted text-left">
                    {['Alert', 'Priority', 'Status', 'Assigned To', ''].map(h => (
                      <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {focusedAlerts.length === 0 && (
                    <tr><td colSpan={5} className="px-4 py-10 text-center text-theme-muted">No alerts found</td></tr>
                  )}
                  {focusedAlerts.map(alert => (
                    <tr key={alert.alert_id} className={cn('border-t border-theme hover:bg-theme-raised transition-colors', PRIORITY_RING[alert.priority])}>
                      <td className="px-4 py-2.5">
                        <p className="font-mono truncate max-w-[180px] text-theme-primary">{alert.classification}</p>
                        <p className="text-theme-muted mt-0.5">{timeAgo(alert.created_at)}</p>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge variant="priority" value={alert.priority}>{alert.priority}</Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge variant="status" value={alert.approval_status}>{alert.approval_status}</Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <select
                          value={alert.assigned_to ?? ''}
                          onChange={e => assign.mutate({ alertId: alert.alert_id, analystId: e.target.value || null, analysts })}
                          className="bg-theme-raised border border-theme text-theme-primary text-xs rounded px-2 py-1 focus:outline-none focus:border-blue-500"
                        >
                          <option value="">Unassigned</option>
                          {analysts.map(a => (
                            <option key={a.id} value={a.id}>{a.name}</option>
                          ))}
                        </select>
                      </td>
                      <td className="px-4 py-2.5">
                        <button onClick={() => navigate(`/alerts/${alert.alert_id}`)} className="text-theme-muted hover:text-blue-400 transition-colors">
                          <ChevronRight size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Sidebar: unassigned + workload */}
            <div className="space-y-3">
              <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-theme flex items-center gap-2">
                  <UserX size={13} className="text-amber-400" />
                  <h2 className="text-xs font-semibold text-theme-primary">
                    Unassigned <span className="text-amber-400">({unassigned.length})</span>
                  </h2>
                </div>
                {unassigned.length === 0
                  ? <p className="px-4 py-4 text-xs text-theme-muted">All alerts assigned</p>
                  : (
                    <ul className="divide-y divide-theme">
                      {unassigned.map(a => (
                        <li key={a.alert_id} className="px-4 py-2.5 flex items-center justify-between gap-2">
                          <div className="min-w-0">
                            <p className="text-xs font-mono text-theme-primary truncate">{a.classification}</p>
                            <p className="text-xs text-theme-muted">{timeAgo(a.created_at)}</p>
                          </div>
                          <Badge variant="priority" value={a.priority}>{a.priority}</Badge>
                        </li>
                      ))}
                    </ul>
                  )
                }
              </div>

            </div>
          </div>
        </>
      )}
    </div>
  )
}
