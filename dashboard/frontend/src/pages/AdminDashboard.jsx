import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Users, ChevronRight, UserCheck, UserX, UserPlus, CheckCircle, XCircle, Trash2, Shield } from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo, cn } from '../lib/utils'
import { useToastStore } from '../components/ui/Toast'

const STATUS_DOT = {
  online:  'bg-emerald-400',
  away:    'bg-amber-400',
  offline: 'bg-slate-400',
}

const PRIORITY_RING = {
  critical: 'border-l-2 border-l-red-500',
  high:     'border-l-2 border-l-amber-500',
  medium:   'border-l-2 border-l-blue-500',
  low:      '',
}

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
      if (analystId) {
        const name = analysts?.find(a => a.id === analystId)?.name ?? analystId
        toast({ type: 'success', title: 'Alert assigned', message: `Assigned to ${name}` })
      } else {
        toast({ type: 'success', title: 'Alert unassigned', message: 'Alert is now unassigned' })
      }
    },
    onError: () => {
      toast({ type: 'error', title: 'Assignment failed', message: 'Could not assign alert. Try again.' })
    },
  })
}

function usePendingUsers() {
  return useQuery({
    queryKey: ['admin', 'pending-users'],
    queryFn: () => api.get('/auth/pending-users').then(r => r.data.users),
    refetchInterval: 10_000, // Check every 10 seconds
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
      toast({ type: 'success', title: 'User approved', message: `${data.username} can now log in` })
    },
    onError: () => {
      toast({ type: 'error', title: 'Approval failed', message: 'Could not approve user' })
    },
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
    mutationFn: (username) =>
      api.delete(`/admin/users/${username}`).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'analysts'] })
      toast({ type: 'success', title: 'User deleted', message: `${data.username} account deactivated` })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Delete failed', message: err?.response?.data?.detail || 'Could not delete user' })
    },
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
      toast({ type: 'success', title: 'Role updated', message: `${data.username} is now ${data.role}` })
    },
    onError: () => {
      toast({ type: 'error', title: 'Update failed', message: 'Could not update role' })
    },
  })
}

function useRoleChangeRequests() {
  return useQuery({
    queryKey: ['admin', 'role-requests'],
    queryFn: () => api.get('/admin/role-requests?status=pending').then(r => r.data.requests),
    refetchInterval: 10_000,
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
      toast({ 
        type: 'success', 
        title: data.status === 'approved' ? 'Request approved' : 'Request denied',
        message: `${data.username}'s role ${data.status}` 
      })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Action failed', message: err?.response?.data?.detail || 'Could not process request' })
    },
  })
}

export default function AdminDashboard() {
  const navigate = useNavigate()
  const [selectedAnalyst, setSelectedAnalyst] = useState(null)

  const { data: analysts = [], isLoading: loadingAnalysts } = useAnalysts()
  const { data: alertData, isLoading: loadingAlerts } = useAdminAlerts()
  const { data: pendingUsers = [], isLoading: loadingPending } = usePendingUsers()
  const { data: allUsers = [], isLoading: loadingUsers } = useAllUsers()
  const { data: roleRequests = [], isLoading: loadingRoleRequests } = useRoleChangeRequests()
  const assign = useAssignAlert()
  const approveUser = useApproveUser()
  const deleteUser = useDeleteUser()
  const updateRole = useUpdateUserRole()
  const processRoleRequest = useProcessRoleRequest()
  const [approvingUser, setApprovingUser] = useState(null)
  const [activeTab, setActiveTab] = useState('alerts') // 'alerts' | 'users' | 'role-requests'

  if (loadingAnalysts || loadingAlerts || loadingPending || loadingUsers || loadingRoleRequests) return <PageSpinner />

  const alerts = alertData?.items ?? []
  const unassigned = alerts.filter(a => !a.assigned_to)

  // Build per-analyst alert lists
  const byAnalyst = analysts.map(analyst => ({
    ...analyst,
    alerts: alerts.filter(a => a.assigned_to === analyst.id),
  }))

  const activeCount = (a) =>
    a.alerts.filter(al => ['received','triaged','plans_generated'].includes(al.approval_status)).length

  // Filtered view when an analyst is selected
  const focusedAlerts = selectedAnalyst
    ? alerts.filter(a => a.assigned_to === selectedAnalyst)
    : alerts

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-theme-primary flex items-center gap-2">
            <Users size={16} className="text-blue-400" /> Admin Dashboard
          </h1>
          <p className="text-xs text-theme-muted mt-0.5">Analyst workloads, alert assignments, and user management</p>
        </div>
        <div className="flex items-center gap-2">
          {selectedAnalyst && (
            <button
              onClick={() => setSelectedAnalyst(null)}
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              ← Show all analysts
            </button>
          )}
          {/* Tab Navigation */}
          <div className="flex bg-theme-surface border border-theme rounded-lg overflow-hidden">
            <button
              onClick={() => setActiveTab('alerts')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === 'alerts'
                  ? 'bg-blue-600 text-blue-100'
                  : 'text-theme-secondary hover:text-theme-primary'
              )}
            >
              Alerts
            </button>
            <button
              onClick={() => setActiveTab('users')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === 'users'
                  ? 'bg-blue-600 text-blue-100'
                  : 'text-theme-secondary hover:text-theme-primary'
              )}
            >
              Users ({allUsers.filter(u => u.is_active).length})
            </button>
            <button
              onClick={() => setActiveTab('role-requests')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium transition-colors relative',
                activeTab === 'role-requests'
                  ? 'bg-blue-600 text-blue-100'
                  : 'text-theme-secondary hover:text-theme-primary'
              )}
            >
              Role Requests
              {roleRequests.length > 0 && (
                <span className="absolute top-0 right-0 -mt-1 -mr-1 w-4 h-4 bg-red-500 text-white text-[10px] rounded-full flex items-center justify-center">
                  {roleRequests.length}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'role-requests' ? (
        /* Role Change Requests View */
        <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-theme flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield size={13} className="text-purple-400" />
              <h2 className="text-xs font-semibold text-theme-primary">
                Role Change Requests <span className={roleRequests.length > 0 ? "text-purple-400" : "text-theme-muted"}>({roleRequests.length})</span>
              </h2>
            </div>
          </div>
          {roleRequests.length === 0 ? (
            <div className="px-4 py-8 text-center text-theme-muted text-sm">
              No pending role change requests
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-theme-raised">
                  <tr>
                    <th className="px-4 py-2 text-left text-theme-secondary">User</th>
                    <th className="px-4 py-2 text-left text-theme-secondary">Current Role</th>
                    <th className="px-4 py-2 text-left text-theme-secondary">Requested Role</th>
                    <th className="px-4 py-2 text-left text-theme-secondary">Reason</th>
                    <th className="px-4 py-2 text-left text-theme-secondary">Requested</th>
                    <th className="px-4 py-2 text-left text-theme-secondary">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-theme">
                  {roleRequests.map(request => (
                    <tr key={request.id} className="hover:bg-theme-base">
                      <td className="px-4 py-2.5">
                        <p className="text-theme-primary font-medium">{request.username}</p>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge variant="role" value={request.current_role}>
                          {request.current_role.replace('_', ' ')}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge variant="priority" value={request.requested_role === 'admin' ? 'critical' : 'high'}>
                          {request.requested_role.replace('_', ' ')}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5 max-w-xs">
                        <p className="text-theme-secondary truncate" title={request.reason}>
                          {request.reason}
                        </p>
                      </td>
                      <td className="px-4 py-2.5 text-theme-muted">
                        {timeAgo(request.created_at)}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex gap-1">
                          <button
                            onClick={() => {
                              const notes = prompt('Add optional notes for approval:')
                              processRoleRequest.mutate({ requestId: request.id, approve: true, notes })
                            }}
                            disabled={processRoleRequest.isPending}
                            className="p-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded"
                            title="Approve"
                          >
                            <CheckCircle size={14} />
                          </button>
                          <button
                            onClick={() => {
                              const notes = prompt('Reason for denial (required):')
                              if (notes) {
                                processRoleRequest.mutate({ requestId: request.id, approve: false, notes })
                              }
                            }}
                            disabled={processRoleRequest.isPending}
                            className="p-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded"
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
      ) : activeTab === 'users' ? (
        /* User Management View */
        <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-theme flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield size={13} className="text-purple-400" />
              <h2 className="text-xs font-semibold text-theme-primary">User Management</h2>
            </div>
            <p className="text-xs text-theme-muted">Click role to change, trash to delete</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-theme-raised">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-theme-secondary">Username</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-theme-secondary">Email</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-theme-secondary">Role</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-theme-secondary">Status</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-theme-secondary">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme">
                {allUsers.filter(u => u.is_active).map(user => (
                  <tr key={user.username} className="hover:bg-theme-base">
                    <td className="px-4 py-2.5">
                      <p className="text-xs text-theme-primary font-medium">{user.username}</p>
                    </td>
                    <td className="px-4 py-2.5">
                      <p className="text-xs text-theme-secondary">{user.email || '-'}</p>
                    </td>
                    <td className="px-4 py-2.5">
                      <select
                        value={user.role}
                        onChange={(e) => updateRole.mutate({ username: user.username, role: e.target.value })}
                        disabled={updateRole.isPending}
                        className="text-xs bg-theme-base border border-theme rounded px-2 py-1 text-theme-primary"
                      >
                        <option value="analyst">Analyst</option>
                        <option value="senior_analyst">Senior Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant={user.status === 'approved' ? 'success' : 'warning'}>
                        {user.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => {
                          if (confirm(`Are you sure you want to deactivate ${user.username}'s account?`)) {
                            deleteUser.mutate(user.username)
                          }
                        }}
                        disabled={deleteUser.isPending || user.role === 'admin'}
                        className="p-1.5 text-red-400 hover:bg-red-950 rounded disabled:opacity-50"
                        title={user.role === 'admin' ? 'Cannot delete admin accounts' : 'Delete user'}
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
      ) : (
        <>
          {/* Analyst cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {byAnalyst.map(analyst => {
          const active = activeCount(analyst)
          const isSelected = selectedAnalyst === analyst.id
          return (
            <button
              key={analyst.id}
              onClick={() => setSelectedAnalyst(isSelected ? null : analyst.id)}
              className={cn(
                'bg-theme-surface border rounded-lg p-3 text-left transition-all',
                isSelected
                  ? 'border-blue-500 ring-1 ring-blue-500/40'
                  : 'border-theme hover:border-blue-400'
              )}
            >
              <div className="flex items-center gap-2 mb-2">
                <div className="relative">
                  <div className="w-8 h-8 rounded-full bg-blue-600/30 border border-blue-500/40 flex items-center justify-center text-xs font-bold text-blue-300">
                    {analyst.avatar}
                  </div>
                  <span className={cn('absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 border-theme-surface', STATUS_DOT[analyst.status])} />
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
        {/* Alert assignment table */}
        <div className="lg:col-span-2 bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-theme flex items-center justify-between">
            <h2 className="text-xs font-semibold text-theme-primary">
              {selectedAnalyst
                ? `Alerts — ${analysts.find(a => a.id === selectedAnalyst)?.name}`
                : 'All Alerts'}
              <span className="ml-2 text-theme-muted font-normal">({focusedAlerts.length})</span>
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
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-theme-muted">
                    No alerts found
                  </td>
                </tr>
              )}
              {focusedAlerts.map(alert => {
                const analyst = analysts.find(a => a.id === alert.assigned_to)
                return (
                  <tr
                    key={alert.alert_id}
                    className={cn('border-t border-theme hover:bg-theme-raised transition-colors', PRIORITY_RING[alert.priority])}
                  >
                    <td className="px-4 py-2.5">
                      <p className="text-theme-primary font-mono truncate max-w-[180px]">{alert.classification}</p>
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
                      <button
                        onClick={() => navigate(`/alerts/${alert.alert_id}`)}
                        className="text-theme-muted hover:text-blue-400 transition-colors"
                      >
                        <ChevronRight size={14} />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Unassigned + analyst summary */}
        <div className="space-y-3">
          {/* Unassigned alerts */}
          <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-theme flex items-center gap-2">
              <UserX size={13} className="text-amber-400" />
              <h2 className="text-xs font-semibold text-theme-primary">
                Unassigned <span className="text-amber-400">({unassigned.length})</span>
              </h2>
            </div>
            {unassigned.length === 0
              ? <p className="px-4 py-4 text-xs text-theme-muted">All alerts are assigned</p>
              : (
                <ul className="divide-y divide-theme">
                  {unassigned.map(a => (
                    <li key={a.alert_id} className="px-4 py-2.5 flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-xs text-theme-primary font-mono truncate">{a.classification}</p>
                        <p className="text-xs text-theme-muted">{timeAgo(a.created_at)}</p>
                      </div>
                      <Badge variant="priority" value={a.priority}>{a.priority}</Badge>
                    </li>
                  ))}
                </ul>
              )
            }
          </div>

          {/* Pending User Approvals */}
          <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-theme flex items-center gap-2">
              <UserPlus size={13} className="text-emerald-400" />
              <h2 className="text-xs font-semibold text-theme-primary">
                Pending Approvals <span className={pendingUsers.length > 0 ? "text-emerald-400" : "text-theme-muted"}>({pendingUsers.length})</span>
              </h2>
            </div>
            {pendingUsers.length === 0 ? (
              <p className="px-4 py-4 text-xs text-theme-muted">No pending approvals</p>
            ) : (
              <ul className="divide-y divide-theme">
                {pendingUsers.map(user => (
                  <li key={user.id} className="px-4 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="text-xs text-theme-primary font-semibold">{user.username}</p>
                        <p className="text-xs text-theme-muted truncate">{user.email}</p>
                        <p className="text-xs text-theme-muted">{timeAgo(user.requested_at)}</p>
                      </div>
                      {approvingUser === user.id ? (
                        <div className="flex gap-1">
                          <button
                            onClick={() => approveUser.mutate({ userId: user.id, role: 'analyst' })}
                            className="px-2 py-1 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded"
                          >
                            Analyst
                          </button>
                          <button
                            onClick={() => approveUser.mutate({ userId: user.id, role: 'senior_analyst' })}
                            className="px-2 py-1 text-xs bg-purple-600 hover:bg-purple-500 text-white rounded"
                          >
                            Senior
                          </button>
                          <button
                            onClick={() => setApprovingUser(null)}
                            className="p-1 text-theme-muted hover:text-red-400"
                          >
                            <XCircle size={14} />
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setApprovingUser(user.id)}
                          className="p-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded"
                        >
                          <CheckCircle size={14} />
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Workload summary */}
          <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-theme flex items-center gap-2">
              <UserCheck size={13} className="text-blue-400" />
              <h2 className="text-xs font-semibold text-theme-primary">Workload</h2>
            </div>
            <ul className="divide-y divide-theme">
              {byAnalyst.map(analyst => (
                <li key={analyst.id} className="px-4 py-2.5 flex items-center gap-2">
                  <span className={cn('w-2 h-2 rounded-full shrink-0', STATUS_DOT[analyst.status])} />
                  <span className="flex-1 text-xs text-theme-secondary">{analyst.name}</span>
                  <span className="text-xs text-theme-muted">{analyst.alerts.length}</span>
                  <div className="w-16 h-1 bg-theme-raised rounded-full overflow-hidden">
                    <div
                      className="h-full bg-blue-500 rounded-full"
                      style={{ width: `${Math.min((analyst.alerts.length / Math.max(alerts.length, 1)) * 100 * 2, 100)}%` }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      </>
      )}
    </div>
  )
}
