import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  User, Mail, Shield, Lock, AlertCircle, CheckCircle,
  XCircle, ChevronRight, Clock, KeyRound, BellRing
} from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { Spinner } from '../components/ui/Spinner'
import { cn, timeAgo } from '../lib/utils'
import { useToastStore } from '../components/ui/Toast'

// ── Data hooks ────────────────────────────────────────────────────────────────

function useProfile() {
  return useQuery({
    queryKey: ['profile'],
    queryFn: () => api.get('/auth/me').then(r => r.data),
    staleTime: 30_000,
  })
}

function useMyAlerts() {
  return useQuery({
    queryKey: ['alerts', 'my', { priority: '', status: '' }],
    queryFn: () => api.get('/alerts/my').then(r => r.data),
    staleTime: 15_000,
  })
}

function useRoleRequestStatus() {
  return useQuery({
    queryKey: ['role-request-status'],
    queryFn: () => api.get('/me/role-request-status').then(r => r.data),
    staleTime: 30_000,
  })
}

function useUpdateProfile() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (data) => api.patch('/auth/me', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['profile'] })
      toast({ type: 'success', title: 'Profile updated', message: 'Your changes have been saved' })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Update failed', message: err?.response?.data?.detail || 'Could not update profile' })
    },
  })
}

function useChangePassword() {
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (data) => api.post('/auth/me/change-password', data).then(r => r.data),
    onSuccess: () => {
      toast({ type: 'success', title: 'Password changed', message: 'Your password has been updated' })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Change failed', message: err?.response?.data?.detail || 'Could not change password' })
    },
  })
}

function useRequestRoleChange() {
  const qc = useQueryClient()
  const toast = useToastStore(s => s.push)
  return useMutation({
    mutationFn: (data) => api.post('/me/request-role', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['profile'] })
      qc.invalidateQueries({ queryKey: ['role-request-status'] })
      toast({ type: 'success', title: 'Request sent', message: 'Role change request submitted for admin review' })
    },
    onError: (err) => {
      toast({ type: 'error', title: 'Request failed', message: err?.response?.data?.detail || 'Could not submit request' })
    },
  })
}

// ── Sub-components ────────────────────────────────────────────────────────────

function RoleRequestStatus({ status }) {
  if (!status?.has_pending_request) return null
  const req = status.request
  return (
    <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-900/20 border border-amber-700/40">
      <Clock size={14} className="text-amber-400 mt-0.5 shrink-0" />
      <div>
        <p className="text-xs font-medium text-amber-300">Role Change Pending</p>
        <p className="text-xs text-amber-400/80 mt-0.5">
          Requested <span className="font-semibold">{req.requested_role.replace('_', ' ')}</span>
          {' '}· {timeAgo(req.created_at)}
        </p>
      </div>
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function Profile() {
  const { data: profile, isLoading: loadingProfile } = useProfile()
  const { data: alertsData, isLoading: loadingAlerts } = useMyAlerts()
  const { data: roleStatus } = useRoleRequestStatus()
  const updateProfile = useUpdateProfile()
  const changePassword = useChangePassword()
  const requestRoleChange = useRequestRoleChange()
  const [activeTab, setActiveTab] = useState('overview')

  // Form states
  const [email, setEmail] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [requestedRole, setRequestedRole] = useState('')
  const [roleReason, setRoleReason] = useState('')

  if (loadingProfile) return <div className="flex justify-center p-8"><Spinner /></div>

  const myAlerts = alertsData?.items ?? []

  const handleEmailUpdate = (e) => {
    e.preventDefault()
    updateProfile.mutate({ email })
  }

  const handlePasswordChange = (e) => {
    e.preventDefault()
    if (newPassword !== confirmPassword) {
      useToastStore.getState().push({ type: 'error', title: 'Password mismatch', message: 'New passwords do not match' })
      return
    }
    if (newPassword.length < 8) {
      useToastStore.getState().push({ type: 'error', title: 'Password too short', message: 'Password must be at least 8 characters' })
      return
    }
    changePassword.mutate({ current_password: currentPassword, new_password: newPassword })
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
  }

  const handleRoleRequest = (e) => {
    e.preventDefault()
    requestRoleChange.mutate({ requested_role: requestedRole, reason: roleReason })
    setRequestedRole('')
    setRoleReason('')
  }

  const TABS = [
    { id: 'overview', label: 'Overview', Icon: User },
    { id: 'security', label: 'Security', Icon: Lock },
    { id: 'alerts',   label: `My Alerts (${myAlerts.length})`, Icon: BellRing },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-base font-semibold text-theme-primary flex items-center gap-2">
          <User size={16} className="text-blue-400" /> My Profile
        </h1>
        <p className="text-xs text-theme-muted mt-0.5">Manage your account settings and view assigned alerts</p>
      </div>

      {/* Tab Navigation */}
      <div className="flex bg-theme-surface border border-theme rounded-lg overflow-hidden w-fit">
        {TABS.map(({ id, label, Icon }) => (
          <button
            key={id}
            id={`profile-tab-${id}`}
            onClick={() => setActiveTab(id)}
            className={cn(
              'flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors',
              activeTab === id
                ? 'bg-blue-600 text-blue-100'
                : 'text-theme-secondary hover:text-theme-primary'
            )}
          >
            <Icon size={12} />
            {label}
          </button>
        ))}
      </div>

      {/* ── Overview Tab ──────────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Profile Info Card */}
          <div className="bg-theme-surface border border-theme rounded-lg p-5">
            <h2 className="text-sm font-semibold text-theme-primary mb-4 flex items-center gap-2">
              <User size={14} className="text-blue-400" /> Profile Information
            </h2>
            <div className="space-y-3">
              {/* Avatar + username */}
              <div className="flex items-center gap-3 p-3 bg-theme-base rounded-lg">
                <div className="w-10 h-10 rounded-full bg-blue-600/20 flex items-center justify-center shrink-0">
                  <span className="text-blue-400 font-bold text-sm">
                    {profile?.username?.substring(0, 2).toUpperCase()}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-theme-muted">Username</p>
                  <p className="text-sm text-theme-primary font-medium">{profile?.username}</p>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-theme-base rounded-lg">
                <Mail size={18} className="text-theme-muted shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-theme-muted">Email</p>
                  <p className="text-sm text-theme-primary truncate">{profile?.email || 'Not set'}</p>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-theme-base rounded-lg">
                <Shield size={18} className="text-theme-muted shrink-0" />
                <div>
                  <p className="text-xs text-theme-muted">Role</p>
                  <Badge variant="role" value={profile?.role}>{profile?.role?.replace('_', ' ')}</Badge>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-theme-base rounded-lg">
                <CheckCircle size={18} className="text-emerald-400 shrink-0" />
                <div>
                  <p className="text-xs text-theme-muted">Member Since</p>
                  <p className="text-sm text-theme-primary">
                    {profile?.created_at ? new Date(profile.created_at).toLocaleDateString() : 'Unknown'}
                  </p>
                </div>
              </div>

              {/* Pending role request banner */}
              <RoleRequestStatus status={roleStatus} />
            </div>
          </div>

          {/* Email Update */}
          <div className="bg-theme-surface border border-theme rounded-lg p-5">
            <h2 className="text-sm font-semibold text-theme-primary mb-4 flex items-center gap-2">
              <Mail size={14} className="text-blue-400" /> Update Email
            </h2>
            <form onSubmit={handleEmailUpdate} className="space-y-3">
              <div>
                <label className="text-xs text-theme-secondary block mb-1">New Email Address</label>
                <input
                  id="profile-email-input"
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary
                             focus:outline-none focus:border-blue-500"
                  placeholder={profile?.email || 'Enter email address'}
                  required
                />
              </div>
              <button
                type="submit"
                id="update-email-btn"
                disabled={updateProfile.isPending || !email}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 text-blue-100 text-xs font-semibold rounded py-2 transition-colors"
              >
                {updateProfile.isPending ? <Spinner className="h-3 w-3 inline" /> : 'Update Email'}
              </button>
            </form>
          </div>

          {/* Role Change Request */}
          <div className="bg-theme-surface border border-theme rounded-lg p-5 lg:col-span-2">
            <h2 className="text-sm font-semibold text-theme-primary mb-1 flex items-center gap-2">
              <Shield size={14} className="text-purple-400" /> Request Role Change
            </h2>
            <p className="text-xs text-theme-muted mb-4">
              Role changes require admin approval. You'll be notified by email when a decision is made.
            </p>

            {roleStatus?.has_pending_request ? (
              <div className="p-4 rounded-lg bg-amber-900/20 border border-amber-700/40 text-center">
                <Clock size={16} className="text-amber-400 mx-auto mb-1" />
                <p className="text-xs text-amber-300 font-medium">A role change request is already pending</p>
                <p className="text-xs text-amber-400/70 mt-0.5">
                  Requested: <span className="font-semibold">{roleStatus.request.requested_role.replace('_', ' ')}</span>
                  {' '}({timeAgo(roleStatus.request.created_at)})
                </p>
              </div>
            ) : (
              <form onSubmit={handleRoleRequest} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs text-theme-secondary block mb-1">Requested Role</label>
                    <select
                      id="role-request-select"
                      value={requestedRole}
                      onChange={e => setRequestedRole(e.target.value)}
                      className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                      required
                    >
                      <option value="">Select a role…</option>
                      {profile?.role !== 'analyst'         && <option value="analyst">Analyst</option>}
                      {profile?.role !== 'senior_analyst'  && <option value="senior_analyst">Senior Analyst</option>}
                      {profile?.role !== 'admin'           && <option value="admin">Admin</option>}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-theme-secondary block mb-1">Current Role</label>
                    <div className="py-2">
                      <Badge variant="role" value={profile?.role}>{profile?.role?.replace('_', ' ')}</Badge>
                    </div>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-theme-secondary block mb-1">Reason for Request</label>
                  <textarea
                    id="role-request-reason"
                    value={roleReason}
                    onChange={e => setRoleReason(e.target.value)}
                    className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                    rows={3}
                    placeholder="Explain why you need this role change…"
                    required
                  />
                </div>
                <button
                  type="submit"
                  id="submit-role-request-btn"
                  disabled={requestRoleChange.isPending || !requestedRole || !roleReason}
                  className="bg-purple-600 hover:bg-purple-500 disabled:bg-purple-900 text-purple-100 text-xs font-semibold rounded px-4 py-2 transition-colors"
                >
                  {requestRoleChange.isPending ? <Spinner className="h-3 w-3 inline" /> : 'Submit Request'}
                </button>
              </form>
            )}
          </div>
        </div>
      )}

      {/* ── Security Tab ──────────────────────────────────────────────────── */}
      {activeTab === 'security' && (
        <div className="max-w-md space-y-4">
          <div className="bg-theme-surface border border-theme rounded-lg p-5">
            <h2 className="text-sm font-semibold text-theme-primary mb-4 flex items-center gap-2">
              <Lock size={14} className="text-amber-400" /> Change Password
            </h2>
            <form onSubmit={handlePasswordChange} className="space-y-3">
              <div>
                <label className="text-xs text-theme-secondary block mb-1">Current Password</label>
                <input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={e => setCurrentPassword(e.target.value)}
                  className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="text-xs text-theme-secondary block mb-1">New Password</label>
                <input
                  id="new-password-field"
                  type="password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                  minLength={8}
                  required
                />
                <p className="text-xs text-theme-muted mt-1">Minimum 8 characters</p>
              </div>
              <div>
                <label className="text-xs text-theme-secondary block mb-1">Confirm New Password</label>
                <input
                  id="confirm-password-field"
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  className={cn(
                    'w-full bg-theme-base border rounded px-3 py-2 text-sm text-theme-primary focus:outline-none',
                    confirmPassword && confirmPassword !== newPassword
                      ? 'border-red-500'
                      : 'border-theme focus:border-blue-500'
                  )}
                  required
                />
                {confirmPassword && confirmPassword !== newPassword && (
                  <p className="text-xs text-red-400 mt-1">Passwords do not match</p>
                )}
              </div>
              <button
                type="submit"
                id="change-password-btn"
                disabled={changePassword.isPending || !currentPassword || !newPassword || newPassword !== confirmPassword}
                className="w-full bg-amber-600 hover:bg-amber-500 disabled:bg-amber-900 text-amber-100 text-xs font-semibold rounded py-2 transition-colors"
              >
                {changePassword.isPending ? <Spinner className="h-3 w-3 inline" /> : 'Change Password'}
              </button>
            </form>
          </div>

          {/* Forgot password link */}
          <div className="bg-theme-surface border border-theme rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRound size={14} className="text-theme-muted" />
              <div>
                <p className="text-xs font-medium text-theme-primary">Forgot your password?</p>
                <p className="text-xs text-theme-muted">Request a reset link via email</p>
              </div>
            </div>
            <Link
              to="/forgot-password"
              id="forgot-password-link"
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors shrink-0"
            >
              Reset <ChevronRight size={12} />
            </Link>
          </div>
        </div>
      )}

      {/* ── My Alerts Tab ─────────────────────────────────────────────────── */}
      {activeTab === 'alerts' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-theme-muted">
              Alerts currently assigned to you
            </p>
            <Link
              to="/my-alerts"
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              Open full view <ChevronRight size={12} />
            </Link>
          </div>

          <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-theme">
              <h2 className="text-sm font-semibold text-theme-primary flex items-center gap-2">
                <AlertCircle size={14} className="text-blue-400" />
                Assigned Alerts
                <span className="text-theme-muted font-normal">({myAlerts.length})</span>
              </h2>
            </div>

            {loadingAlerts ? (
              <div className="p-8 text-center"><Spinner /></div>
            ) : myAlerts.length === 0 ? (
              <div className="px-4 py-10 text-center">
                <BellRing size={24} className="text-theme-muted opacity-30 mx-auto mb-2" />
                <p className="text-sm text-theme-muted">No alerts currently assigned to you</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-theme-raised">
                    <tr>
                      {['Classification', 'Priority', 'Status', 'Time'].map(h => (
                        <th key={h} className="px-4 py-2 text-left text-theme-secondary font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme">
                    {myAlerts.slice(0, 10).map(alert => (
                      <tr key={alert.alert_id} className="hover:bg-theme-base">
                        <td className="px-4 py-2.5">
                          <Link
                            to={`/alerts/${alert.alert_id}`}
                            className="text-theme-primary font-medium hover:text-blue-400 transition-colors font-mono"
                          >
                            {alert.classification}
                          </Link>
                        </td>
                        <td className="px-4 py-2.5">
                          <Badge variant="priority" value={alert.priority}>{alert.priority}</Badge>
                        </td>
                        <td className="px-4 py-2.5">
                          <Badge variant="status" value={alert.approval_status}>{alert.approval_status}</Badge>
                        </td>
                        <td className="px-4 py-2.5 text-theme-muted">
                          {timeAgo(alert.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {myAlerts.length > 10 && (
                  <div className="px-4 py-2 border-t border-theme">
                    <Link to="/my-alerts" className="text-xs text-blue-400 hover:text-blue-300">
                      View all {myAlerts.length} alerts →
                    </Link>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
