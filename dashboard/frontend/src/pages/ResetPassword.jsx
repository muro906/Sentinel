import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Lock, ShieldAlert, CheckCircle, AlertTriangle, Eye, EyeOff } from 'lucide-react'
import api from '../lib/api'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''

  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')

  // Redirect to login after success
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => navigate('/login'), 3000)
      return () => clearTimeout(timer)
    }
  }, [success, navigate])

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-theme-base px-4">
        <div className="w-full max-w-md bg-theme-surface border border-theme rounded-2xl p-8 text-center">
          <AlertTriangle size={32} className="text-amber-400 mx-auto mb-3" />
          <h1 className="text-lg font-semibold text-theme-primary mb-2">Invalid Reset Link</h1>
          <p className="text-sm text-theme-muted mb-4">
            This password reset link is invalid or has expired.
          </p>
          <Link to="/forgot-password" className="text-sm text-blue-400 hover:text-blue-300 transition-colors">
            Request a new reset link
          </Link>
        </div>
      </div>
    )
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    try {
      await api.post('/auth/reset-password', { token, new_password: newPassword })
      setSuccess(true)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Reset failed. The link may be expired or already used.')
    } finally {
      setLoading(false)
    }
  }

  const passwordStrength = (pw) => {
    if (!pw) return null
    if (pw.length < 8) return { label: 'Too short', color: 'bg-red-500', width: '25%' }
    if (pw.length < 10 && !/[^a-zA-Z0-9]/.test(pw)) return { label: 'Weak', color: 'bg-amber-500', width: '45%' }
    if (pw.length >= 12 && /[^a-zA-Z0-9]/.test(pw) && /[0-9]/.test(pw)) return { label: 'Strong', color: 'bg-emerald-500', width: '100%' }
    return { label: 'Moderate', color: 'bg-blue-500', width: '65%' }
  }

  const strength = passwordStrength(newPassword)

  return (
    <div className="min-h-screen flex items-center justify-center bg-theme-base px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <ShieldAlert size={28} className="text-blue-400" />
          <span className="text-xl font-bold text-theme-primary tracking-wider">SENTINEL</span>
        </div>

        <div className="bg-theme-surface border border-theme rounded-2xl p-8 shadow-xl">
          {success ? (
            /* Success State */
            <div className="text-center space-y-4">
              <div className="flex justify-center">
                <div className="w-14 h-14 rounded-full bg-emerald-600/20 flex items-center justify-center">
                  <CheckCircle size={28} className="text-emerald-400" />
                </div>
              </div>
              <h1 className="text-lg font-semibold text-theme-primary">Password Reset!</h1>
              <p className="text-sm text-theme-secondary">
                Your password has been updated successfully.
              </p>
              <p className="text-xs text-theme-muted">
                Redirecting to login in 3 seconds…
              </p>
              <Link
                to="/login"
                className="inline-block text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                Go to Sign In now
              </Link>
            </div>
          ) : (
            /* Reset Form */
            <>
              <div className="text-center mb-6">
                <div className="flex justify-center mb-3">
                  <div className="w-12 h-12 rounded-full bg-blue-600/20 flex items-center justify-center">
                    <Lock size={22} className="text-blue-400" />
                  </div>
                </div>
                <h1 className="text-lg font-semibold text-theme-primary">Set a new password</h1>
                <p className="text-xs text-theme-muted mt-1">
                  Choose a strong password for your Sentinel account
                </p>
              </div>

              {error && (
                <div className="mb-4 p-3 rounded-lg bg-red-900/30 border border-red-700/50 text-xs text-red-300 flex items-start gap-2">
                  <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* New Password */}
                <div>
                  <label htmlFor="new-password" className="block text-xs text-theme-secondary mb-1.5">
                    New Password
                  </label>
                  <div className="relative">
                    <input
                      id="new-password"
                      type={showNew ? 'text' : 'password'}
                      value={newPassword}
                      onChange={e => setNewPassword(e.target.value)}
                      required
                      minLength={8}
                      autoFocus
                      placeholder="Minimum 8 characters"
                      className="w-full bg-theme-base border border-theme rounded-lg px-3 py-2.5 pr-10 text-sm
                                 text-theme-primary placeholder-theme-muted focus:outline-none
                                 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowNew(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-theme-muted hover:text-theme-primary transition-colors"
                    >
                      {showNew ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>

                  {/* Strength indicator */}
                  {newPassword && strength && (
                    <div className="mt-2 space-y-1">
                      <div className="h-1 w-full bg-theme-raised rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-300 ${strength.color}`}
                          style={{ width: strength.width }}
                        />
                      </div>
                      <p className="text-xs text-theme-muted">{strength.label}</p>
                    </div>
                  )}
                </div>

                {/* Confirm Password */}
                <div>
                  <label htmlFor="confirm-password" className="block text-xs text-theme-secondary mb-1.5">
                    Confirm New Password
                  </label>
                  <div className="relative">
                    <input
                      id="confirm-password"
                      type={showConfirm ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={e => setConfirmPassword(e.target.value)}
                      required
                      placeholder="Repeat your password"
                      className={`w-full bg-theme-base border rounded-lg px-3 py-2.5 pr-10 text-sm
                                 text-theme-primary placeholder-theme-muted focus:outline-none
                                 focus:ring-1 transition-all
                                 ${confirmPassword && confirmPassword !== newPassword
                                   ? 'border-red-500 focus:border-red-500 focus:ring-red-500/30'
                                   : 'border-theme focus:border-blue-500 focus:ring-blue-500/30'
                                 }`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirm(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-theme-muted hover:text-theme-primary transition-colors"
                    >
                      {showConfirm ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                  {confirmPassword && confirmPassword !== newPassword && (
                    <p className="text-xs text-red-400 mt-1">Passwords do not match</p>
                  )}
                </div>

                <button
                  type="submit"
                  id="reset-password-btn"
                  disabled={loading || !newPassword || !confirmPassword || newPassword !== confirmPassword}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 disabled:cursor-not-allowed
                             text-white text-sm font-semibold rounded-lg py-2.5 transition-colors"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Updating…
                    </span>
                  ) : (
                    'Reset Password'
                  )}
                </button>
              </form>

              <div className="mt-6 text-center">
                <Link
                  to="/forgot-password"
                  className="text-xs text-theme-muted hover:text-theme-primary transition-colors"
                >
                  Request a new reset link
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
