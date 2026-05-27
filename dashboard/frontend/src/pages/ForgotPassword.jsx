import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Mail, ShieldAlert, ArrowLeft, CheckCircle } from 'lucide-react'
import api from '../lib/api'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [submitted, setSubmitted] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await api.post('/auth/forgot-password', { email })
      setSubmitted(true)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Something went wrong. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-theme-base px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <ShieldAlert size={28} className="text-blue-400" />
          <span className="text-xl font-bold text-theme-primary tracking-wider">SENTINEL</span>
        </div>

        <div className="bg-theme-surface border border-theme rounded-2xl p-8 shadow-xl">
          {submitted ? (
            /* Success State */
            <div className="text-center space-y-4">
              <div className="flex justify-center">
                <div className="w-14 h-14 rounded-full bg-emerald-600/20 flex items-center justify-center">
                  <CheckCircle size={28} className="text-emerald-400" />
                </div>
              </div>
              <h1 className="text-lg font-semibold text-theme-primary">Check your inbox</h1>
              <p className="text-sm text-theme-secondary leading-relaxed">
                If <span className="text-blue-400 font-medium">{email}</span> is registered,
                you'll receive a password reset link within a few minutes.
              </p>
              <p className="text-xs text-theme-muted">
                The link expires in 1 hour. Check your spam folder if you don't see it.
              </p>
              <Link
                to="/login"
                className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors mt-2"
              >
                <ArrowLeft size={12} /> Back to Sign In
              </Link>
            </div>
          ) : (
            /* Request Form */
            <>
              <div className="text-center mb-6">
                <div className="flex justify-center mb-3">
                  <div className="w-12 h-12 rounded-full bg-blue-600/20 flex items-center justify-center">
                    <Mail size={22} className="text-blue-400" />
                  </div>
                </div>
                <h1 className="text-lg font-semibold text-theme-primary">Reset your password</h1>
                <p className="text-xs text-theme-muted mt-1">
                  Enter your email and we'll send you a reset link
                </p>
              </div>

              {error && (
                <div className="mb-4 p-3 rounded-lg bg-red-900/30 border border-red-700/50 text-xs text-red-300">
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label htmlFor="forgot-email" className="block text-xs text-theme-secondary mb-1.5">
                    Email Address
                  </label>
                  <input
                    id="forgot-email"
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    required
                    autoFocus
                    placeholder="you@example.com"
                    className="w-full bg-theme-base border border-theme rounded-lg px-3 py-2.5 text-sm
                               text-theme-primary placeholder-theme-muted focus:outline-none
                               focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all"
                  />
                </div>

                <button
                  type="submit"
                  id="send-reset-btn"
                  disabled={loading || !email}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 disabled:cursor-not-allowed
                             text-white text-sm font-semibold rounded-lg py-2.5 transition-colors"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Sending…
                    </span>
                  ) : (
                    'Send Reset Link'
                  )}
                </button>
              </form>

              <div className="mt-6 text-center">
                <Link
                  to="/login"
                  className="inline-flex items-center gap-1.5 text-xs text-theme-muted hover:text-theme-primary transition-colors"
                >
                  <ArrowLeft size={12} /> Back to Sign In
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
