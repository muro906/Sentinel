import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle, Info, X } from 'lucide-react'
import { create } from 'zustand'
import { cn } from '../../lib/utils'

const DURATION = 5000   // ms before auto-dismiss

const ICONS = {
  info:    <Info size={14} className="text-blue-400 shrink-0 mt-0.5" />,
  success: <CheckCircle size={14} className="text-emerald-400 shrink-0 mt-0.5" />,
  warning: <AlertTriangle size={14} className="text-amber-400 shrink-0 mt-0.5" />,
  error:   <AlertTriangle size={14} className="text-red-400 shrink-0 mt-0.5" />,
}

const BAR_COLOR = {
  info:    'bg-blue-500',
  success: 'bg-emerald-500',
  warning: 'bg-amber-500',
  error:   'bg-red-500',
}

let _id = 0

export const useToastStore = create((set) => ({
  toasts: [],
  push: (toast) => {
    const id = ++_id
    set((s) => ({ toasts: [...s.toasts, { id, type: 'info', ...toast }] }))
    return id
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}))

function Toast({ id, type = 'info', title, message }) {
  const dismiss   = useToastStore((s) => s.dismiss)
  const [leaving, setLeaving] = useState(false)

  // Start slide-out 300ms before actual removal
  useEffect(() => {
    const slideOut = setTimeout(() => setLeaving(true), DURATION - 300)
    const remove   = setTimeout(() => dismiss(id), DURATION)
    return () => { clearTimeout(slideOut); clearTimeout(remove) }
  }, [id, dismiss])

  const handleDismiss = () => {
    setLeaving(true)
    setTimeout(() => dismiss(id), 280)
  }

  return (
    <div
      className={cn(
        'relative overflow-hidden w-80 rounded-lg shadow-xl border',
        'bg-theme-surface border-theme',
        leaving
          ? 'animate-out slide-out-to-right-4 fade-out duration-300'
          : 'animate-in slide-in-from-right-4 fade-in duration-300'
      )}
    >
      <div className="flex items-start gap-3 p-3 pr-8">
        {ICONS[type]}
        <div className="flex-1 min-w-0">
          {title   && <p className="text-xs font-semibold text-theme-primary">{title}</p>}
          {message && <p className="text-xs text-theme-secondary mt-0.5 leading-relaxed">{message}</p>}
        </div>
        <button
          onClick={handleDismiss}
          className="absolute top-2.5 right-2.5 text-theme-muted hover:text-theme-primary transition-colors"
        >
          <X size={12} />
        </button>
      </div>

      {/* Progress bar — shrinks from full width to 0 over DURATION ms */}
      <div className="h-0.5 w-full bg-theme-raised">
        <div
          className={cn('h-full', BAR_COLOR[type])}
          style={{
            width: '100%',
            animation: `toast-shrink ${DURATION}ms linear forwards`,
          }}
        />
      </div>

      <style>{`
        @keyframes toast-shrink {
          from { width: 100%; }
          to   { width: 0%;   }
        }
      `}</style>
    </div>
  )
}

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts)
  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
      {toasts.map((t) => (
        <div key={t.id} className="pointer-events-auto">
          <Toast {...t} />
        </div>
      ))}
    </div>
  )
}
