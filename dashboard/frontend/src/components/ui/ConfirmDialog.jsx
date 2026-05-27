import { useState } from 'react'
import { AlertTriangle, X, ShieldAlert } from 'lucide-react'
import { cn } from '../../lib/utils'

export function ConfirmDialog({
  open,
  title,
  description,
  confirmText,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  onConfirm,
  onCancel,
  danger = false,
  children,        // optional extra content rendered between description and input
}) {
  const [typed, setTyped] = useState('')
  if (!open) return null

  const canConfirm = confirmText ? typed === confirmText : true

  const handleConfirm = () => {
    if (!canConfirm) return
    setTyped('')
    onConfirm()
  }

  const handleCancel = () => {
    setTyped('')
    onCancel()
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
    >
      <div className="bg-theme-surface border border-theme rounded-xl w-full max-w-md shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between px-6 pt-6 pb-4">
          <div className="flex items-center gap-2.5">
            {danger && (
              <div className="w-8 h-8 rounded-full bg-red-600/20 flex items-center justify-center shrink-0">
                <ShieldAlert size={16} className="text-red-400" />
              </div>
            )}
            <h2
              id="confirm-dialog-title"
              className="text-sm font-semibold text-theme-primary"
            >
              {title}
            </h2>
          </div>
          <button
            onClick={handleCancel}
            className="text-theme-muted hover:text-theme-primary transition-colors ml-4 shrink-0"
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 pb-6 space-y-4">
          {description && (
            <p className="text-sm text-theme-secondary leading-relaxed">{description}</p>
          )}

          {/* Optional children (e.g., list of destructive actions) */}
          {children}

          {/* Typed confirmation input */}
          {confirmText && (
            <div>
              <label className="text-xs text-theme-secondary block mb-1.5">
                Type <span className="font-mono font-semibold text-red-400">{confirmText}</span> to confirm
              </label>
              <input
                type="text"
                className="w-full bg-theme-base border border-theme rounded px-3 py-1.5 text-sm text-theme-primary focus:outline-none focus:border-red-500"
                value={typed}
                onChange={e => setTyped(e.target.value)}
                autoFocus
                placeholder={confirmText}
              />
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-1">
            <button
              id="confirm-dialog-cancel"
              onClick={handleCancel}
              className="px-4 py-1.5 text-sm rounded font-medium transition-colors bg-theme-raised text-theme-secondary hover:bg-theme-base hover:text-theme-primary"
            >
              {cancelLabel}
            </button>
            <button
              id="confirm-dialog-confirm"
              onClick={handleConfirm}
              disabled={!canConfirm}
              className={cn(
                'px-4 py-1.5 text-sm rounded font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed',
                danger
                  ? 'bg-red-600 text-white hover:bg-red-500'
                  : 'bg-blue-600 text-white hover:bg-blue-500'
              )}
            >
              {confirmLabel}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}