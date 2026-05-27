import { X } from 'lucide-react'

const SHORTCUTS = [
  { keys: ['Esc'],     desc: 'Go back' },
  { keys: ['?'],       desc: 'Show this help' },
  { keys: ['g', 'h'],  desc: 'Go to Alert Feed' },
  { keys: ['g', 'c'],  desc: 'Go to CVE Browser' },
  { keys: ['g', 's'],  desc: 'Go to Assets' },
]

export function ShortcutsDialog({ open, onClose }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-theme-surface border border-theme rounded-xl w-full max-w-sm mx-4 p-5 shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-theme-primary">Keyboard Shortcuts</h2>
          <button onClick={onClose} className="text-theme-muted hover:text-theme-primary transition-colors">
            <X size={16} />
          </button>
        </div>
        <div className="space-y-2">
          {SHORTCUTS.map(({ keys, desc }) => (
            <div key={desc} className="flex items-center justify-between text-xs">
              <span className="text-theme-secondary">{desc}</span>
              <div className="flex items-center gap-1">
                {keys.map((k, i) => (
                  <span key={i} className="flex items-center gap-1">
                    <kbd className="px-1.5 py-0.5 rounded bg-theme-raised border border-theme text-theme-primary font-mono text-xs">{k}</kbd>
                    {i < keys.length - 1 && <span className="text-theme-muted">then</span>}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
        <p className="text-xs text-theme-muted mt-4 border-t border-theme pt-3">Press <kbd className="px-1 py-0.5 rounded bg-theme-raised border border-theme font-mono">Esc</kbd> or click outside to close</p>
      </div>
    </div>
  )
}
