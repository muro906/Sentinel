import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

export function useKeyboardShortcuts({ onShowHelp } = {}) {
  const navigate = useNavigate()

  useEffect(() => {
    const handler = (e) => {
      // Ignore when typing in an input/textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return

      if (e.key === 'Escape') {
        navigate(-1)
      }
      if (e.key === '?' && !e.shiftKey) {
        onShowHelp?.()
      }
      if (e.key === 'g' && !e.ctrlKey && !e.metaKey) {
        // g then h = go home
        const handler2 = (e2) => {
          if (e2.key === 'h') navigate('/')
          if (e2.key === 'a') navigate('/')
          if (e2.key === 'c') navigate('/cves')
          if (e2.key === 's') navigate('/assets')
          window.removeEventListener('keydown', handler2)
        }
        window.addEventListener('keydown', handler2, { once: true })
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [navigate, onShowHelp])
}
