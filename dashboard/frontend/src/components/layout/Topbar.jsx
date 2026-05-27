import { useState, useEffect, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { LogOut, Moon, Sun, Keyboard, User, ChevronDown, Settings, BellRing, ArrowRightLeft } from 'lucide-react'
import api from '../../lib/api'
import { useAuthStoreSelectors } from '../../store/auth'
import { useThemeStore } from '../../store/theme'
import { cn } from '../../lib/utils'

function useClock() {
    const [time, setTime] = useState(() => new Date())
    useEffect(() => {
        const t = setInterval(() => setTime(new Date()), 1000)
        return () => clearInterval(t)
    }, [])
    // Show local time with timezone abbreviation
    return time.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short',
    })
}

function UserMenu({ username, role, onLogout }) {
    const [open, setOpen] = useState(false)
    const ref = useRef(null)

    // Close on outside click
    useEffect(() => {
        const handler = (e) => {
            if (ref.current && !ref.current.contains(e.target)) setOpen(false)
        }
        document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [])

    const initials = username
        ? username.split(/[_@.]/).map(p => p[0]?.toUpperCase()).filter(Boolean).slice(0, 2).join('')
        : '?'

    const roleLabel = role?.replace(/_/g, ' ') ?? ''

    return (
        <div className="relative" ref={ref}>
            <button
                id="user-menu-btn"
                onClick={() => setOpen(v => !v)}
                className="flex items-center gap-2 hover:bg-theme-raised rounded-lg px-2 py-1 transition-colors group"
            >
                {/* Avatar circle */}
                <div className="w-6 h-6 rounded-full bg-blue-600/30 border border-blue-500/50 flex items-center justify-center shrink-0">
                    <span className="text-[10px] font-bold text-blue-300">{initials}</span>
                </div>
                <div className="text-left hidden sm:block">
                    <p className="text-xs font-medium text-theme-primary leading-none">{username}</p>
                    <p className="text-[10px] text-blue-400 capitalize leading-none mt-0.5">{roleLabel}</p>
                </div>
                <ChevronDown
                    size={12}
                    className={cn('text-theme-muted transition-transform', open && 'rotate-180')}
                />
            </button>

            {open && (
                <div className="absolute right-0 top-full mt-1.5 w-48 bg-theme-surface border border-theme rounded-xl shadow-xl z-50 overflow-hidden">
                    {/* Header */}
                    <div className="px-4 py-3 border-b border-theme bg-theme-raised">
                        <p className="text-xs font-semibold text-theme-primary truncate">{username}</p>
                        <p className="text-[10px] text-blue-400 capitalize mt-0.5">{roleLabel}</p>
                    </div>

                    {/* Menu items */}
                    <div className="py-1">
                        <Link
                            to="/profile"
                            id="profile-menu-link"
                            onClick={() => setOpen(false)}
                            className="flex items-center gap-2.5 px-4 py-2 text-xs text-theme-secondary hover:bg-theme-raised hover:text-theme-primary transition-colors"
                        >
                            <User size={13} className="text-theme-muted" />
                            My Profile
                        </Link>
                        <Link
                            to="/my-alerts"
                            id="my-alerts-menu-link"
                            onClick={() => setOpen(false)}
                            className="flex items-center gap-2.5 px-4 py-2 text-xs text-theme-secondary hover:bg-theme-raised hover:text-theme-primary transition-colors"
                        >
                            <BellRing size={13} className="text-theme-muted" />
                            My Alerts
                        </Link>
                        <Link
                            to="/transfers"
                            id="transfers-menu-link"
                            onClick={() => setOpen(false)}
                            className="flex items-center gap-2.5 px-4 py-2 text-xs text-theme-secondary hover:bg-theme-raised hover:text-theme-primary transition-colors"
                        >
                            <ArrowRightLeft size={13} className="text-theme-muted" />
                            Transfers
                        </Link>
                        <Link
                            to="/profile"
                            state={{ tab: 'security' }}
                            id="security-menu-link"
                            onClick={() => setOpen(false)}
                            className="flex items-center gap-2.5 px-4 py-2 text-xs text-theme-secondary hover:bg-theme-raised hover:text-theme-primary transition-colors"
                        >
                            <Settings size={13} className="text-theme-muted" />
                            Security Settings
                        </Link>
                    </div>

                    {/* Sign out */}
                    <div className="border-t border-theme py-1">
                        <button
                            id="sign-out-btn"
                            onClick={() => { setOpen(false); onLogout() }}
                            className="w-full flex items-center gap-2.5 px-4 py-2 text-xs text-red-400 hover:bg-red-950/40 transition-colors"
                        >
                            <LogOut size={13} />
                            Sign Out
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}

export default function Topbar({ onShowShortcuts }) {
    const username = useAuthStoreSelectors.use.userName()
    const role = useAuthStoreSelectors.use.role()
    const clear = useAuthStoreSelectors.use.clear()
    const navigate = useNavigate()
    const { theme, toggle } = useThemeStore()
    const clock = useClock()

    const handleLogout = async () => {
        await api.post('/auth/logout').catch(() => {})
        clear()
        navigate('/login')
    }

    return (
        <header className='h-11 flex items-center justify-between px-6 transition-colors duration-200 bg-theme-header border-b border-theme'>
            <span className='text-xs font-mono text-theme-muted tabular-nums'>{clock}</span>
            <div className='flex items-center gap-3'>
                <button
                    onClick={toggle}
                    className='text-theme-muted hover:text-blue-500 transition-colors'
                    title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                    {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
                </button>
                <button
                    onClick={onShowShortcuts}
                    className='text-theme-muted hover:text-blue-500 transition-colors'
                    title='Keyboard shortcuts (?)'
                >
                    <Keyboard size={14} />
                </button>

                {/* User dropdown menu */}
                <UserMenu username={username} role={role} onLogout={handleLogout} />
            </div>
        </header>
    )
}
