import { NavLink } from "react-router-dom";
import { AlertTriangle, BookOpen, Server, Shield, LayoutDashboard, ShieldCheck, BellRing, ArrowRightLeft, ShieldAlert, ChevronLeft } from "lucide-react"
import { useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '../../store/auth'
import { cn } from '../../lib/utils'

const NAV = [
    { to: '/',            label: 'Overview',    Icon: LayoutDashboard },
    { to: '/alerts',      label: 'Alert Feed',  Icon: AlertTriangle,  badge: true },
    { to: '/my-alerts',   label: 'My Alerts',   Icon: BellRing,       myBadge: true },
    { to: '/transfers',   label: 'Transfers',   Icon: ArrowRightLeft, transferBadge: true },
    { to: '/escalations', label: 'Escalations', Icon: ShieldAlert,    escalationBadge: true, seniorOnly: true },
    { to: '/assets',      label: 'Assets',      Icon: Server },
    { to: '/cves',        label: 'CVE Browser', Icon: BookOpen },
    { to: '/admin',       label: 'Admin',       Icon: ShieldCheck,    adminOnly: true },
]

export default function Sidebar({ collapsed, onToggle }) {
    const qc = useQueryClient()
    const role = useAuthStore(state => state.role)
    const userName = useAuthStore(state => state.userName)
    const alertData = qc.getQueryData(['alerts', {}])
    const myAlertsData = qc.getQueryData(['alerts', 'my', { priority: '', status: '' }])
    const transferData = qc.getQueryData(['transfers', ''])
    const escalationData = qc.getQueryData(['escalations'])

    const activeCount = (alertData?.items ?? []).filter(
        a => ['received', 'triaged', 'plans_generated'].includes(a.approval_status)
    ).length
    const myCount = (myAlertsData?.items ?? []).filter(
        a => ['pending'].includes(a.approval_status)
    ).length
    const transferCount = (transferData?.items ?? []).filter(
        t => t.to_user === userName && t.status === 'pending'
    ).length
    const escalationCount = (escalationData?.items ?? []).filter(
        e => e.status === 'pending'
    ).length

    const isElevated = role === 'admin' || role === 'senior_analyst'

    return (
        <aside className="w-full h-full flex flex-col bg-theme-nav border-r border-theme overflow-hidden">
            {/* Header / collapse toggle */}
            <div className="border-b border-theme shrink-0">
                <button
                    onClick={onToggle}
                    className={cn(
                        "w-full flex items-center gap-2.5 transition-all duration-200",
                        "hover:bg-blue-500/10 active:bg-blue-500/15",
                        collapsed ? "justify-center px-4 py-4" : "px-5 py-4"
                    )}
                    title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                >
                    <Shield size={17} className="text-blue-500 shrink-0" />
                    {!collapsed && (
                        <>
                            <div className="flex-1 text-left min-w-0">
                                <div className="font-bold text-theme-primary text-sm tracking-wider">SENTINEL</div>
                                <div className="text-[11px] text-theme-muted leading-none mt-0.5">SOC Dashboard</div>
                            </div>
                            <ChevronLeft size={13} className="text-theme-muted shrink-0" />
                        </>
                    )}
                </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 py-2 overflow-y-auto overflow-x-hidden">
                {NAV
                    .filter(item => !item.adminOnly || role === 'admin')
                    .filter(item => !item.seniorOnly || isElevated)
                    .map(({ to, label, Icon, badge, myBadge, transferBadge, escalationBadge }) => {
                        const count = badge ? activeCount
                            : myBadge ? myCount
                            : transferBadge ? transferCount
                            : escalationBadge ? escalationCount
                            : 0
                        const badgeClass = badge ? 'bg-red-500'
                            : myBadge ? 'bg-blue-500'
                            : transferBadge ? 'bg-amber-500'
                            : 'bg-red-600'
                        const pulses = !!escalationBadge

                        return (
                            <NavLink
                                key={to}
                                to={to}
                                end={to === '/'}
                                title={collapsed ? label : undefined}
                                className={({ isActive }) =>
                                    cn(
                                        'flex items-center py-2 text-sm transition-all duration-150',
                                        collapsed ? 'justify-center px-4' : 'gap-2.5 px-5',
                                        isActive
                                            ? 'text-white bg-blue-600/20 border-r-2 border-blue-500'
                                            : 'text-theme-secondary hover:text-theme-primary hover:bg-theme-raised'
                                    )
                                }
                            >
                                <span className="relative shrink-0">
                                    <Icon size={14} />
                                    {collapsed && count > 0 && (
                                        <span className={cn(
                                            "absolute -top-1.5 -right-1.5 w-2 h-2 rounded-full",
                                            badgeClass,
                                            pulses && "animate-pulse"
                                        )} />
                                    )}
                                </span>
                                {!collapsed && (
                                    <>
                                        <span className="flex-1 truncate">{label}</span>
                                        {count > 0 && (
                                            <span className={cn(
                                                "text-xs text-white font-bold rounded-full px-1.5 py-0.5 leading-none shrink-0",
                                                badgeClass,
                                                pulses && "animate-pulse"
                                            )}>
                                                {count}
                                            </span>
                                        )}
                                    </>
                                )}
                            </NavLink>
                        )
                    })}
            </nav>

            {/* Expand hint shown at bottom when collapsed */}
            {collapsed && (
                <div className="border-t border-theme shrink-0 py-2 flex justify-center">
                    <button
                        onClick={onToggle}
                        title="Expand sidebar"
                        className="p-1.5 rounded-md text-theme-muted hover:text-theme-primary hover:bg-theme-raised transition-colors"
                    >
                        <ChevronLeft size={13} className="rotate-180" />
                    </button>
                </div>
            )}
        </aside>
    )
}
