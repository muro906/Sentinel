import { NavLink } from "react-router-dom";
import { AlertTriangle, BookOpen, Server, Shield, LayoutDashboard, ShieldCheck, BellRing, ArrowRightLeft, ShieldAlert } from "lucide-react"
import { useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '../../store/auth'
import { cn } from '../../lib/utils'

const NAV = [
    {to: '/',             label: 'Overview',      Icon: LayoutDashboard},
    {to: '/alerts',       label: 'Alert Feed',    Icon: AlertTriangle,    badge: true},
    {to: '/my-alerts',    label: 'My Alerts',     Icon: BellRing,         myBadge: true},
    {to: '/transfers',    label: 'Transfers',     Icon: ArrowRightLeft,   transferBadge: true},
    {to: '/escalations',  label: 'Escalations',   Icon: ShieldAlert,      escalationBadge: true, seniorOnly: true},
    {to: '/assets',       label: 'Assets',        Icon: Server},
    {to: '/cves',         label: 'CVE Browser',   Icon: BookOpen},
    {to: '/admin',        label: 'Admin',         Icon: ShieldCheck,      adminOnly: true},
]

export default function Sidebar() {
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
        <aside className="w-56 shrink-0 flex flex-col transition-colors duration-200 bg-theme-nav border-r border-theme">
            <div className="px-5 py-4 border-b border-theme">
                <div className="flex items-center gap-2">
                    <Shield size={16} className="text-blue-500" />
                    <span className="font-bold text-theme-primary text-sm tracking-wider">SENTINEL</span>
                </div>
                <p className="text-xs text-theme-muted mt-0.5">SOC Dashboard</p>
            </div>
            <nav className="flex-1 py-2">
                {NAV
                  .filter(item => !item.adminOnly || role === 'admin')
                  .filter(item => !item.seniorOnly || isElevated)
                  .map(({ to, label, Icon, badge, myBadge, transferBadge, escalationBadge }) => (
                    <NavLink
                        key={to}
                        to={to}
                        end={to === '/'}
                        className={({ isActive }) =>
                            cn('flex items-center gap-2.5 px-5 py-2 text-sm transition-colors', isActive
                                ? 'text-white bg-blue-600/20 border-r-2 border-blue-500'
                                : 'text-theme-secondary hover:text-theme-primary hover:bg-theme-raised'
                            )
                        }
                    >
                        <Icon size={14} />
                        <span className="flex-1">{label}</span>
                        {badge && activeCount > 0 && (
                            <span className="text-xs bg-red-500 text-white font-bold rounded-full px-1.5 py-0.5 leading-none">
                                {activeCount}
                            </span>
                        )}
                        {myBadge && myCount > 0 && (
                            <span className="text-xs bg-blue-500 text-white font-bold rounded-full px-1.5 py-0.5 leading-none">
                                {myCount}
                            </span>
                        )}
                        {transferBadge && transferCount > 0 && (
                            <span className="text-xs bg-amber-500 text-white font-bold rounded-full px-1.5 py-0.5 leading-none">
                                {transferCount}
                            </span>
                        )}
                        {escalationBadge && escalationCount > 0 && (
                            <span className="text-xs bg-red-600 text-white font-bold rounded-full px-1.5 py-0.5 leading-none animate-pulse">
                                {escalationCount}
                            </span>
                        )}
                    </NavLink>
                ))}
            </nav>
        </aside>
    )
}