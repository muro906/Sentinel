import { useNavigate } from 'react-router-dom'
import { AlertTriangle, CheckCircle, Clock, ShieldAlert, Activity, ArrowRight } from 'lucide-react'
import { useAlerts } from '../hooks/useAlerts'
import { PageSpinner } from '../components/ui/Spinner'
import { timeAgo } from '../lib/utils'
import { Badge } from '../components/ui/Badge'

const PRIORITY_ORDER = ['critical', 'high', 'medium', 'low']
const STATUS_ORDER   = ['received', 'triaged', 'plans_generated', 'approved', 'rejected', 'executed', 'closed']

const PRIORITY_STYLE = {
  critical: { bar: 'bg-red-500',    label: 'text-red-400'    },
  high:     { bar: 'bg-amber-500',  label: 'text-amber-400'  },
  medium:   { bar: 'bg-blue-500',   label: 'text-blue-400'   },
  low:      { bar: 'bg-slate-500',  label: 'text-slate-400'  },
}

function StatCard({ icon: Icon, label, value, sub, iconClass }) {
  return (
    <div className="bg-theme-surface border border-theme rounded-lg p-4 flex items-start gap-3">
      <div className={`p-2 rounded-lg bg-theme-raised ${iconClass}`}>
        <Icon size={16} />
      </div>
      <div>
        <p className="text-xs text-theme-muted">{label}</p>
        <p className="text-2xl font-bold text-theme-primary leading-none mt-0.5">{value}</p>
        {sub && <p className="text-xs text-theme-muted mt-1">{sub}</p>}
      </div>
    </div>
  )
}

export default function Overview() {
  const navigate = useNavigate()
  const { data, isLoading } = useAlerts({})

  if (isLoading) return <PageSpinner />

  const alerts = data?.items ?? []
  const total  = alerts.length

  // Counts by priority
  const byPriority = PRIORITY_ORDER.reduce((acc, p) => {
    acc[p] = alerts.filter(a => a.priority === p).length
    return acc
  }, {})

  // Counts by status
  const byStatus = STATUS_ORDER.reduce((acc, s) => {
    acc[s] = alerts.filter(a => a.approval_status === s).length
    return acc
  }, {})

  const critical    = byPriority.critical ?? 0
  const needsAction = (byStatus.received ?? 0) + (byStatus.triaged ?? 0) + (byStatus.plans_generated ?? 0)
  const resolved    = (byStatus.executed ?? 0) + (byStatus.closed ?? 0)

  // 5 most recent alerts
  const recent = [...alerts]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5)

  return (
    <div className="space-y-6">
      {/* Page title */}
      <div>
        <h1 className="text-base font-semibold text-theme-primary">Overview</h1>
        <p className="text-xs text-theme-muted mt-0.5">Current operational status</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={ShieldAlert}   label="Total Alerts"    value={total}       iconClass="text-blue-400"    />
        <StatCard icon={AlertTriangle} label="Critical"         value={critical}    iconClass="text-red-400"     sub={critical > 0 ? 'Requires immediate attention' : 'No critical alerts'} />
        <StatCard icon={Clock}         label="Awaiting Action"  value={needsAction} iconClass="text-amber-400"   sub="received + triaged + pending" />
        <StatCard icon={CheckCircle}   label="Resolved"         value={resolved}    iconClass="text-emerald-400" sub="executed + closed" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Priority breakdown */}
        <div className="bg-theme-surface border border-theme rounded-lg p-4">
          <h2 className="text-xs font-semibold text-theme-primary mb-3 flex items-center gap-1.5">
            <Activity size={13} /> Alerts by Priority
          </h2>
          <div className="space-y-2.5">
            {PRIORITY_ORDER.map(p => {
              const count = byPriority[p] ?? 0
              const pct   = total > 0 ? (count / total) * 100 : 0
              const style = PRIORITY_STYLE[p]
              return (
                <div key={p}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className={`capitalize font-medium ${style.label}`}>{p}</span>
                    <span className="text-theme-muted">{count} ({pct.toFixed(0)}%)</span>
                  </div>
                  <div className="h-1.5 bg-theme-raised rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${style.bar} transition-all duration-500`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Status breakdown */}
        <div className="bg-theme-surface border border-theme rounded-lg p-4">
          <h2 className="text-xs font-semibold text-theme-primary mb-3">Alerts by Status</h2>
          <div className="grid grid-cols-2 gap-2">
            {STATUS_ORDER.map(s => {
              const count = byStatus[s] ?? 0
              if (count === 0) return null
              return (
                <div key={s} className="flex items-center justify-between bg-theme-raised rounded px-2.5 py-1.5">
                  <span className="text-xs text-theme-secondary capitalize">{s.replace('_', ' ')}</span>
                  <Badge variant="status" value={s}>{count}</Badge>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent alerts */}
      <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-theme">
          <h2 className="text-xs font-semibold text-theme-primary">Recent Alerts</h2>
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            View all <ArrowRight size={11} />
          </button>
        </div>
        <table className="w-full text-xs">
          <tbody>
            {recent.map(a => (
              <tr
                key={a.alert_id}
                onClick={() => navigate(`/alerts/${a.alert_id}`)}
                className="border-t border-theme hover:bg-theme-raised cursor-pointer transition-colors"
              >
                <td className="px-4 py-2.5 text-theme-muted whitespace-nowrap w-28">{timeAgo(a.created_at)}</td>
                <td className="px-4 py-2.5 text-theme-primary font-mono">{a.classification}</td>
                <td className="px-4 py-2.5"><Badge variant="priority" value={a.priority}>{a.priority}</Badge></td>
                <td className="px-4 py-2.5"><Badge variant="status" value={a.approval_status}>{a.approval_status}</Badge></td>
                <td className="px-4 py-2.5 text-theme-muted text-right">{a.src_ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
