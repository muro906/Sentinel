import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'

export default function Assets() {
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)

  const { data, isLoading } = useQuery({
    queryKey: ['assets', search],
    queryFn:  () => api.get('/assets', { params: search ? { search } : {} }).then(r => r.data),
    staleTime: 60_000,
  })

  if (isLoading) return <PageSpinner />
  const assets = data?.items ?? []

  return (
    <div>
      <div className="flex items-center justify-between mb-5">
        <h1 className="text-base font-semibold text-theme-primary">
          Assets
          <span className="ml-2 text-xs text-theme-muted font-normal">{data?.total ?? 0} total</span>
        </h1>
        <div className="relative">
          <Search size={12} className="absolute left-2.5 top-2 text-theme-muted" />
          <input
            className="bg-theme-raised border border-theme text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500"
            placeholder="Search hostname or IP…"
            value={search} onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden transition-colors duration-200">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-theme-raised text-theme-muted text-left">
              {['Hostname','IP','Zone','OS','Type','Tier'].map(h => (
                <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <>
                <tr
                  key={a.id}
                  onClick={() => setExpanded(expanded === a.id ? null : a.id)}
                  className="border-t border-theme hover:bg-theme-raised cursor-pointer transition-colors"
                >
                  <td className="px-4 py-2.5 text-theme-primary font-medium">{a.hostname}</td>
                  <td className="px-4 py-2.5 font-mono text-theme-secondary">{a.ip_address}</td>
                  <td className="px-4 py-2.5 text-theme-secondary">{a.zone_name}</td>
                  <td className="px-4 py-2.5 text-theme-secondary">{a.os}</td>
                  <td className="px-4 py-2.5 text-theme-secondary">{a.asset_type}</td>
                  <td className="px-4 py-2.5">
                    <Badge variant="default">Tier {a.criticality_tier}</Badge>
                  </td>
                </tr>
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}