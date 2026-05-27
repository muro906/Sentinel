import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import api from '../lib/api'
import { Badge } from '../components/ui/Badge'
import { PageSpinner } from '../components/ui/Spinner'

function cvssColour(score) {
  if (score >= 9)  return 'text-red-400'
  if (score >= 7)  return 'text-amber-400'
  if (score >= 4)  return 'text-yellow-400'
  return 'text-slate-400'
}

export default function CVEBrowser() {
  const [search,      setSearch]      = useState('')
  const [minCvss,     setMinCvss]     = useState(0)
  const [exploitOnly, setExploitOnly] = useState(false)
  const [expanded,    setExpanded]    = useState(null)

  const { data, isLoading } = useQuery({
    queryKey: ['cves', search, minCvss, exploitOnly],
    queryFn:  () => api.get('/cves', {
      params: {
        ...(search      ? { search }           : {}),
        ...(minCvss     ? { min_cvss: minCvss } : {}),
        ...(exploitOnly ? { exploit_only: true }: {}),
      },
    }).then(r => r.data),
    staleTime: 120_000,
  })

  if (isLoading) return <PageSpinner />
  const cves = data?.items ?? []

  return (
    <div>
      <div className="flex items-center justify-between mb-5">
        <h1 className="text-base font-semibold text-theme-primary">
          CVE Browser
          <span className="ml-2 text-xs text-theme-muted font-normal">{data?.total ?? 0} entries</span>
        </h1>
        <div className="flex gap-2 items-center">
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-2 text-theme-muted" />
            <input
              className="bg-theme-raised border border-theme text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500"
              placeholder="CVE ID, product…"
              value={search} onChange={e => setSearch(e.target.value)}
            />
          </div>
          <select value={minCvss} onChange={e => setMinCvss(Number(e.target.value))}
            className="bg-theme-raised border border-theme text-xs text-theme-primary rounded px-2 py-1.5">
            <option value={0}>CVSS ≥ 0</option>
            <option value={4}>CVSS ≥ 4</option>
            <option value={7}>CVSS ≥ 7</option>
            <option value={9}>CVSS ≥ 9</option>
          </select>
          <label className="flex items-center gap-1.5 text-xs text-theme-secondary cursor-pointer">
            <input type="checkbox" checked={exploitOnly} onChange={e => setExploitOnly(e.target.checked)}
              className="accent-blue-500" />
            Exploit only
          </label>
        </div>
      </div>

      <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden transition-colors duration-200">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-theme-raised text-theme-muted text-left">
              {['CVE ID','CVSS','Severity','Product','Vector','Exploit'].map(h => (
                <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cves.map((c) => (
              <>
                <tr
                  key={c.cve_id}
                  onClick={() => setExpanded(expanded === c.cve_id ? null : c.cve_id)}
                  className="border-t border-theme hover:bg-theme-raised cursor-pointer transition-colors"
                >
                  <td className="px-4 py-2.5 font-mono text-blue-500">{c.cve_id}</td>
                  <td className={`px-4 py-2.5 font-bold ${cvssColour(c.cvss_v3_score)}`}>
                    {c.cvss_v3_score?.toFixed(1) ?? '—'}
                  </td>
                  <td className="px-4 py-2.5 text-theme-primary capitalize">{c.severity?.toLowerCase()}</td>
                  <td className="px-4 py-2.5 text-theme-primary">{c.affected_product}</td>
                  <td className="px-4 py-2.5 text-theme-secondary font-mono">{c.attack_vector}</td>
                  <td className="px-4 py-2.5">
                    {c.exploit_available
                      ? <span className="text-red-400 font-semibold">⚡ Yes</span>
                      : <span className="text-theme-muted">—</span>}
                  </td>
                </tr>
                {expanded === c.cve_id && (
                  <tr className="border-t border-theme bg-theme-raised">
                    <td colSpan={6} className="px-4 py-3">
                      <p className="text-theme-secondary leading-relaxed">{c.description}</p>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}