import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Globe, Database, Loader2 } from 'lucide-react'
import api from '../lib/api'
import { PageSpinner } from '../components/ui/Spinner'
import { cn } from '../lib/utils'

function cvssColour(score) {
  if (score >= 9)  return 'text-red-400'
  if (score >= 7)  return 'text-amber-400'
  if (score >= 4)  return 'text-yellow-400'
  return 'text-slate-400'
}

function CVETable({ cves, expanded, onToggle }) {
  if (cves.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-2">
        <Globe size={32} className="text-theme-muted opacity-30" />
        <p className="text-sm text-theme-muted">No CVEs found</p>
      </div>
    )
  }
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="bg-theme-raised text-theme-muted text-left">
          {['CVE ID', 'CVSS', 'Severity', 'Product', 'Vector', 'Exploit'].map(h => (
            <th key={h} className="px-4 py-2.5 font-medium">{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {cves.map(c => (
          <>
            <tr
              key={c.cve_id}
              onClick={() => onToggle(c.cve_id)}
              className="border-t border-theme hover:bg-theme-raised cursor-pointer transition-colors"
            >
              <td className="px-4 py-2.5 font-mono text-blue-400">{c.cve_id}</td>
              <td className={`px-4 py-2.5 font-bold ${cvssColour(c.cvss_v3_score)}`}>
                {c.cvss_v3_score?.toFixed(1) ?? '—'}
              </td>
              <td className="px-4 py-2.5 text-theme-primary capitalize">{c.severity?.toLowerCase()}</td>
              <td className="px-4 py-2.5 text-theme-primary">{c.affected_product ?? '—'}</td>
              <td className="px-4 py-2.5 text-theme-secondary font-mono">{c.attack_vector ?? '—'}</td>
              <td className="px-4 py-2.5">
                {c.exploit_available
                  ? <span className="text-red-400 font-semibold">⚡ Yes</span>
                  : <span className="text-theme-muted">—</span>}
              </td>
            </tr>
            {expanded === c.cve_id && (
              <tr key={`${c.cve_id}-desc`} className="border-t border-theme bg-theme-raised/50">
                <td colSpan={6} className="px-4 py-3">
                  <p className="text-theme-secondary leading-relaxed text-xs">{c.description}</p>
                </td>
              </tr>
            )}
          </>
        ))}
      </tbody>
    </table>
  )
}

export default function CVEBrowser() {
  const [search,      setSearch]      = useState('')
  const [minCvss,     setMinCvss]     = useState(0)
  const [exploitOnly, setExploitOnly] = useState(false)
  const [expanded,    setExpanded]    = useState(null)
  const [mode,        setMode]        = useState('local')  // 'local' | 'nvd'
  const [nvdInput,    setNvdInput]    = useState('')
  const [nvdSearch,   setNvdSearch]   = useState('')       // committed on Enter / button click

  // ── Local DB ────────────────────────────────────────────────────────────────
  const localQ = useQuery({
    queryKey: ['cves', search, minCvss, exploitOnly],
    queryFn:  () => api.get('/cves', {
      params: {
        ...(search      ? { search }            : {}),
        ...(minCvss     ? { min_cvss: minCvss } : {}),
        ...(exploitOnly ? { exploit_only: true } : {}),
      },
    }).then(r => r.data),
    staleTime: 120_000,
    enabled: mode === 'local',
  })

  // ── NVD Live ────────────────────────────────────────────────────────────────
  const nvdQ = useQuery({
    queryKey: ['cves-nvd', nvdSearch, minCvss, exploitOnly],
    queryFn:  () => api.get('/cves/search-nvd', {
      params: {
        q:     nvdSearch,
        limit: 40,
        ...(minCvss     ? { min_cvss: minCvss }  : {}),
        ...(exploitOnly ? { exploit_only: true }  : {}),
      },
    }).then(r => r.data),
    staleTime: 300_000,
    enabled: mode === 'nvd' && nvdSearch.length >= 2,
  })

  const isLocal    = mode === 'local'
  const activeQ    = isLocal ? localQ : nvdQ
  const cves       = activeQ.data?.items ?? []
  const isSearching = !isLocal && nvdQ.isFetching

  const commitNvdSearch = () => {
    if (nvdInput.trim().length >= 2) setNvdSearch(nvdInput.trim())
  }

  if (isLocal && localQ.isLoading) return <PageSpinner />

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-base font-semibold text-theme-primary">CVE Browser</h1>
          <p className="text-xs text-theme-muted mt-0.5">
            {isLocal
              ? `${localQ.data?.total ?? 0} entries in local database`
              : nvdSearch
                ? `${cves.length} results from NIST NVD — saved to local DB`
                : 'Enter a keyword to query NIST NVD live'}
          </p>
        </div>

        {/* Local / NVD toggle */}
        <div className="flex bg-theme-surface border border-theme rounded-lg overflow-hidden">
          <button
            onClick={() => setMode('local')}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors',
              isLocal ? 'bg-blue-600 text-blue-100' : 'text-theme-secondary hover:text-theme-primary'
            )}
          >
            <Database size={11} /> Local DB
          </button>
          <button
            onClick={() => setMode('nvd')}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors',
              !isLocal ? 'bg-blue-600 text-blue-100' : 'text-theme-secondary hover:text-theme-primary'
            )}
          >
            <Globe size={11} /> NVD Live
          </button>
        </div>
      </div>

      {/* Search / filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {isLocal ? (
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-2 text-theme-muted" />
            <input
              className="bg-theme-raised border border-theme text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-52"
              placeholder="CVE ID, product, keyword…"
              value={search} onChange={e => setSearch(e.target.value)}
            />
          </div>
        ) : (
          <div className="flex items-center gap-1.5">
            <div className="relative">
              <Globe size={12} className="absolute left-2.5 top-2 text-blue-400" />
              <input
                className="bg-theme-raised border border-blue-500/40 text-xs text-theme-primary rounded pl-7 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-52"
                placeholder="e.g. log4shell, openssh, smb…"
                value={nvdInput}
                onChange={e => setNvdInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && commitNvdSearch()}
              />
            </div>
            <button
              onClick={commitNvdSearch}
              disabled={nvdInput.trim().length < 2 || isSearching}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded transition-colors"
            >
              {isSearching
                ? <Loader2 size={11} className="animate-spin" />
                : <Search size={11} />}
              Search NVD
            </button>
          </div>
        )}

        <select
          value={minCvss} onChange={e => setMinCvss(Number(e.target.value))}
          className="bg-theme-raised border border-theme text-xs text-theme-primary rounded px-2 py-1.5"
        >
          <option value={0}>CVSS ≥ 0</option>
          <option value={4}>CVSS ≥ 4</option>
          <option value={7}>CVSS ≥ 7</option>
          <option value={9}>CVSS ≥ 9 (Critical)</option>
        </select>

        <label className="flex items-center gap-1.5 text-xs text-theme-secondary cursor-pointer">
          <input type="checkbox" checked={exploitOnly}
            onChange={e => setExploitOnly(e.target.checked)} className="accent-blue-500" />
          Exploit known
        </label>
      </div>

      {/* NVD info hint */}
      {!isLocal && !nvdSearch && (
        <div className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-blue-950/30 border border-blue-700/40 text-xs text-blue-300">
          <Globe size={13} className="text-blue-400 shrink-0" />
          Searches the <strong className="text-blue-200">NIST National Vulnerability Database</strong> in real time.
          Results are automatically cached in the Local DB view.
        </div>
      )}

      {/* Results */}
      <div className="bg-theme-surface border border-theme rounded-lg overflow-hidden">
        {isSearching ? (
          <div className="flex items-center justify-center gap-2 py-16 text-xs text-theme-muted">
            <Loader2 size={16} className="animate-spin text-blue-400" />
            Querying NIST NVD…
          </div>
        ) : (
          <CVETable
            cves={cves}
            expanded={expanded}
            onToggle={id => setExpanded(expanded === id ? null : id)}
          />
        )}
      </div>
    </div>
  )
}
