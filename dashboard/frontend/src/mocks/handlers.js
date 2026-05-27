import { http, HttpResponse } from 'msw'
import { ALERTS, PLANS, TRACES, CVES, ASSETS, ANALYSTS } from './data'

function makeMockToken() {
  const payload = btoa(JSON.stringify({ sub: 'analyst01', role: 'admin', exp: 9999999999 })).replace(/=/g,'')
  return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.mock-signature`
}

export const handlers = [
  // Auth
  http.post('/api/auth/login', () =>
    HttpResponse.json({ access_token: makeMockToken() })
  ),
  http.post('/api/auth/refresh', () =>
    HttpResponse.json({ access_token: makeMockToken() })
  ),
  http.post('/api/auth/logout', () =>
    new HttpResponse(null, { status: 204 })
  ),

  // Alerts list
  http.get('/api/alerts', ({ request }) => {
    const url = new URL(request.url)
    const priority = url.searchParams.get('priority')
    const status = url.searchParams.get('status')
    let items = ALERTS
    if (priority) items = items.filter(a => a.priority === priority)
    if (status)   items = items.filter(a => a.approval_status === status)
    return HttpResponse.json({ items, total: items.length })
  }),

  // Single alert
  http.get('/api/alerts/:id', ({ params }) => {
    const alert = ALERTS.find(a => a.alert_id === params.id)
    if (!alert) return new HttpResponse(null, { status: 404 })
    return HttpResponse.json(alert)
  }),

  // Plans
  http.get('/api/alerts/:id/plans', ({ params }) => {
    const plans = PLANS[params.id] ?? { plans: [] }
    return HttpResponse.json(plans)
  }),
  http.post('/api/alerts/:id/approve', () =>
    HttpResponse.json({ status: 'approved' })
  ),
  http.post('/api/alerts/:id/reject', () =>
    HttpResponse.json({ status: 'rejected' })
  ),

  // Trace
  http.get('/api/alerts/:id/trace', ({ params }) => {
    const events = TRACES[params.id] ?? []
    return HttpResponse.json(events)
  }),

  // CVEs
  http.get('/api/cves', ({ request }) => {
    const url = new URL(request.url)
    const search = url.searchParams.get('search')?.toLowerCase()
    const minCvss = parseFloat(url.searchParams.get('min_cvss') ?? '0')
    const exploitOnly = url.searchParams.get('exploit_only') === 'true'
    let items = CVES
    if (search)      items = items.filter(c => c.cve_id.toLowerCase().includes(search) || c.affected_product.toLowerCase().includes(search))
    if (minCvss)     items = items.filter(c => c.cvss_v3_score >= minCvss)
    if (exploitOnly) items = items.filter(c => c.exploit_available)
    return HttpResponse.json({ items, total: items.length })
  }),

  // Admin
  http.get('/api/admin/analysts', () =>
    HttpResponse.json({ analysts: ANALYSTS })
  ),

  http.post('/api/alerts/:id/assign', async ({ params, request }) => {
    const { analyst_id } = await request.json()
    const alert = ALERTS.find(a => a.alert_id === params.id)
    if (!alert) return new HttpResponse(null, { status: 404 })
    alert.assigned_to = analyst_id
    return HttpResponse.json({ alert_id: params.id, assigned_to: analyst_id })
  }),

  // Assets
  http.get('/api/assets', ({ request }) => {
    const url = new URL(request.url)
    const search = url.searchParams.get('search')?.toLowerCase()
    let items = ASSETS
    if (search) items = items.filter(a => a.hostname.toLowerCase().includes(search) || a.ip_address.includes(search))
    return HttpResponse.json({ items, total: items.length })
  }),
]
