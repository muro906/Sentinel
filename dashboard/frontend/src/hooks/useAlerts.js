import {useQuery} from '@tanstack/react-query'
import api from '../lib/api'

// Fetches a paginated/filtered list of alerts; re-polls every 15 seconds
export function useAlerts(params){
    return useQuery({
        queryKey: ['alerts', params], // Cache key includes filters so each param set is cached separately
        queryFn: () => api.get('/alerts',{params}).then(res => res.data),
        refetchInterval: 15_000, // Keep the list fresh without a manual refresh
    })
}

// Fetches a single alert by ID; polls every 5s while a plan is executing so the
// UI detects the approved → closed transition without a manual refresh.
export function useAlert(alertId){
    return useQuery({
        queryKey: ['alert', alertId],
        queryFn: () => api.get(`/alerts/${alertId}`).then(res => res.data),
        enabled: !!alertId,
        // Poll during active investigation states so the UI transitions automatically:
        //   triaged        → agents running,  poll until plans appear
        //   plans_generated→ waiting for analyst action, no need to poll
        //   approved       → execution running, poll until closed
        refetchInterval: (query) => {
            const s = query.state.data?.approval_status
            return (s === 'triaged' || s === 'approved') ? 5_000 : false
        },
    })
}