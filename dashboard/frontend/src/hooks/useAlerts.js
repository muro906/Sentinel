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

// Fetches a single alert by ID; does not run until a valid alertid is provided
export function useAlert(alertId){
    return useQuery({
        queryKey: ['alert', alertId],
        queryFn: () => api.get(`/alerts/${alertId}`).then(res => res.data),
        enabled: !!alertId, // Prevents fetching when alertid is null/undefined
    })
}