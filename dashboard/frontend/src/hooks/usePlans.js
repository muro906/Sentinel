import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import api from '../lib/api'
import { useToastStore } from '../components/ui/Toast'

export function usePlans(alertId){
    return useQuery({
        queryKey: ['plans', alertId],
        queryFn: () => api.get(`/plans/${alertId}/plans`).then(res => res.data),
        enabled: !!alertId,
    })
}

export function useApprovePlan(alertId, { onDone } = {}) {
    const qc = useQueryClient()
    const toast = useToastStore(s => s.push)
    return useMutation({
        mutationFn: (body) => api.post(`/plans/${alertId}/approve`, body).then(res => res.data),
        onSuccess: (data) => {
            qc.invalidateQueries({queryKey: ['plans', alertId]})
            qc.invalidateQueries({queryKey: ['alert', alertId]})
            qc.invalidateQueries({queryKey: ['alerts']})
            toast({ type: 'success', title: 'Plan approved ✓', message: 'Plan queued for execution. Returning to alerts…' })
            onDone?.('approved')
        },
        onError: (err) => {
            const msg = err?.response?.data?.detail || 'Could not approve plan'
            toast({ type: 'error', title: 'Approval failed', message: msg })
        }
    })
}

export function useRejectPlan(alertId, { onDone } = {}) {
    const qc = useQueryClient()
    const toast = useToastStore(s => s.push)
    return useMutation({
        mutationFn: (body) => api.post(`/plans/${alertId}/reject`, body).then(res => res.data),
        onSuccess: () => {
            qc.invalidateQueries({queryKey: ['plans', alertId]})
            qc.invalidateQueries({queryKey: ['alert', alertId]})
            qc.invalidateQueries({queryKey: ['alerts']})
            toast({ type: 'info', title: 'Plan rejected', message: 'Plan has been rejected. Returning to alerts…' })
            onDone?.('rejected')
        },
        onError: (err) => {
            const msg = err?.response?.data?.detail || 'Could not reject plan'
            toast({ type: 'error', title: 'Rejection failed', message: msg })
        }
    })
}