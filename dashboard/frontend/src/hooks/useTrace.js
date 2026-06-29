import { useCallback, useState } from "react";
import {useQuery} from "@tanstack/react-query";
import api from "../lib/api";
import {useWebSocket} from './useWebSocket'

export function useTrace(alertId){
    const [live, setLive] = useState([]);
    const query = useQuery({
        queryKey: ['trace', alertId],
        queryFn: () => api.get(`/traces/${alertId}/trace`).then(res => res.data),
        enabled: !!alertId,
        // Poll every 4 s so traces appear in real time during an active investigation.
        // The backend merges Postgres (durable) + Redis (live), so this always returns
        // the complete picture without duplicates.
        refetchInterval: 4000,
        staleTime: 0,
    })

    // Append each incoming WebSocket frame to the live events list
    const onMessage = useCallback((e) => setLive(p =>[...p, e]), [])
    // Subscribe to live trace events over WebSocket; only connects when alertId is valid
    useWebSocket(`/ws/alerts/${alertId}/trace`, onMessage, !!alertId)

    // Merge historical and live events, deduplicating by event_id
    // Historical data comes first; live events may overlap on reconnect
    const seen = new Set();
    const all = [...(query.data ?? []), ...live];

    const merged = all.filter(e => {
        if (seen.has(e.event_id)) return false; seen.add(e.event_id); return true;
    })
    
    return {events: merged, isLoading: query.isLoading};
}
