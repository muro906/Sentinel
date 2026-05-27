import {clsx} from 'clsx'
import {twMerge} from 'tailwind-merge'

import {formatDistanceToNow, parseISO} from 'date-fns'

// Merges Tailwind classes safely, resolving conflicts via tailwind-merge
export function cn(...inputs){
    return twMerge(clsx(inputs))
}

// Return distance between now and given date in words
export function timeAgo(iso){
    try{
        return formatDistanceToNow(parseISO(iso), {addSuffix: true})
    } catch {
        return iso
    }
}

// Maps an alert priority level to Tailwind text/border/background classes
// Falls back to neutral slate styles for unknown values
export function priorityColor(p){
    return({
        critical: 'text-red-400 border-red-800 bg-red-950',
        high: 'text-amber-400 border-amber-800 bg-amber-950',
        medium: 'text-blue-400 border-blue-800 bg-blue-950',
        low: 'text-slate-400 border-slate-700 bg-slate-800/60'
    })[p.toLowerCase()] ?? 'text-slate-400 border-slate-700 bg-slate-800/60'
}

// Maps an alert/incident status to Tailwind text/background classes
// Falls back to neutral slate styles for unknown values
export function statusColor(s){
    return({
        received: 'text-slate-400 bg-slate-700/60',
        triaged: 'text-blue-300 bg-blue-950/80',
        plans_generated: 'text-violet-300 bg-violet-950',
        pending: 'text-amber-300 bg-amber-950',
        approved: 'text-emerald-300 bg-emerald-950',
        rejected: 'text-red-300 bg-red-950',
        executed: 'text-emerald-300 bg-emerald-950',
        closed: 'text-slate-400 bg-slate-700/60'
    })[s.toLowerCase()] ?? 'text-slate-400 bg-slate-700/60'
}
