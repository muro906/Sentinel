import {cn, priorityColor, statusColor} from '../../lib/utils'

export function Badge({children, variant= 'default', value ='', className}){
    const color = 
    variant === 'priority' ? priorityColor(value) :
    variant === 'status' ? statusColor(value) :
    'text-theme-secondary bg-theme-raised'

    return(
        <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border border-transparent', color,className)}>
            {children}
        </span>
    )
}