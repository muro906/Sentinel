import{cn} from '../../lib/utils'

export function Card({children, className}){
    return(
        <div className={cn('rounded-lg pb-4 p-4 transition-colors duration-200 bg-theme-surface border border-theme', className)}>
            {children}
        </div>
    )
}

export function CardHeader({children, className}){
    return(
        <div className={cn('flex items-center justify-between mb-3', className)}>
            {children}
        </div>
    )
}
export function CardTitle({children}){
    return <h3 className="text-sm font-semibold text-theme-primary">{children}</h3>
}