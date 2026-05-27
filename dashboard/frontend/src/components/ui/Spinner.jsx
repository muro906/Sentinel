import {cn} from '../../lib/utils'
export function Spinner({className}){
    return(
        <div className={cn('h-5 w-5 rounded-full border-2 border-theme border-t-blue-500 animate-spin', className)}/>
    )
}
export function PageSpinner(){
    return(
        <div className="flex items-center justify-center h-48">
            <Spinner />
        </div>
    )
}