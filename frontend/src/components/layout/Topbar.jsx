import {useNavigate} from 'react-router-dom'
import {LogOut} from 'lucide-react'
import api from '../../lib/api'
import {useAuthStoreSelectors} from '../../store/auth'

export default function Topbar(){
    const username = useAuthStoreSelectors.use.userName();
    const role = useAuthStoreSelectors.use.role();
    const clear = useAuthStoreSelectors.use.clear();
    const navigate = useNavigate()

    const handleLogout = async () => {
        await api.post('/auth/logout').catch(() => {});
        clear();
        navigate('/login')
    }
    
    return (
        <header className='h-11 bg-slate-950 border-b border-slate-800 flex items-center justify-end px-6'>
            <span className='text-blue-400 capitalize'>
                {role?.replace('_', ' ')}
            </span>
            <button onClick={handleLogout} className='flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors'>
                <LogOut size={13}/> Sign Out
            </button>

        </header>
    )
}
