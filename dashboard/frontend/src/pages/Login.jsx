import {useState} from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import {Shield, UserPlus} from 'lucide-react'
import {Link} from 'react-router-dom'
import {useAuthStore} from '../store/auth'
import {Spinner} from '../components/ui/Spinner'

export default function Login(){
    const [userName, setUserName] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const setTokens = useAuthStore(state => state.setTokens)
    const [loading, setLoading] = useState(false)
    const navigate = useNavigate()

    const handleSubmit = async e => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try{
            const params = new URLSearchParams({username: userName, password});
            const {data} = await axios.post('/api/auth/login', params, {withCredentials: true});

            // Guard against malformed token — never let raw exception surface
            let payload
            try {
                payload = JSON.parse(atob(data.access_token.split('.')[1]))
            } catch {
                setError('Authentication failed. Please try again.')
                return
            }
            setTokens(data.access_token, payload.sub, payload.role)
            navigate('/')
        } catch(err){
            // Normalise error messages — never expose raw server internals to the UI
            const status = err?.response?.status
            if (status === 401 || status === 403) {
                setError('Invalid username or password.')
            } else if (status >= 500) {
                setError('Server error. Please try again later.')
            } else {
                setError('Login failed. Check your connection and try again.')
            }
        } finally {
            setLoading(false)
        }

    }
    return (
        <div className="min-h-screen bg-theme-base flex items-center justify-center p-4">
            <div className="w-full max-w-sm">
                <div className="flex flex-col items-center mb-8">
                    <div className="bg-blue-600/20 border border-blie-600/40 rounded-xl p-3 mb-3">
                        <Shield 
                        size={24}
                        className="text-blue-400" />
                    </div>
                    <h1 className="text-xl font-bold text-theme-primary">Sentinel SOC</h1>
                    <p className="text-xs text-theme-muted mt-1">Sign in to your analyst account</p>
                </div>
                <form onSubmit={handleSubmit} className='bg-theme-surface border border-theme rounded-xl p-6 space-y-4'>
                    {error &&(
                        <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>
                    )}
                    <div>
                        <label className="text-xs text-theme-secondary block mb-1">Username</label>
                        <input type="text" 
                        value={userName} className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500" 
                        onChange={e =>{setUserName(e.target.value)}}
                        autoComplete='username' required/>
                        
                    </div>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label className="text-xs text-theme-secondary">Password</label>
                            <Link
                                to="/forgot-password"
                                id="forgot-password-link"
                                className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                            >
                                Forgot password?
                            </Link>
                        </div>
                        <input type="password" className='w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500'
                        value={password}
                        onChange={e=>{setPassword(e.target.value)}} autoComplete='current-password' required/>
                    </div>
                    <button type="submit" disabled={loading} className='w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 disabled:cursor-not-allowed text-blue-100 text-sm font-semibold rounded py-2 transition-colors flex items-center justify-center gap-2'>
                        {loading && <Spinner className='h-4 w-4'/>}
                        Sign In
                    </button>
                </form>
                
                <div className="mt-6 text-center">
                    <Link 
                        to="/register" 
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center justify-center gap-1 transition-colors"
                    >
                        <UserPlus size={12} />
                        Create Account
                    </Link>
                    <p className="text-xs text-theme-muted mt-2">
                        Requires admin approval
                    </p>
                </div>
            </div>
        </div>
    )

}