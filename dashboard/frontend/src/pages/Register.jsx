import {useState} from 'react'
import { useNavigate, Link } from 'react-router-dom'
import axios from 'axios'
import {Shield, ArrowLeft} from 'lucide-react'
import {Spinner} from '../components/ui/Spinner'

export default function Register(){
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: ''
    })
    const [error, setError] = useState('')
    const [success, setSuccess] = useState('')
    const [loading, setLoading] = useState(false)
    const navigate = useNavigate()

    const handleSubmit = async e => {
        e.preventDefault();
        setError('');
        setSuccess('');
        
        // Validation
        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match')
            return
        }
        if (formData.password.length < 8) {
            setError('Password must be at least 8 characters')
            return
        }
        
        setLoading(true);
        try{
            const {data} = await axios.post('/api/auth/register', {
                username: formData.username,
                email: formData.email,
                password: formData.password
            })
            
            setSuccess(data.detail)
            // Clear form
            setFormData({username: '', email: '', password: '', confirmPassword: ''})
            
            // Redirect to login after 3 seconds
            setTimeout(() => {
                navigate('/login')
            }, 3000)
        } catch(err){
            const msg = err?.response?.data?.detail || 'Registration failed. Please try again.'
            setError(msg)
        } finally {
            setLoading(false)
        }
    }

    const handleChange = (e) => {
        setFormData(prev => ({
            ...prev,
            [e.target.name]: e.target.value
        }))
    }

    return (
        <div className="min-h-screen bg-theme-base flex items-center justify-center p-4">
            <div className="w-full max-w-sm">
                <div className="flex flex-col items-center mb-8">
                    <div className="bg-blue-600/20 border border-blue-600/40 rounded-xl p-3 mb-3">
                        <Shield size={24} className="text-blue-400" />
                    </div>
                    <h1 className="text-xl font-bold text-theme-primary">Create Account</h1>
                    <p className="text-xs text-theme-muted mt-1">Register for Sentinel SOC access</p>
                </div>

                <form onSubmit={handleSubmit} className='bg-theme-surface border border-theme rounded-xl p-6 space-y-4'>
                    {error && (
                        <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>
                    )}
                    {success && (
                        <p className="text-xs text-emerald-400 bg-emerald-950 border border-emerald-800 rounded px-3 py-2">
                            {success}<br/>Redirecting to login...
                        </p>
                    )}
                    
                    <div>
                        <label className="text-xs text-theme-secondary block mb-1">Username</label>
                        <input 
                            type="text" 
                            name="username"
                            value={formData.username}
                            onChange={handleChange}
                            className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                            required
                            minLength={3}
                            autoComplete='username'
                        />
                    </div>

                    <div>
                        <label className="text-xs text-theme-secondary block mb-1">Email</label>
                        <input 
                            type="email" 
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                            required
                            autoComplete='email'
                        />
                    </div>

                    <div>
                        <label className="text-xs text-theme-secondary block mb-1">Password</label>
                        <input 
                            type="password" 
                            name="password"
                            value={formData.password}
                            onChange={handleChange}
                            className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                            required
                            minLength={8}
                            autoComplete='new-password'
                        />
                        <p className="text-xs text-theme-muted mt-1">Minimum 8 characters</p>
                    </div>

                    <div>
                        <label className="text-xs text-theme-secondary block mb-1">Confirm Password</label>
                        <input 
                            type="password" 
                            name="confirmPassword"
                            value={formData.confirmPassword}
                            onChange={handleChange}
                            className="w-full bg-theme-base border border-theme rounded px-3 py-2 text-sm text-theme-primary focus:outline-none focus:border-blue-500"
                            required
                            autoComplete='new-password'
                        />
                    </div>

                    <button 
                        type="submit" 
                        disabled={loading || success} 
                        className='w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 disabled:cursor-not-allowed text-blue-100 text-sm font-semibold rounded py-2 transition-colors flex items-center justify-center gap-2'
                    >
                        {loading && <Spinner className='h-4 w-4'/>}
                        Create Account
                    </button>
                </form>

                <div className="mt-6 text-center">
                    <Link 
                        to="/login" 
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center justify-center gap-1"
                    >
                        <ArrowLeft size={12} />
                        Back to Login
                    </Link>
                </div>
            </div>
        </div>
    )
}
