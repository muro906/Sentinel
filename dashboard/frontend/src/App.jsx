import { Component, useEffect, useState } from 'react'
import {BrowserRouter, Navigate, Route, Routes} from 'react-router-dom'
import axios from 'axios'
import {useAuthStore} from './store/auth'
import AppShell from './components/layout/AppShell'
import Login from './pages/Login'
import AlertFeed from './pages/AlertFeed'
import AlertDetail from './pages/AlertDetail'
import TraceViewer from './pages/TraceViewer'
import CVEBrowser from './pages/CVEBrowser'
import Assets from './pages/Assets'
import PlanReview from './pages/PlanReview'
import Overview from './pages/Overview'
import AdminDashboard from './pages/AdminDashboard'
import Register from './pages/Register'
import Profile from './pages/Profile'
import MyAlerts from './pages/MyAlerts'
import TransferAlerts from './pages/TransferAlerts'
import EscalatedAlerts from './pages/EscalatedAlerts'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'

class ErrorBoundary extends Component {
    constructor(props) {
        super(props)
        this.state = { hasError: false }
    }
    static getDerivedStateFromError() {
        return { hasError: true }
    }
    render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-theme-base flex items-center justify-center p-4">
                    <div className="text-center">
                        <p className="text-red-400 text-sm font-medium mb-2">Something went wrong.</p>
                        <button
                            onClick={() => { this.setState({ hasError: false }); window.location.href = '/'; }}
                            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                        >
                            Return to dashboard
                        </button>
                    </div>
                </div>
            )
        }
        return this.props.children
    }
}

function tokenExp(token) {
    try { return JSON.parse(atob(token.split('.')[1])).exp * 1000 } catch { return 0 }
}
function isTokenValid(token) {
    return !!token && tokenExp(token) > Date.now()
}

function RoleRoute({ children, roles }) {
    const role = useAuthStore(state => state.role)
    if (!roles.includes(role)) return <Navigate to="/" replace />
    return <>{children}</>
}

function ProtectedRoute({ children }) {
    const token    = useAuthStore(state => state.accessToken)
    const setTokens = useAuthStore(state => state.setTokens)
    const clear    = useAuthStore(state => state.clear)
    const [checking, setChecking] = useState(false)
    const [redirectToLogin, setRedirectToLogin] = useState(false)

    useEffect(() => {
        if (!isTokenValid(token)) {
            // Try to silently refresh before forcing a login
            setChecking(true)
            axios.post('/api/auth/refresh', {}, { withCredentials: true })
                .then(({ data }) => {
                    try {
                        const payload = JSON.parse(atob(data.access_token.split('.')[1]))
                        setTokens(data.access_token, payload.sub, payload.role)
                    } catch {
                        clear()
                        setRedirectToLogin(true)
                    }
                })
                .catch(() => { clear(); setRedirectToLogin(true) })
                .finally(() => setChecking(false))
        }
    }, [token, setTokens, clear])

    if (redirectToLogin) return <Navigate to="/login" replace />
    if (!isTokenValid(token) && checking) return null   // briefly blank while refreshing
    if (!isTokenValid(token) && !checking) return <Navigate to="/login" replace />
    return <>{children}</>
}

export default function App(){
    return(
        <ErrorBoundary>
        <BrowserRouter>
            <Routes>
                {/* Public / unauthenticated routes */}
                <Route path='/login' element={<Login />} />
                <Route path='/register' element={<Register />} />
                <Route path='/forgot-password' element={<ForgotPassword />} />
                <Route path='/reset-password' element={<ResetPassword />} />

                {/* Protected app shell routes */}
                <Route path='/' element={
                    <ProtectedRoute>
                        <AppShell/> 
                    </ProtectedRoute>
                }>
                    <Route index element={<Overview />} />
                    <Route path='alerts' element={<AlertFeed />} />
                    <Route path='alerts/:id' element={<AlertDetail />} />
                    <Route path='alerts/:id/plans' element={<PlanReview />}/>
                    <Route path='alerts/:id/trace' element={<TraceViewer />} />
                    <Route path='my-alerts' element={<MyAlerts />} />
                    <Route path='transfers' element={<TransferAlerts />} />
                    <Route path='escalations' element={<EscalatedAlerts />} />
                    <Route path='cves' element={<CVEBrowser />} />
                    <Route path='assets' element={<Assets />} />
                    <Route path='admin' element={
                        <RoleRoute roles={['admin']}>
                            <AdminDashboard />
                        </RoleRoute>
                    } />
                    <Route path='profile' element={<Profile />} />
                </Route>
            </Routes>
        </BrowserRouter>
        </ErrorBoundary>
    )
}
