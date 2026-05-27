import {BrowserRouter, Navigate, Route, Routes} from 'react-router-dom'
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

function isTokenValid(token) {
    if (!token) return false
    try {
        const { exp } = JSON.parse(atob(token.split('.')[1]))
        // exp is in seconds; Date.now() is in milliseconds
        return exp * 1000 > Date.now()
    } catch {
        return false
    }
}

function RoleRoute({ children, roles }) {
    const role = useAuthStore(state => state.role)
    if (!roles.includes(role)) return <Navigate to="/" replace />
    return <>{children}</>
}

function ProtectedRoute({children}){
    const token = useAuthStore(state => state.accessToken)
    const clear = useAuthStore(state => state.clear)

    if (!isTokenValid(token)) {
        // Clear any stale state before redirecting
        if (token) clear()
        return <Navigate to="/login" replace />
    }
    return <>{children}</>
}

export default function App(){
    return(
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
    )
}
