import axios from 'axios';

import useAuthStore from '../store/auth';

// Pre-configured Axios instance — all requests go to /api and include cookies
const api = axios.create({baseURL:'/api', withCredentials: true})

// Attach access token to every outgoing request
api.interceptors.request.use(
    (config) =>{
        // Use getState() — hooks cannot be called outside React components
        const token = useAuthStore.getState().accessToken
        if(token){
            // Inject the JWT as a Bearer token in the Authorization header
            config.headers.Authorization =`Bearer ${token}`
        }
        return config
    }
)

// On error 401: silently attempt a token refresh, then retry the original request
api.interceptors.response.use(
    (res) => res,  // Pass through successful responses unchanged
    async (error) => {
        // Only attempt refresh once per request (_retry flag prevents infinite loops)
        if(error.response?.status === 401 && !error.config._retry){
            error.config._retry = true;
            try{
                // Request a new access token using the httpOnly refresh cookie
                const{data} = await axios.post('/api/auth/refresh', {}, { withCredentials: true});
                // Decode the JWT payload — guarded against malformed tokens
                let payload
                try {
                    payload = JSON.parse(atob(data.access_token.split('.')[1]))
                } catch {
                    useAuthStore.getState().clear()
                    window.location.href = '/login'
                    return Promise.reject(new Error('Invalid token received'))
                }
                useAuthStore.getState().setTokens(data.access_token, payload.sub, payload.role);
                // Update the failed request's header and retry it
                error.config.headers.Authorization = `Bearer ${data.access_token}`;
                return api(error.config)
            }
            catch{
                // Refresh failed — clear auth state and force re-login
                useAuthStore.getState().clear();
                window.location.href = '/login';
            }
            
        }
        // For all other errors, propagate them to the caller
        return Promise.reject(error);
    }
)

export default api