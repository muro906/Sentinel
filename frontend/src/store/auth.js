// Manage authentication state with zustand.,Application uses role-based authentication

import {create} from 'zustand'
import {createSelectors} from './create-selectors'
const useAuthStore = create((set) => ({
    accessToken: null,
    userName: null,
    role: null,
    // Never store in local storage to prevent XSS token theft
    setTokens: (accessToken, userName, role) => set({
        accessToken: accessToken,
        userName: userName,
        role: role
    }),
    clear: () => set({
        accessToken: null,
        userName: null,
        role: null
    })
}))

// Create selectors for auth state
export const useAuthStoreSelectors = createSelectors(useAuthStore);
export default useAuthStore;