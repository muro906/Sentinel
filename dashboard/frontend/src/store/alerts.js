import {create} from 'zustand'

export const useAlertsStore = create((set) => ({
    liveNotifications: [],
    pushNotification: (notification) => set((state) => {
        return {
            liveNotifications: [...state.liveNotifications.slice(0,50), notification]
        }
    }),
    clearNotifications: () => set(
        {liveNotifications: []}
    )
    
    
}))