import { create } from 'zustand'

const saved = localStorage.getItem('theme')
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
const initial = saved ?? (prefersDark ? 'dark' : 'light')

if (initial === 'dark') document.documentElement.classList.add('dark')
else document.documentElement.classList.remove('dark')

export const useThemeStore = create((set) => ({
  theme: initial,
  toggle: () => set((state) => {
    const next = state.theme === 'dark' ? 'light' : 'dark'
    localStorage.setItem('theme', next)
    if (next === 'dark') document.documentElement.classList.add('dark')
    else document.documentElement.classList.remove('dark')
    return { theme: next }
  }),
}))
