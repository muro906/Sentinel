import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'
import { useAuthStore } from '../store/auth'

export const worker = setupWorker(...handlers)

export function seedMockAuth() {
  const payload = btoa(JSON.stringify({ sub: 'analyst01', role: 'admin', exp: 9999999999 })).replace(/=/g,'')
  const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.mock-signature`
  useAuthStore.getState().setTokens(token, 'analyst01', 'admin')
}
