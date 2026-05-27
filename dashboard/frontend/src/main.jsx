import React from 'react'
import ReactDOM from 'react-dom/client'
import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import App from './App.jsx'
import './index.css'

const queryClient = new QueryClient(
  {defaultOptions:{ queries: {staleTime: 30_000, retry:1}},
})

async function prepare() {
  // MSW mock worker disabled - using real backend API
  // To re-enable mocks for offline development:
  // 1. Uncomment the code below
  // 2. Comment out the vite proxy in vite.config.js
  //
  // if (import.meta.env.DEV) {
  //   const { worker, seedMockAuth } = await import('./mocks/browser.js')
  //   await worker.start({ onUnhandledRequest: 'bypass' })
  //   seedMockAuth()
  // }
}

prepare().then(() => {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </React.StrictMode>
  )
})
