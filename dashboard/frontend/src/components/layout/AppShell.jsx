import { useState } from 'react'
import {Outlet} from 'react-router-dom'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import { ToastContainer } from '../ui/Toast'
import { ShortcutsDialog } from '../ui/ShortcutsDialog'
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts'

export default function AppShell(){
    const [showShortcuts, setShowShortcuts] = useState(false)
    useKeyboardShortcuts({ onShowHelp: () => setShowShortcuts(true) })

    return(
        <div className="flex h-screen overflow-hidden transition-colors duration-200 bg-theme-base text-theme-secondary">
            <Sidebar />
            <div className="flex flex-col flex-1 overflow-hidden">
                <Topbar onShowShortcuts={() => setShowShortcuts(true)} />
                <main className="flex-1 overflow-y-auto p-6">
                    <Outlet />
                </main>
            </div>
            <ToastContainer />
            <ShortcutsDialog open={showShortcuts} onClose={() => setShowShortcuts(false)} />
        </div>
    )
}