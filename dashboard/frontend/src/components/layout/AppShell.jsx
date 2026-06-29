import { useState, useRef, useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import { ToastContainer } from '../ui/Toast'
import { ShortcutsDialog } from '../ui/ShortcutsDialog'
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts'

const COLLAPSED_WIDTH = 56
const MIN_WIDTH = 160
const MAX_WIDTH = 340
const DEFAULT_WIDTH = 224

export default function AppShell() {
    const [showShortcuts, setShowShortcuts] = useState(false)
    const [collapsed, setCollapsed] = useState(
        () => localStorage.getItem('sentinel-sidebar-collapsed') === 'true'
    )
    const [sidebarWidth, setSidebarWidth] = useState(() => {
        const saved = parseInt(localStorage.getItem('sentinel-sidebar-width'), 10)
        return saved >= MIN_WIDTH && saved <= MAX_WIDTH ? saved : DEFAULT_WIDTH
    })
    const [isResizing, setIsResizing] = useState(false)
    const isResizingRef = useRef(false)
    const startX = useRef(0)
    const startWidth = useRef(0)

    useKeyboardShortcuts({ onShowHelp: () => setShowShortcuts(true) })

    useEffect(() => {
        const handleMouseMove = (e) => {
            if (!isResizingRef.current) return
            const delta = e.clientX - startX.current
            const newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, startWidth.current + delta))
            setSidebarWidth(newWidth)
        }
        const handleMouseUp = () => {
            if (!isResizingRef.current) return
            isResizingRef.current = false
            setIsResizing(false)
            document.body.style.cursor = ''
            document.body.style.userSelect = ''
            setSidebarWidth(w => {
                localStorage.setItem('sentinel-sidebar-width', w)
                return w
            })
        }
        window.addEventListener('mousemove', handleMouseMove)
        window.addEventListener('mouseup', handleMouseUp)
        return () => {
            window.removeEventListener('mousemove', handleMouseMove)
            window.removeEventListener('mouseup', handleMouseUp)
        }
    }, [])

    const handleResizeStart = (e) => {
        if (collapsed) return
        e.preventDefault()
        isResizingRef.current = true
        setIsResizing(true)
        startX.current = e.clientX
        startWidth.current = sidebarWidth
        document.body.style.cursor = 'col-resize'
        document.body.style.userSelect = 'none'
    }

    const handleToggle = () => {
        setCollapsed(v => {
            const next = !v
            localStorage.setItem('sentinel-sidebar-collapsed', next)
            return next
        })
    }

    const effectiveWidth = collapsed ? COLLAPSED_WIDTH : sidebarWidth

    return (
        <div className="flex h-screen overflow-hidden transition-colors duration-200 bg-theme-base text-theme-secondary">
            <div
                className="relative flex-none flex"
                style={{
                    width: effectiveWidth,
                    transition: isResizing ? 'none' : 'width 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
                }}
            >
                <Sidebar collapsed={collapsed} onToggle={handleToggle} />
                {!collapsed && (
                    <div
                        className="absolute right-0 top-0 bottom-0 w-1 cursor-col-resize z-20 group"
                        onMouseDown={handleResizeStart}
                    >
                        <div className="absolute inset-0 transition-colors duration-150 group-hover:bg-blue-500/50" />
                    </div>
                )}
            </div>
            <div className="flex flex-col flex-1 overflow-hidden min-w-0">
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
