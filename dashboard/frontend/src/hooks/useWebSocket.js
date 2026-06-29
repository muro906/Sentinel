import { useCallback, useEffect, useRef } from "react";
import { useAuthStore } from "../store/auth";
export function useWebSocket(path, onMessage, enabled = true){
    const ws = useRef(null);
    const token = useAuthStore((state)=> state.accessToken);

    const connect = useCallback(() => {
        // WebSocket is disabled in dev/mock mode (MSW cannot intercept WS connections)
        if(import.meta.env.DEV || !token || !enabled) return
        const proto = location.protocol === 'https:' ? 'wss' :'ws'

        const socket = new WebSocket(`${proto}://${location.host}${path}`)
        socket.onopen = () => {
            socket.send(JSON.stringify({ type: 'auth', token }))
        }
        socket.onmessage = (e) => {
            try{
                const data = JSON.parse(e.data);
                if (data.type != 'ping') onMessage(data)
            } catch { /* Ignore malformed frames */}
        }

        //Auto-reconnect after 3s on unexpected close
        socket.onclose = (e) => {
            if((e.code != 1000) && enabled){
                setTimeout(connect, 3000)
            }
        }
        socket.onerror = () => {
            socket.close()
        }
        ws.current = socket;
    },[path, token, enabled, onMessage])
    useEffect(() => {
        connect();
        return () => {
            ws.current?.close(1000, 'unmount');
        }
    }, [connect])

}