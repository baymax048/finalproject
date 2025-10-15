import { useEffect, useRef, useCallback } from 'react';
import type { WebSocketMessage } from './types';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8001';

interface UseWebSocketOptions {
  userId: string | null;
  onMessage?: (message: WebSocketMessage) => void;
  reconnectInterval?: number;
}

export const useWebSocket = ({ userId, onMessage, reconnectInterval = 3000 }: UseWebSocketOptions) => {
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimeout = useRef<number | undefined>(undefined);
  const shouldConnect = useRef(true);

  const connect = useCallback(() => {
    if (!userId || !shouldConnect.current) return;

    try {
      ws.current = new WebSocket(`${WS_URL}/ws/${userId}`);

      ws.current.onopen = () => {
        console.log('WebSocket connected');
      };

      ws.current.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          onMessage?.(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      ws.current.onclose = () => {
        console.log('WebSocket closed');
        if (shouldConnect.current) {
          reconnectTimeout.current = window.setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
    }
  }, [userId, onMessage, reconnectInterval]);

  const disconnect = useCallback(() => {
    shouldConnect.current = false;
    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
    }
    if (ws.current) {
      ws.current.close();
      ws.current = null;
    }
  }, []);

  useEffect(() => {
    connect();

    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return { disconnect };
};
