import { useEffect, useState } from 'react';

// Subscribe to an SSE endpoint that emits JSON frames; returns the latest value + connection state.
export function useEventSource<T>(url: string): { data: T | null; connected: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    const es = new EventSource(url);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (ev) => {
      try {
        setData(JSON.parse(ev.data) as T);
      } catch {
        /* ignore malformed frame */
      }
    };
    return () => es.close();
  }, [url]);
  return { data, connected };
}
