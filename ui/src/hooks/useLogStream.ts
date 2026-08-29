import { useEffect, useState } from 'react';

// Accumulate the bridge's live log lines from the /api/logs SSE stream (capped to `max`).
export function useLogStream(max = 300): string[] {
  const [lines, setLines] = useState<string[]>([]);
  useEffect(() => {
    const es = new EventSource('/api/logs');
    es.onmessage = (ev) => {
      let line: string;
      try {
        line = JSON.parse(ev.data);
      } catch {
        line = ev.data;
      }
      setLines((prev) => {
        const next = [...prev, line];
        return next.length > max ? next.slice(-max) : next;
      });
    };
    return () => es.close();
  }, [max]);
  return lines;
}
