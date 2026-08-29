import { useEffect, useRef, useState } from 'react';
import type { Snapshot } from '../types';

// Build a per-server request-rate history (delta of cumulative `requests` between snapshots),
// so the dashboard can draw a req/interval sparkline without any bridge-side bucketing.
export function useReqHistory(data: Snapshot | null, max = 30): Record<string, number[]> {
  const [hist, setHist] = useState<Record<string, number[]>>({});
  const prev = useRef<Record<string, number>>({});
  useEffect(() => {
    if (!data) return;
    setHist((h) => {
      const next = { ...h };
      for (const s of data.servers) {
        const last = prev.current[s.name];
        if (last !== undefined) {
          const arr = [...(next[s.name] ?? []), Math.max(0, s.requests - last)];
          next[s.name] = arr.length > max ? arr.slice(-max) : arr;
        }
        prev.current[s.name] = s.requests;
      }
      return next;
    });
  }, [data, max]);
  return hist;
}
