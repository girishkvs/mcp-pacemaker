import { useCallback, useEffect, useState } from 'react';
import { parseSnapshot } from '../lib/api';
import { SnapshotOrder, type SnapshotUpdate } from '../lib/snapshotOrder';
import type { Snapshot } from '../types';

// Subscribe to an SSE endpoint that emits JSON frames; returns the latest value + connection state.
export function useEventSource<T extends Snapshot>(url: string): {
  data: T | null;
  connected: boolean;
  error?: string;
  setData: (snapshot: T) => SnapshotUpdate<T>;
} {
  const [data, storeData] = useState<T | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string>();
  const [ordering] = useState(() => new SnapshotOrder<T>());
  const setData = useCallback((snapshot: T) => {
    const parsed = parseSnapshot(snapshot);
    const update = ordering.accept(parsed);
    if (update.accepted) {
      storeData(parsed);
      setError(undefined);
    }
    return update;
  }, [ordering]);
  useEffect(() => {
    let active = true;
    const es = new EventSource(url);
    es.onopen = () => { if (active) setConnected(true); };
    es.onerror = () => { if (active) setConnected(false); };
    es.onmessage = (ev) => {
      if (!active) return;
      try {
        setData(JSON.parse(ev.data) as T);
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Invalid snapshot received. Active values were kept.');
      }
    };
    return () => {
      active = false;
      es.close();
    };
  }, [url, setData]);
  return { data, connected, error, setData };
}
