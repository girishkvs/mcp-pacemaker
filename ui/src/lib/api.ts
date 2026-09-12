// Talk to the bridge's control/health endpoints. The admin nonce is delivered same-origin in the
// served index.html (a cross-origin page can't read it), and required by /admin/*.
import type { PoolingBatch, Snapshot } from '../types';
import { hasSnapshotOrder, validateSnapshotOrder } from './snapshotOrder';
export function getNonce(): string {
  return document.querySelector('meta[name="mcp-nonce"]')?.getAttribute('content') ?? '';
}

export async function recycle(name: string): Promise<{ ok: boolean; recycled: number }> {
  const r = await fetch(`/admin/recycle/${encodeURIComponent(name)}`, {
    method: 'POST',
    headers: { 'x-mcp-nonce': getNonce() },
  });
  if (!r.ok) throw new Error(`recycle failed: ${r.status}`);
  return r.json();
}

interface PoolingResponse {
  ok: true;
  name: string;
  revision: string;
  snapshot: Snapshot;
}

export type PoolingResult = PoolingResponse & (
  | { pending: true; batchId: string; undoId: string }
  | { pending?: false; cancelled?: boolean; undoId?: string }
);

export type PoolingChange =
  | { mode: 'pool'; minWarm: number; revision: string }
  | { mode: 'isolated'; revision: string }
  | { undoId: string; revision: string };

export function parsePoolingBatch(batch: PoolingBatch): PoolingBatch {
  if (batch.status !== 'failed') return batch;
  const commitState = batch.commitState === 'not-committed' || batch.commitState === 'committed'
    ? batch.commitState
    : 'unknown';
  return { ...batch, commitState };
}

export function parseSnapshot<T extends Snapshot>(snapshot: T): T {
  validateSnapshotOrder(snapshot);
  const prewarm = snapshot.prewarm;
  if (!prewarm) return snapshot;
  for (const batch of prewarm.batches ?? []) {
    for (const change of batch.changes) {
      if (!Object.prototype.hasOwnProperty.call(change, 'minWarm')) continue;
      const target = change.mode === 'pool' ? change.minWarm : undefined;
      const validTarget = typeof target === 'number' &&
        Number.isSafeInteger(target) &&
        target >= 1 &&
        Number.isSafeInteger(prewarm.maxWarm) &&
        target <= prewarm.maxWarm;
      if (!validTarget) {
        throw new Error('Snapshot contains an invalid pooling target. Reread active settings before retrying.');
      }
    }
  }
  return {
    ...snapshot,
    prewarm: {
      ...prewarm,
      saveWarning: typeof prewarm.saveWarning === 'string' ? prewarm.saveWarning : undefined,
      batches: prewarm.batches?.map(parsePoolingBatch),
    },
  };
}

export async function changePooling(name: string, change: PoolingChange): Promise<PoolingResult> {
  const response = await fetch(`/admin/servers/${encodeURIComponent(name)}/pooling`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-mcp-nonce': getNonce(),
      'x-mcp-pooling-batch': '1',
    },
    body: JSON.stringify(change),
  });
  if (response.status === 401) {
    throw new Error('Admin session expired. Reload the dashboard before changing settings.');
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`Pooling change returned an unreadable response (${response.status}). Reread active settings before retrying.`);
  }
  if (!response.ok ||
      result?.ok !== true) {
    throw new Error(result?.error || `Pooling change failed (${response.status})`);
  }
  if (!result.snapshot ||
      typeof result.revision !== 'string') {
    throw new Error('Pooling response is incomplete. Reread active settings before retrying.');
  }
  if (response.status === 202) {
    const validReceipt = result.pending === true &&
      typeof result.batchId === 'string' &&
      result.batchId.length > 0 &&
      typeof result.undoId === 'string' &&
      result.undoId.length > 0 &&
      hasSnapshotOrder(result.snapshot) &&
      result.snapshot.prewarm?.batches?.some((batch: { id: string }) => batch.id === result.batchId);
    if (!validReceipt) {
      throw new Error('Queued change has no usable receipt. Reread active settings; do not assume it was applied.');
    }
  } else if (response.status !== 200 ||
             result.pending === true) {
    throw new Error('Unexpected pooling response. Reread active settings before retrying.');
  }
  return { ...result, snapshot: parseSnapshot(result.snapshot) };
}

export async function fetchSnapshot(): Promise<Snapshot> {
  const response = await fetch('/api/status', { cache: 'no-store' });
  if (!response.ok) throw new Error(`Reading active settings failed (${response.status}).`);
  const snapshot = await response.json();
  if (!snapshot?.ok ||
      !Array.isArray(snapshot.servers)) {
    throw new Error('Reading active settings returned an unreadable snapshot.');
  }
  return parseSnapshot(snapshot);
}

export async function reloadPooling(): Promise<Snapshot> {
  const response = await fetch('/admin/reload', {
    method: 'POST',
    headers: { 'x-mcp-nonce': getNonce() },
  });
  if (response.status === 401) {
    throw new Error('Admin session expired. Reload the dashboard before reloading configuration.');
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`Reload returned an unreadable response (${response.status}). Reread active settings.`);
  }
  if (!response.ok ||
      result?.ok !== true ||
      result?.error) {
    throw new Error(result?.error || `Reload failed (${response.status}).`);
  }
  return result.snapshot ? parseSnapshot(result.snapshot) : fetchSnapshot();
}

export interface DoctorCheck {
  name: string;
  status: 'ok' | 'warn' | 'bad';
  detail: string;
}

export async function fetchDoctor(): Promise<{ ran: string; checks: DoctorCheck[] }> {
  const r = await fetch('/api/doctor');
  return r.json();
}
