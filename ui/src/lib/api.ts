// Talk to the bridge's control/health endpoints. The admin nonce is delivered same-origin in the
// served index.html (a cross-origin page can't read it), and required by /admin/*.
import type { Snapshot } from '../types';
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

export interface PoolingResult {
  ok: true;
  name: string;
  revision: string;
  undoId?: string;
  snapshot: Snapshot;
}

export type PoolingChange =
  | { mode: 'pool'; minWarm: number; revision: string }
  | { mode: 'isolated'; revision: string }
  | { undoId: string; revision: string };

export async function changePooling(name: string, change: PoolingChange): Promise<PoolingResult> {
  const response = await fetch(`/admin/servers/${encodeURIComponent(name)}/pooling`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-mcp-nonce': getNonce() },
    body: JSON.stringify(change),
  });
  if (response.status === 401) {
    throw new Error('Admin session expired. Reload the dashboard before changing settings.');
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`Pooling change returned an unreadable response (${response.status}). Refresh before retrying.`);
  }
  if (!response.ok ||
      result.ok !== true) {
    throw new Error(result.error || `Pooling change failed (${response.status})`);
  }
  return result;
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
