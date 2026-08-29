// Talk to the bridge's control/health endpoints. The admin nonce is delivered same-origin in the
// served index.html (a cross-origin page can't read it), and required by /admin/*.
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

export interface DoctorCheck {
  name: string;
  status: 'ok' | 'warn' | 'bad';
  detail: string;
}

export async function fetchDoctor(): Promise<{ ran: string; checks: DoctorCheck[] }> {
  const r = await fetch('/api/doctor');
  return r.json();
}
