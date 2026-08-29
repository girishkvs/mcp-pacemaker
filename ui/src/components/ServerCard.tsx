import { useState } from 'react';
import { Activity, RefreshCw, Server } from 'lucide-react';
import type { ServerStat } from '../types';
import { recycle } from '../lib/api';
import { Sparkline } from './Sparkline';

function fmtToken(sec: number): { text: string; cls: string } {
  if (sec <= 0) return { text: 'token expired', cls: 'text-danger' };
  const m = Math.round(sec / 60);
  const text = m >= 60 ? `token ${Math.floor(m / 60)}h ${m % 60}m` : `token ${m}m`;
  return { text, cls: m <= 5 ? 'text-amber' : 'text-ok' };
}

export function ServerCard({ s, history }: { s: ServerStat; history: number[] }) {
  const [busy, setBusy] = useState(false);
  const isHttp = s.type === 'http';
  const token = isHttp && s.tokenExpiresIn != null ? fmtToken(s.tokenExpiresIn) : null;

  const onRecycle = async () => {
    setBusy(true);
    try {
      await recycle(s.name);
    } catch {
      /* surfaced via the live log */
    } finally {
      setTimeout(() => setBusy(false), 600);
    }
  };

  return (
    <section className="bg-panel border border-line rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="m-0 text-base font-bold flex items-center gap-2">
          <Server size={15} className="text-accent" />
          {s.name}
        </h2>
        <div className="flex items-center gap-2">
          {s.sharing && s.sharing !== 'isolated' && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-panel2 border border-accent text-accent" title="session sharing policy">
              {s.sharing}
            </span>
          )}
          <span className="text-xs px-2 py-0.5 rounded-full bg-panel2 border border-line text-muted" title={s.url ?? 'stdio child process'}>
            {s.type}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4 text-[13px] text-muted">
        <span className="flex items-center gap-1" title="active client sessions">
          <Activity size={13} className={s.sessions > 0 ? 'text-ok' : 'text-muted'} />
          {s.sessions}{s.maxSessions ? `/${s.maxSessions}` : ''}
        </span>
        <span title="total requests routed to this server">{s.requests} req</span>
        {s.pids.length > 0 && <span title="child process id(s)">pid {s.pids.join(', ')}</span>}
        {s.warm != null && s.warm > 0 && <span className="text-ok" title="pre-warmed pool children ready">{s.warm} warm</span>}
        <span className="ml-auto text-accent" title="requests per snapshot (~2s)">
          <Sparkline values={history ?? []} />
        </span>
      </div>

      {(token || s.lastActivitySec != null) && (
        <div className="mt-2 flex items-center gap-3 text-xs">
          {token && (
            <span className={token.cls} title="cached auth token time-to-live">
              {token.text}
            </span>
          )}
          {s.lastActivitySec != null && (
            <span className="text-muted" title="time since last request">
              active {s.lastActivitySec}s ago
            </span>
          )}
        </div>
      )}

      {s.clients && s.clients.length > 0 && (
        <div className="mt-2 flex items-center gap-1.5 flex-wrap text-xs">
          <span className="text-muted">agents:</span>
          {s.clients.map((c) => (
            <span key={c} className="px-1.5 py-0.5 rounded-md bg-panel2 border border-line text-accent" title="connected MCP host / agent">
              {c}
            </span>
          ))}
        </div>
      )}

      {s.lastError && (
        <div className="mt-2 text-xs text-danger truncate" title={s.lastError}>
          err: {s.lastError}
        </div>
      )}

      <div className="mt-3 flex gap-2">
        <button
          onClick={onRecycle}
          disabled={busy || isHttp}
          title={isHttp ? 'http servers have no child process to recycle' : 'stop active children; they respawn on next use (fresh token)'}
          className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-panel2 border border-line text-fg hover:border-accent disabled:opacity-40 disabled:cursor-default"
        >
          <RefreshCw size={12} className={busy ? 'animate-spin' : ''} />
          Recycle
        </button>
      </div>
    </section>
  );
}
