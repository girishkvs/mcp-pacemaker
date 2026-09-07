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

// "active 6870s ago" is not something anyone can read at a glance.
function fmtAgo(sec: number): string {
  if (sec < 60) return `${sec}s ago`;
  const m = Math.round(sec / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m ago`;
}

// An error string is only useful if it says what to do about it. These are the ones the bridge
// actually produces, mapped to the action an operator would take.
function explainError(msg: string): string | null {
  if (/max sessions/i.test(msg)) return 'The bridge refused new sessions — recycle this server to free the cap.';
  if (/rejected the credential/i.test(msg)) return 'The credential the bridge supplied was refused; it has been discarded and will be re-minted.';
  if (/upstream returned 5/i.test(msg)) return 'The upstream server returned an error. Nothing to do here — check the service.';
  if (/upstream timeout/i.test(msg)) return 'The server did not answer in time. It may be slow to start or overloaded.';
  if (/ECONNRESET|ECONNREFUSED|socket hang up/i.test(msg)) return 'The connection dropped. Usually transient; a retry normally succeeds.';
  if (/exited code/i.test(msg)) return 'The server process exited on its own. The stderr tail above is the reason.';
  return null;
}

// A distinct badge for "nobody has called this server yet". Rendering that as healthy is what
// let a server sit broken here for hours without the dashboard saying anything.
const HEALTH_BADGE = {
  ok: { text: 'healthy', cls: 'border-ok text-ok', title: 'last request to this server succeeded' },
  failing: { text: 'failing', cls: 'border-danger text-danger', title: 'recent requests to this server are failing' },
  unknown: { text: 'unused', cls: 'border-line text-muted', title: 'no request has been made yet, so health is unknown' },
} as const;

export function ServerCard({ s, history }: { s: ServerStat; history: number[] }) {
  const [busy, setBusy] = useState(false);
  const isHttp = s.type === 'http';
  const token = isHttp && s.tokenExpiresIn != null ? fmtToken(s.tokenExpiresIn) : null;
  const health = HEALTH_BADGE[s.health?.state ?? 'unknown'];

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
          <span className={`text-xs px-2 py-0.5 rounded-full bg-panel2 border ${health.cls}`} title={health.title}>
            {s.health?.state === 'failing' && s.health.consecutiveFailures > 1 ? `${health.text} ×${s.health.consecutiveFailures}` : health.text}
          </span>
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
        <span className="flex items-center gap-1" title={s.maxSessions ? 'streamable sessions counted against the cap (total includes classic SSE)' : 'active client sessions'}>
          <Activity size={13} className={s.sessions > 0 ? 'text-ok' : 'text-muted'} />
          {s.maxSessions ? `${s.cappedSessions ?? s.sessions}/${s.maxSessions}` : s.sessions}
          {s.maxSessions != null && s.cappedSessions != null && s.sessions > s.cappedSessions && (
            <span className="text-muted"> (+{s.sessions - s.cappedSessions} sse)</span>
          )}
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
              active {fmtAgo(s.lastActivitySec)}
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

      {s.spawn && (
        <div className="mt-2 flex items-center gap-3 text-xs text-muted">
          <span title={`measured over ${s.spawn.samples} cold starts (p95 ${(s.spawn.p95Ms / 1000).toFixed(1)}s)`}>
            cold start {(s.spawn.p50Ms / 1000).toFixed(1)}s
          </span>
          {s.peakConcurrency ? <span title="peak concurrent sessions in the last hour">peak {s.peakConcurrency}</span> : null}
        </div>
      )}

      {s.advice && (
        <div className="mt-2 rounded-lg border border-amber/50 bg-amber/5 px-2.5 py-2 text-xs">
          <div className="font-semibold text-amber">Slow to start — {s.advice.reason}.</div>
          <div className="mt-1 text-fg">
            Pre-warming would hide this. Add{' '}
            <code className="px-1 rounded bg-panel2 border border-line">
              "sharing": "pool", "minWarm": {s.advice.suggest.minWarm}
            </code>{' '}
            to this server in <code className="px-1 rounded bg-panel2 border border-line">servers.json</code>.
          </div>
          <div className="mt-1 text-muted">
            Costs {s.advice.suggest.minWarm} resident process{s.advice.suggest.minWarm === 1 ? '' : 'es'}, so it is your call — the bridge will not turn it on by itself.
          </div>
        </div>
      )}

      {s.lastError && (
        <div className={`mt-2 rounded-lg border px-2.5 py-2 text-xs ${s.health?.state === 'failing' ? 'border-danger/50 bg-danger/5' : 'border-line bg-panel2'}`}>
          <div className={`flex items-start gap-1.5 ${s.health?.state === 'failing' ? 'text-danger' : 'text-muted'}`}>
            <span className="shrink-0 font-semibold">{s.health?.state === 'failing' ? 'failing:' : 'last error:'}</span>
            <span className="break-words">{s.lastError}</span>
          </div>
          {explainError(s.lastError) && (
            <div className="mt-1 text-muted break-words">{explainError(s.lastError)}</div>
          )}
          {s.health?.state !== 'failing' && (
            <div className="mt-1 text-ok">Recovered — the most recent request succeeded.</div>
          )}
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
