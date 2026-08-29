import { useState } from 'react';
import { useEventSource } from './hooks/useEventSource';
import { useReqHistory } from './hooks/useReqHistory';
import { ServerCard } from './components/ServerCard';
import { LogDrawer } from './components/LogDrawer';
import { HealthPage } from './components/HealthPage';
import type { Snapshot } from './types';

function fmtUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

export default function App() {
  const { data, connected } = useEventSource<Snapshot>('/api/events');
  const history = useReqHistory(data);
  const [view, setView] = useState<'dashboard' | 'health'>('dashboard');
  const servers = data?.servers ?? [];

  return (
    <div className="min-h-screen flex flex-col">
      <header className="sticky top-0 z-10 flex items-center justify-between px-5 py-3 bg-panel border-b border-line">
        <div className="flex items-center gap-4">
          <div className="flex items-baseline gap-2 font-bold text-lg">
            <span>🫀</span>
            <span>mcp-pacemaker</span>
          </div>
          <nav className="flex gap-1">
            {(['dashboard', 'health'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={`px-3 py-1 rounded-lg text-[13px] font-semibold capitalize ${view === v ? 'bg-panel2 border border-line text-fg' : 'text-muted hover:text-fg'}`}
              >
                {v}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-2 text-muted text-[13px]">
          <span className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-ok shadow-[0_0_6px] shadow-ok' : 'bg-danger'}`} />
          <span>{connected ? 'live' : 'reconnecting…'}</span>
          {data && (
            <span>
              · :{data.port} · up {fmtUptime(data.uptimeSec)} · v{data.version}
            </span>
          )}
        </div>
      </header>

      {view === 'dashboard' ? (
        <>
          <main className="flex-1 w-full max-w-[1160px] mx-auto p-6 grid gap-[18px] [grid-template-columns:repeat(auto-fit,minmax(320px,1fr))]">
            {servers.length === 0 && (
              <p className="col-span-full text-muted text-center p-16">{connected ? 'No servers configured.' : 'Connecting…'}</p>
            )}
            {servers.map((s) => (
              <ServerCard key={s.name} s={s} history={history[s.name] ?? []} />
            ))}
          </main>
          <LogDrawer />
        </>
      ) : (
        <main className="flex-1">
          <HealthPage />
        </main>
      )}

      <footer className="text-muted text-center py-3.5 text-xs border-t border-line bg-panel">
        Live via SSE · loopback only · mcp-pacemaker dashboard
      </footer>
    </div>
  );
}
