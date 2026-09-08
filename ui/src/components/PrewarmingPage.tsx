import type { PoolingActions } from '../hooks/usePoolingActions';
import type { Snapshot } from '../types';
import { PoolingControls } from './PoolingControls';

export function PrewarmingPage({ snapshot, actions, connected }: {
  snapshot: Snapshot | null;
  actions: PoolingActions;
  connected: boolean;
}) {
  const servers = snapshot?.servers.filter((server) => server.type === 'stdio') ?? [];
  const eligible = servers.filter((server) => server.prewarming?.eligible);
  const pooled = servers.filter((server) => server.sharing === 'pool');
  const shared = servers.filter((server) => server.sharing === 'shared');
  const seconds = (ms: number | null | undefined) => ms == null ? '-' : `${(ms / 1000).toFixed(1)}s`;
  return (
    <div className="max-w-[1400px] mx-auto p-6">
      <h1 className="text-xl font-bold">Pre-warming</h1>
      <p className="mt-2 mb-4 text-sm text-muted">
        {eligible.length} pre-warming candidates, {pooled.length} pooled, {shared.length} shared.
        {' '}A warm slot is an exclusive, pre-started process, not a shared initialized session.
        Nothing is enabled automatically.
      </p>
      <div className="overflow-x-auto rounded-xl border border-line bg-panel">
        <table className="w-full text-sm text-left">
          <thead className="bg-panel2 text-muted">
            <tr>
              {['Server / mode', 'Cold start p50 / p95', 'Peak sessions', 'Process starts', 'Warm / target', 'Shared child', 'Action'].map((label) =>
                <th key={label} className="p-3 font-medium">{label}</th>)}
            </tr>
          </thead>
          <tbody>
            {servers.map((server) => (
              <tr key={server.name} className="border-t border-line align-top">
                <td className="p-3">
                  <div className="font-semibold">{server.name}</div>
                  <div className="text-xs text-muted mt-1">{server.sharing}</div>
                </td>
                <td className="p-3">
                  {seconds(server.spawn?.p50Ms)} / {seconds(server.spawn?.p95Ms)}
                  <div className="text-xs text-muted mt-1">{server.spawn?.samples ?? 0} latency samples</div>
                </td>
                <td className="p-3">{server.peakConcurrency ?? 0}</td>
                <td className="p-3">{server.spawn?.total ?? '-'}</td>
                <td className="p-3">{server.sharing === 'shared' ? '-' : `${server.warm ?? 0} / ${server.minWarm ?? 0}`}</td>
                <td className="p-3">
                  {server.sharing === 'shared' ? server.shared?.state ?? 'Not active' : '-'}
                  {server.shared && (
                    <div className="text-xs text-muted mt-1">
                      {server.shared.members} sessions, {server.shared.unresolved} pending, {server.shared.queued} queued
                    </div>
                  )}
                </td>
                <td className="p-3 min-w-[260px]">
                  <PoolingControls server={server} actions={actions} enabled={connected && Boolean(snapshot?.prewarm)} />
                </td>
              </tr>
            ))}
            {!servers.length && <tr><td colSpan={7} className="p-8 text-center text-muted">{connected ? 'No stdio servers configured.' : 'Connecting...'}</td></tr>}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-muted">
        Process counters cover this bridge instance{snapshot?.startedAt ? `, started ${snapshot.startedAt}` : ''}.
        HTTP proxies do not spawn local processes and are excluded.
      </p>
    </div>
  );
}
