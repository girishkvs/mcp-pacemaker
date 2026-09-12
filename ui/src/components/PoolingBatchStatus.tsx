import type { PoolingActions } from '../hooks/usePoolingActions';
import type { PoolingBatch, Snapshot } from '../types';

export function PoolingBatchStatus({ actions, snapshot, connected, snapshotError }: {
  actions: PoolingActions;
  snapshot: Snapshot | null;
  connected: boolean;
  snapshotError?: string;
}) {
  const showStatus = snapshot?.prewarm || snapshotError || actions.instanceChanged || actions.unavailable.length > 0;
  if (!showStatus) return null;
  const saveWarning = snapshot?.prewarm?.saveWarning;
  const latestResult = actions.batches.find((batch) => batch.status !== 'pending' && batch.status !== 'applying');
  const previousUndo = actions.batches.find((batch) =>
    batch.status === 'applied' &&
    batch.revision === snapshot?.prewarm?.revision &&
    actions.batchAction(batch).available);
  const visible = [...actions.pending];
  for (const batch of [latestResult, previousUndo]) {
    if (batch &&
        !visible.some((entry) => entry.id === batch.id)) visible.push(batch);
  }
  const unavailableNames = [...new Set(actions.unavailable.flatMap((receipt) =>
    receipt.summary.changes.map((change) => change.name)))];
  const statusText = (batch: PoolingBatch) => {
    if (batch.status === 'pending') {
      if (!connected) return 'Pending (last reported; countdown unavailable)';
      const seconds = Math.max(0, Math.ceil(((batch.applyAt ?? actions.now) - actions.now) / 1000));
      return seconds > 0 ? `Pending — reload in ${seconds}s` : 'Pending — waiting for the bridge to apply';
    }
    if (batch.status === 'applying') return connected ? 'Applying' : 'Applying (last reported)';
    if (batch.status === 'applied') return 'Batch applied';
    if (batch.status === 'cancelled') return 'Batch cancelled';
    return 'Configuration batch failed';
  };
  return (
    <section aria-label="Configuration batches" className="w-full max-w-[1160px] mx-auto mt-4 px-6">
      <div className="rounded-xl border border-line bg-panel px-4 py-3 text-[13px]">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="font-semibold">Configuration batches</h2>
            <p className="text-muted">
              {snapshot?.prewarm?.batches
                ? `Changes share a ${(snapshot.prewarm.batchDelayMs ?? 5000) / 1000}s delay after the last accepted change. Other servers remain editable while pending.`
                : snapshot?.prewarm ? 'This bridge applies pooling changes immediately.' : 'Pooling controls are unavailable from the current bridge.'}
            </p>
            <p className="text-muted">Reload now reloads configuration and flushes the pending batch; it does not refresh this page.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={!actions.editable}
              onClick={() => actions.reloadNow()}
              className="rounded-lg border border-accent bg-accent/10 px-3 py-1.5 hover:bg-accent/20 disabled:opacity-40"
            >{actions.reloading ? 'Reloading...' : 'Reload now'}</button>
            <button
              type="button"
              disabled={actions.busy}
              onClick={() => actions.reread()}
              className="rounded-lg border border-line px-3 py-1.5 hover:border-accent disabled:opacity-40"
            >{actions.reading ? 'Reading...' : 'Reread active settings'}</button>
          </div>
        </div>
        {typeof saveWarning === 'string' && saveWarning && (
          <p role="note" className="mt-3 rounded-lg border border-line bg-panel2 px-3 py-2 text-muted break-words">
            <span className="font-medium text-fg">File save notice: </span>{saveWarning}
          </p>
        )}
        {snapshotError && <p role="alert" className="mt-2 text-amber break-words">Snapshot update rejected: {snapshotError}</p>}
        {!connected && (
          <p role="status" className="mt-2 text-amber">Bridge disconnected. Batch status and active settings are last reported values. Nothing will be resubmitted on reconnect.</p>
        )}
        {actions.instanceChanged && (
          <p role="alert" className="mt-2 text-amber">Bridge instance changed. Old receipts cannot be reused. Reread active settings, then refresh the dashboard to renew the admin session.</p>
        )}
        {unavailableNames.length > 0 && (
          <p role="status" className="mt-2 text-amber break-words">
            Outcome unavailable for retained batches affecting {unavailableNames.length} server{unavailableNames.length === 1 ? '' : 's'}: {unavailableNames.join(', ')}.
            {' '}Their summaries expired or the bridge instance changed; success is not assumed.
            {actions.needsReread && ' Reread active settings before another change.'}
          </p>
        )}
        {visible.map((batch) => {
          const action = actions.batchAction(batch);
          const count = batch.changes.length;
          const actionable = batch.status === 'pending' || (batch.status === 'applied' && action.available);
          const unsettled = batch.status === 'pending' || batch.status === 'applying';
          const color = batch.status === 'failed' ? 'text-danger' : unsettled ? 'text-amber' : 'text-muted';
          return (
            <div key={batch.id} className="mt-3 border-t border-line pt-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <p role="status" className={`font-semibold ${color}`}>{statusText(batch)}</p>
                  <p className="break-words">Whole batch — {count} server{count === 1 ? '' : 's'}: {batch.changes.map((change) => change.name).join(', ')}.</p>
                  {unsettled && (
                    <p className="text-muted break-words">
                      Requested: {batch.changes.map((change) => {
                        const target = change.mode === 'pool'
                          ? change.minWarm === undefined
                            ? 'pooling with configured target'
                            : `pool, ${change.minWarm} warm slots`
                          : 'isolated, pre-warming off';
                        return `${change.name}: ${target}`;
                      }).join('; ')}.
                    </p>
                  )}
                </div>
                {actionable && (
                  <button
                    type="button"
                    disabled={Boolean(action.reason)}
                    title={action.reason}
                    onClick={() => actions.undoBatch(batch.id, batch.status === 'pending' ? 'cancel' : 'undo')}
                    className="shrink-0 rounded-lg border border-line px-3 py-1.5 hover:border-accent disabled:opacity-40"
                  >{action.label} ({count} server{count === 1 ? '' : 's'})</button>
                )}
              </div>
              {actionable && <p className="mt-1 text-muted">{action.reason ?? (batch.status === 'pending' ? 'Cancel discards every requested change in this batch.' : 'Undo stages the entire previous configuration as another five-second batch.')}</p>}
              {batch.status === 'failed' && <p role="alert" className="mt-1 text-danger break-words">{batch.error ?? 'Batch failed without a reported reason.'} No automatic retry.</p>}
            </div>
          );
        })}
        {actions.batchError && <p role="alert" className="mt-3 text-danger break-words">{actions.batchError}</p>}
        {actions.readMessage && <p role="status" className="mt-2 text-muted">{actions.readMessage}</p>}
      </div>
    </section>
  );
}
