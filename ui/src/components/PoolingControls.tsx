import type { PoolingActions } from '../hooks/usePoolingActions';
import type { ServerStat } from '../types';

export function PoolingControls({ server, actions, enabled }: {
  server: ServerStat;
  actions: PoolingActions;
  enabled: boolean;
}) {
  const state = actions.states[server.name];
  const count = server.prewarming?.suggestedMinWarm ?? 1;
  const pooled = server.sharing === 'pool';
  const supported = Boolean(server.prewarming?.eligible);
  const pending = state?.status === 'pending';
  const applying = state?.status === 'applying';
  const disabled = !enabled || !supported || !actions.editable || state?.busy || pending || applying;
  const requested = state?.requested;
  const requestedLabel = requested?.mode === 'pool'
    ? requested.minWarm === undefined
      ? 'pooling with configured target'
      : `pre-warming with ${requested.minWarm} warm slots`
    : 'pre-warming off (isolated)';
  return (
    <div className="text-xs">
      {supported ? (
        <>
          <p className="text-muted mb-2">
            {enabled ? 'Active: ' : 'Last reported active: '}
            {pooled
              ? `Pooling, ${server.warm ?? 0}/${server.minWarm ?? 0} warm processes. Active sessions are additional.`
              : `Pre-warming is off. Enabling uses ${count} additional resident process${count === 1 ? '' : 'es'}.`}
          </p>
          <div className="flex gap-2 flex-wrap">
            <button
              type="button"
              disabled={disabled}
              onClick={() => actions.apply(server.name, pooled ? null : count)}
              className="rounded-lg border border-accent bg-accent/10 px-3 py-1.5 text-fg hover:bg-accent/20 disabled:opacity-40"
            >
              {state?.busy ? 'Submitting...' : applying ? 'Applying...' : pending ? 'Pending...' : pooled ? 'Disable pre-warming' : `Enable pre-warming (${count})`}
            </button>
            {state?.undoId && !state.batchId && (
              <button
                type="button"
                disabled={!enabled || !actions.editable || state.busy}
                onClick={() => actions.undo(server.name)}
                className="rounded-lg border border-line px-3 py-1.5 text-fg hover:border-accent disabled:opacity-40"
              >Undo</button>
            )}
          </div>
        </>
      ) : (
        <p className="text-muted">{server.prewarming?.reason ?? 'Pooling controls need the updated bridge.'}</p>
      )}
      {(pending || applying) && requested && (
        <p role="status" className="mt-2 text-amber">
          {enabled ? applying ? 'Applying' : 'Pending' : 'Last reported pending change'} — requested:{' '}
          {requestedLabel}.
          {' '}Awaiting the batch result; active values are shown separately.
          {' '}Shared countdown and whole-batch actions are above.
        </p>
      )}
      {state?.status === 'applied' && <p role="status" className="mt-2 text-ok">Batch applied. Active values are shown above.</p>}
      {state?.status === 'cancelled' && <p role="status" className="mt-2 text-muted">Batch cancelled.</p>}
      {state?.status === 'failed' && <p role="alert" className="mt-2 text-danger break-words">Configuration batch failed: {state.batchError ?? 'No reason was reported.'} No automatic retry.</p>}
      {state?.status === 'unavailable' && (
        <p role="status" className="mt-2 text-amber">
          Batch outcome unavailable. {actions.needsReread ? 'Reread active settings above before another change.' : 'The old receipt cannot be reused.'}
        </p>
      )}
      {state?.message && <p role="status" className="mt-2 text-ok">{state.message}</p>}
      {state?.error && <p role="alert" className="mt-2 text-danger break-words">{state.error}</p>}
    </div>
  );
}
