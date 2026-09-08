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
  const disabled = !enabled || !supported || state?.busy;
  return (
    <div className="text-xs">
      {supported ? (
        <>
          <p className="text-muted mb-2">
            {pooled
              ? `${server.warm ?? 0}/${server.minWarm ?? 0} warm processes. Active sessions are additional.`
              : `Uses ${count} additional resident process${count === 1 ? '' : 'es'}. Only enabled when you choose.`}
          </p>
          <div className="flex gap-2 flex-wrap">
            <button
              type="button"
              disabled={disabled}
              onClick={() => actions.apply(server.name, pooled ? null : count)}
              className="rounded-lg border border-accent bg-accent/10 px-3 py-1.5 text-fg hover:bg-accent/20 disabled:opacity-40"
            >
              {state?.busy ? 'Applying...' : pooled ? 'Disable pre-warming' : `Enable pre-warming (${count})`}
            </button>
            {state?.undoId && (
              <button
                type="button"
                disabled={!enabled || state.busy}
                onClick={() => actions.undo(server.name)}
                className="rounded-lg border border-line px-3 py-1.5 text-fg hover:border-accent disabled:opacity-40"
              >Undo</button>
            )}
          </div>
        </>
      ) : (
        <p className="text-muted">{server.prewarming?.reason ?? 'Pooling controls need the updated bridge.'}</p>
      )}
      {state?.message && <p role="status" className="mt-2 text-ok">{state.message}</p>}
      {state?.error && <p role="alert" className="mt-2 text-danger break-words">{state.error}</p>}
    </div>
  );
}
