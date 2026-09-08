import { useState } from 'react';
import { changePooling } from '../lib/api';
import type { Snapshot } from '../types';

export interface PoolingActionState {
  busy: boolean;
  error?: string;
  message?: string;
  undoId?: string;
  revision?: string;
}

export function usePoolingActions(snapshot: Snapshot | null, connected: boolean, onSnapshot: (snapshot: Snapshot) => void) {
  const [states, setStates] = useState<Record<string, PoolingActionState>>({});
  const update = (name: string, state: PoolingActionState) =>
    setStates((previous) => ({ ...previous, [name]: state }));

  const apply = async (name: string, count: number | null) => {
    if (!connected ||
        !snapshot?.prewarm) {
      update(name, { busy: false, error: 'Bridge is disconnected or does not support pooling controls.' });
      return;
    }
    update(name, { ...states[name], busy: true, error: undefined, message: undefined });
    try {
      const revision = snapshot.prewarm.revision;
      const change = count === null
        ? { mode: 'isolated' as const, revision }
        : { mode: 'pool' as const, minWarm: count, revision };
      const result = await changePooling(name, change);
      onSnapshot(result.snapshot);
      update(name, {
        busy: false,
        revision: result.revision,
        undoId: result.undoId,
        message: count === null ? 'Pre-warming disabled.' : `Enabled ${count} warm slot${count === 1 ? '' : 's'}.`,
      });
    } catch (error) {
      update(name, { ...states[name], busy: false, error: error instanceof Error ? error.message : 'Pooling change failed.' });
    }
  };

  const undo = async (name: string) => {
    const previous = states[name];
    if (!connected ||
        !previous?.undoId ||
        !previous.revision) {
      update(name, { ...previous, busy: false, error: 'No connected, undoable change is available.' });
      return;
    }
    update(name, { ...previous, busy: true, error: undefined });
    try {
      const result = await changePooling(name, { undoId: previous.undoId, revision: previous.revision });
      onSnapshot(result.snapshot);
      update(name, { busy: false, message: 'Previous pooling settings restored.' });
    } catch (error) {
      update(name, { ...previous, busy: false, error: error instanceof Error ? error.message : 'Undo failed.' });
    }
  };

  return { states, apply, undo };
}

export type PoolingActions = ReturnType<typeof usePoolingActions>;
