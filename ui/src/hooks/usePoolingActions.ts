import { useEffect, useRef, useState } from 'react';
import { changePooling, fetchSnapshot, parsePoolingBatch, reloadPooling, type PoolingResult } from '../lib/api';
import { hasSnapshotOrder, type SnapshotUpdate } from '../lib/snapshotOrder';
import type { PoolingBatch, PoolingBatchChange, Snapshot } from '../types';

export interface PoolingActionState {
  busy: boolean;
  error?: string;
  message?: string;
  undoId?: string;
  revision?: string;
  batchId?: string;
  status?: PoolingBatch['status'] | 'unavailable';
  requested?: PoolingBatchChange;
  batchError?: string;
}

interface BatchReceipt {
  name: string;
  undoId?: string;
  instanceId: string;
  snapshotVersion: number;
  summary: PoolingBatch;
  previousUndo?: BatchReceipt;
  unavailable?: boolean;
  reread?: boolean;
}

function reconcileReceipts(previous: Record<string, BatchReceipt>, snapshot: Snapshot) {
  const instanceId = snapshot.instanceId ?? snapshot.startedAt;
  const next = { ...previous };
  const restored: BatchReceipt[] = [];
  const reconcile = (receipt: BatchReceipt): BatchReceipt => {
    if (receipt.unavailable) return receipt;
    const predatesReceipt = receipt.instanceId === instanceId &&
      (!hasSnapshotOrder(snapshot) || snapshot.snapshotVersion < receipt.snapshotVersion);
    if (predatesReceipt) return receipt;
    const reported = snapshot.prewarm?.batches?.find((batch) => batch.id === receipt.summary.id);
    if (receipt.instanceId !== instanceId ||
        !reported) {
      return { ...receipt, unavailable: true, undoId: undefined, previousUndo: undefined };
    }
    return { ...receipt, summary: parsePoolingBatch(reported) };
  };
  for (const [id, receipt] of Object.entries(previous)) {
    const current = reconcile(receipt);
    const notCommitted = current.summary.status === 'cancelled' ||
      (current.summary.status === 'failed' && current.summary.commitState === 'not-committed');
    if (!current.unavailable &&
        notCommitted) {
      if (current.previousUndo) restored.push(current.previousUndo);
      next[id] = { ...current, undoId: undefined, previousUndo: undefined };
    } else if (current.summary.status === 'failed') {
      next[id] = {
        ...current,
        undoId: undefined,
        previousUndo: current.summary.commitState === 'unknown' ? current.previousUndo : undefined,
      };
    } else if (current.summary.status === 'applied') {
      next[id] = { ...current, previousUndo: undefined };
    } else {
      next[id] = current;
    }
  }
  for (const receipt of restored) next[receipt.summary.id] = reconcile(receipt);
  return Object.fromEntries(Object.entries(next).slice(-32));
}

export function usePoolingActions(snapshot: Snapshot | null, connected: boolean, onSnapshot: (snapshot: Snapshot) => SnapshotUpdate) {
  const [localStates, setStates] = useState<Record<string, PoolingActionState>>({});
  const [receipts, setReceipts] = useState<Record<string, BatchReceipt>>({});
  const [request, setRequest] = useState<string | null>(null);
  const [batchError, setBatchError] = useState<string>();
  const [readMessage, setReadMessage] = useState<string>();
  const [readFailures, setReadFailures] = useState<string[]>([]);
  const [now, setNow] = useState(Date.now);
  const inFlight = useRef(false);
  const instanceId = snapshot?.instanceId ?? snapshot?.startedAt;
  const firstInstance = useRef(instanceId);
  if (!firstInstance.current) firstInstance.current = instanceId;
  const instanceChanged = Boolean(firstInstance.current && instanceId !== firstInstance.current);
  const batches = (snapshot?.prewarm?.batches ?? []).map(parsePoolingBatch);
  const pending = batches.filter((batch) => batch.status === 'pending' || batch.status === 'applying');
  const unavailable = Object.values(receipts).filter((receipt) => receipt.unavailable);
  const failureKey = (batch: PoolingBatch, bridgeInstance = instanceId) =>
    JSON.stringify([bridgeInstance, batch.id, batch.commitState, batch.revision]);
  const unreadFailures = batches.filter((batch) =>
    batch.status === 'failed' &&
    batch.commitState !== 'not-committed' &&
    !readFailures.includes(failureKey(batch)));
  const failureWarning = unreadFailures.length > 0
    ? 'A failed batch committed or has an unknown commit outcome. Reread active settings before another change. Rollback is not confirmed; nothing will be resubmitted.'
    : undefined;
  const needsReread = unavailable.some((receipt) => !receipt.reread) || unreadFailures.length > 0;
  const editable = connected && Boolean(snapshot?.prewarm) && !instanceChanged && !request && !needsReread;

  useEffect(() => {
    if (!connected ||
        !snapshot) return;
    setReceipts((previous) => reconcileReceipts(previous, snapshot));
  }, [snapshot, connected, instanceId]);

  const hasCountdown = connected && pending.some((batch) => batch.status === 'pending');
  useEffect(() => {
    if (!hasCountdown) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [hasCountdown]);

  const update = (name: string, state: PoolingActionState) =>
    setStates((previous) => ({ ...previous, [name]: state }));

  const finish = () => {
    inFlight.current = false;
    setRequest(null);
  };

  const remember = (name: string, result: PoolingResult, current: Snapshot | null, previousUndo?: BatchReceipt) => {
    if (!result.pending) return;
    const acceptedSnapshot = result.snapshot;
    if (!hasSnapshotOrder(acceptedSnapshot)) {
      throw new Error('Queued change has no snapshot ordering information. Reread active settings before retrying.');
    }
    const summary = acceptedSnapshot.prewarm!.batches!.find((batch) => batch.id === result.batchId)!;
    setReceipts((previous) => {
      const next = { ...previous };
      if (previousUndo) next[previousUndo.summary.id] = { ...previousUndo, undoId: undefined };
      next[result.batchId] = {
        name,
        undoId: result.undoId,
        instanceId: acceptedSnapshot.instanceId,
        snapshotVersion: acceptedSnapshot.snapshotVersion,
        summary,
        previousUndo: previousUndo ?? previous[result.batchId]?.previousUndo,
      };
      return current ? reconcileReceipts(next, current) : Object.fromEntries(Object.entries(next).slice(-32));
    });
  };

  const apply = async (name: string, count: number | null) => {
    if (inFlight.current) return;
    if (!editable ||
        !snapshot?.prewarm) {
      update(name, { ...localStates[name], busy: false, error: 'Reconnect and reread active settings before changing configuration.' });
      return;
    }
    inFlight.current = true;
    setRequest(`server:${name}`);
    update(name, { ...localStates[name], busy: true, error: undefined, message: undefined });
    try {
      const revision = snapshot.prewarm.revision;
      const change = count === null
        ? { mode: 'isolated' as const, revision }
        : { mode: 'pool' as const, minWarm: count, revision };
      const result = await changePooling(name, change);
      const publication = onSnapshot(result.snapshot);
      remember(name, result, publication.snapshot);
      update(name, result.pending ? { busy: false } : {
        busy: false,
        revision: result.revision,
        undoId: result.undoId,
        message: !publication.accepted
          ? 'Request completed; newer active settings are shown.'
          : count === null ? 'Pre-warming disabled.' : `Enabled ${count} warm slot${count === 1 ? '' : 's'}.`,
      });
    } catch (error) {
      update(name, { ...localStates[name], busy: false, error: error instanceof Error ? error.message : 'Pooling change failed.' });
    } finally {
      finish();
    }
  };

  const undo = async (name: string) => {
    if (inFlight.current) return;
    const previous = localStates[name];
    if (!editable ||
        !previous?.undoId ||
        !previous.revision ||
        !snapshot) {
      update(name, { ...previous, busy: false, error: 'No connected, undoable change is available.' });
      return;
    }
    inFlight.current = true;
    setRequest(`server:${name}`);
    update(name, { ...previous, busy: true, error: undefined });
    try {
      const result = await changePooling(name, { undoId: previous.undoId, revision: previous.revision });
      const publication = onSnapshot(result.snapshot);
      remember(name, result, publication.snapshot);
      update(name, {
        busy: false,
        message: result.pending ? undefined : publication.accepted
          ? 'Previous pooling settings restored.'
          : 'Undo response received; newer active settings are shown.',
      });
    } catch (error) {
      update(name, { ...previous, busy: false, error: error instanceof Error ? error.message : 'Undo failed.' });
    } finally {
      finish();
    }
  };

  const batchAction = (batch: PoolingBatch) => {
    const receipt = receipts[batch.id];
    const label = batch.status === 'pending' ? 'Cancel batch' : 'Undo batch';
    let reason: string | undefined;
    if (!connected) reason = 'Bridge disconnected. Reconnect to use this receipt.';
    else if (instanceChanged) reason = 'Bridge instance changed. Reload the dashboard to renew the admin session.';
    else if (request) reason = 'Another configuration request is in progress.';
    else if (needsReread) reason = 'Reread active settings before another configuration action.';
    else if (!receipt?.undoId ||
             receipt.unavailable) reason = 'This dashboard has no usable private receipt for this batch.';
    else if (batch.status !== 'pending' &&
             batch.status !== 'applied') reason = 'This batch cannot be cancelled or undone in its current state.';
    else if (batch.revision !== snapshot?.prewarm?.revision) reason = 'Active settings changed. This Undo receipt is stale.';
    else if (batch.status === 'applied' &&
             pending.some((entry) => entry.id !== batch.id)) reason = 'Cancel or wait for the other batch before Undo. It will not be discarded.';
    return { label, reason, available: Boolean(receipt?.undoId) && !receipt?.unavailable };
  };

  const undoBatch = async (id: string, intent: 'cancel' | 'undo') => {
    if (inFlight.current) return;
    const batch = batches.find((entry) => entry.id === id);
    const receipt = receipts[id];
    if (!batch ||
        !receipt ||
        !snapshot) return;
    const expectedStatus = intent === 'cancel' ? 'pending' : 'applied';
    const problem = batchAction(batch).reason;
    if (problem ||
        batch.status !== expectedStatus) {
      setBatchError(problem ?? 'Batch status changed. Review its current status before acting.');
      return;
    }
    const names = batch.changes.map((change) => change.name);
    const label = intent === 'cancel' ? 'Cancel' : 'Undo';
    const scope = `${names.length} server${names.length === 1 ? '' : 's'}: ${names.join(', ')}`;
    const detail = intent === 'cancel'
      ? 'None of this pending batch will be applied.'
      : 'This stages the entire previous configuration for another five-second batch.';
    if (!window.confirm(`${label} the whole batch (${scope})?\n${detail}`)) return;
    inFlight.current = true;
    setRequest(`batch:${id}`);
    setBatchError(undefined);
    try {
      const result = await changePooling(receipt.name, { undoId: receipt.undoId!, revision: batch.revision });
      const publication = onSnapshot(result.snapshot);
      if (result.pending) {
        remember(receipt.name, result, publication.snapshot, intent === 'undo' ? { ...receipt, summary: batch, previousUndo: undefined } : undefined);
      } else {
        setReceipts((previous) => {
          const next: Record<string, BatchReceipt> = {
            ...previous,
            [id]: {
              ...previous[id],
              undoId: undefined,
              summary: { ...batch, status: result.cancelled ? 'cancelled' : 'applied', applyAt: null },
            },
          };
          return publication.snapshot ? reconcileReceipts(next, publication.snapshot) : next;
        });
      }
    } catch (error) {
      setBatchError(error instanceof Error ? error.message : 'Batch action failed.');
    } finally {
      finish();
    }
  };

  const reread = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRequest('read');
    setBatchError(undefined);
    setReadMessage(undefined);
    try {
      const next = await fetchSnapshot();
      const publication = onSnapshot(next);
      if (!publication.accepted) {
        setReadMessage('Reread response was older than the current snapshot or came from a retired bridge. Current active settings and receipts were kept; reread again if needed.');
        return;
      }
      const nextInstance = next.instanceId ?? next.startedAt;
      setReadFailures((next.prewarm?.batches ?? [])
        .filter((batch) => batch.status === 'failed')
        .map((batch) => failureKey(batch, nextInstance)));
      setReceipts((previous) => Object.fromEntries(Object.entries(reconcileReceipts(previous, next)).map(([id, receipt]) =>
        [id, receipt.unavailable ? { ...receipt, reread: true } : receipt])));
      setReadMessage('Active settings reread. No change was resubmitted.');
    } catch (error) {
      setBatchError(error instanceof Error ? error.message : 'Reading active settings failed.');
    } finally {
      finish();
    }
  };

  const reloadNow = async () => {
    if (inFlight.current ||
        !editable ||
        !snapshot) return;
    inFlight.current = true;
    setRequest('reload');
    setBatchError(undefined);
    try {
      onSnapshot(await reloadPooling());
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Reload failed.';
      setBatchError(message);
      try {
        onSnapshot(await fetchSnapshot());
      } catch {
        setBatchError(`${message} Could not reread active settings; the reload outcome is unconfirmed.`);
      }
    } finally {
      finish();
    }
  };

  const states = { ...localStates };
  for (const receipt of Object.values(receipts)) {
    const batch = receipt.summary;
    for (const change of batch.changes) {
      const newerRequest = localStates[change.name]?.busy || localStates[change.name]?.error;
      states[change.name] = {
        ...localStates[change.name],
        busy: request === `server:${change.name}`,
        batchId: batch.id,
        status: receipt.unavailable ? 'unavailable' : newerRequest ? undefined : batch.status,
        undoId: receipt.unavailable ? undefined : receipt.undoId,
        revision: batch.revision,
        batchError: batch.error,
        message: undefined,
      };
    }
  }
  for (const batch of [...pending].reverse()) {
    for (const change of batch.changes) {
      states[change.name] = {
        ...states[change.name],
        busy: request === `server:${change.name}`,
        batchId: batch.id,
        status: batch.status,
        requested: change,
        message: undefined,
      };
    }
  }

  return {
    states, apply, undo, batches, pending, batchAction, undoBatch, reloadNow, reread,
    now, editable, instanceChanged, unavailable, needsReread, readMessage,
    batchError: [batchError, failureWarning].filter(Boolean).join(' ') || undefined,
    busy: request !== null,
    reloading: request === 'reload',
    reading: request === 'read',
  };
}

export type PoolingActions = ReturnType<typeof usePoolingActions>;
