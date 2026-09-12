import type { Snapshot } from '../types';

export type OrderedSnapshot = Snapshot & { instanceId: string; snapshotVersion: number };

export interface SnapshotUpdate<T extends Snapshot = Snapshot> {
  accepted: boolean;
  snapshot: T | null;
  reason?: 'older' | 'retired';
}

export function hasSnapshotOrder(snapshot: Snapshot): snapshot is OrderedSnapshot {
  return typeof snapshot.instanceId === 'string' &&
    snapshot.instanceId.length > 0 &&
    Number.isSafeInteger(snapshot.snapshotVersion) &&
    (snapshot.snapshotVersion ?? 0) > 0;
}

export function validateSnapshotOrder(snapshot: Snapshot) {
  const requiresOrder = snapshot.snapshotVersion !== undefined || snapshot.prewarm?.batches !== undefined;
  if (requiresOrder &&
      !hasSnapshotOrder(snapshot)) {
    throw new Error('Snapshot ordering information is missing or invalid. Active values were kept; update the bridge and reload the dashboard.');
  }
}

export class SnapshotOrder<T extends Snapshot = Snapshot> {
  private current: T | null = null;
  private retiredInstances = new Set<string>();

  accept(next: T): SnapshotUpdate<T> {
    validateSnapshotOrder(next);
    const currentInstance = this.current?.instanceId ?? this.current?.startedAt;
    const nextInstance = next.instanceId ?? next.startedAt;
    if (nextInstance &&
        this.retiredInstances.has(nextInstance)) {
      return { accepted: false, snapshot: this.current, reason: 'retired' };
    }
    if (this.current &&
        currentInstance === nextInstance) {
      const currentOrdered = hasSnapshotOrder(this.current);
      if (currentOrdered &&
          !hasSnapshotOrder(next)) {
        throw new Error('An unordered snapshot cannot replace this bridge’s versioned snapshot. Active values were kept.');
      }
      if (currentOrdered &&
          next.snapshotVersion! <= this.current.snapshotVersion!) {
        return { accepted: false, snapshot: this.current, reason: 'older' };
      }
    }
    if (currentInstance &&
        currentInstance !== nextInstance) {
      this.retiredInstances.add(currentInstance);
    }
    this.current = next;
    return { accepted: true, snapshot: next };
  }
}
