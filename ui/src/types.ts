export interface ServerHealth {
  state: 'ok' | 'failing' | 'unknown';
  consecutiveFailures: number;
  lastSuccessSec: number | null;
  lastErrorSec: number | null;
}

export interface ServerStat {
  name: string;
  type: 'stdio' | 'http';
  url?: string;
  sessions: number;
  pids: number[];
  requests: number;
  lastError: string | null;
  lastActivitySec: number | null;
  tokenExpiresIn?: number | null;
  clients?: string[];
  sharing?: string;
  warm?: number;
  spawn?: {
    attempts: number;
    total: number;
    failures: number;
    warmAdoptions: number;
    sessionStarts: number;
    sessionResumes: number;
    samples: number;
    p50Ms: number | null;
    p95Ms: number | null;
    maxMs: number | null;
  } | null;
  peakConcurrency?: number;
  advice?: { reason: string; suggest: { sharing: string; minWarm: number } } | null;
  minWarm?: number;
  prewarming?: {
    eligible: boolean;
    reason?: string;
    suggestedMinWarm: number;
    configuredMinWarm: number | null;
  };
  maxSessions?: number | null;
  cappedSessions?: number;
  startingSessions?: number;
  shared?: {
    generation: string;
    state: 'starting' | 'ready' | 'draining' | 'stopping' | 'dead';
    pid: number | null;
    members: number;
    waiters: number;
    unresolved: number;
    queued: number;
  } | null;
  health?: ServerHealth;
}

export type PoolingBatchChange = { name: string } & (
  | { mode: 'pool'; minWarm?: number }
  | { mode: 'isolated' }
);

export type PoolingCommitState = 'not-committed' | 'committed' | 'unknown';

interface PoolingBatchSummary {
  id: string;
  applyAt: number | null;
  revision: string;
  changes: PoolingBatchChange[];
  error?: string;
}

export type PoolingBatch = PoolingBatchSummary & (
  | { status: 'failed'; commitState: PoolingCommitState }
  | { status: 'pending' | 'applying' | 'applied' | 'cancelled'; commitState?: PoolingCommitState }
);

export interface Snapshot {
  ok: boolean;
  service: string;
  version: string;
  port: number;
  uptimeSec: number;
  instanceId?: string;
  snapshotVersion?: number;
  startedAt?: string;
  prewarm?: {
    revision: string;
    maxWarm: number;
    batchDelayMs?: number;
    saveWarning?: string;
    batches?: PoolingBatch[];
  };
  sessions: number;
  restart?: { sinceSec: number; resumable: number; staleClients: number } | null;
  servers: ServerStat[];
}
