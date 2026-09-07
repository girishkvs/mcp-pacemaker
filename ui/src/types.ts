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
  spawn?: { samples: number; p50Ms: number; p95Ms: number; maxMs: number } | null;
  peakConcurrency?: number;
  advice?: { reason: string; suggest: { sharing: string; minWarm: number } } | null;
  maxSessions?: number | null;
  cappedSessions?: number;
  health?: ServerHealth;
}

export interface Snapshot {
  ok: boolean;
  service: string;
  version: string;
  port: number;
  uptimeSec: number;
  sessions: number;
  restart?: { sinceSec: number; resumable: number; staleClients: number } | null;
  servers: ServerStat[];
}
