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
  maxSessions?: number | null;
}

export interface Snapshot {
  ok: boolean;
  service: string;
  version: string;
  port: number;
  uptimeSec: number;
  sessions: number;
  servers: ServerStat[];
}
