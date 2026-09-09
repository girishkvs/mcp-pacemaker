#!/usr/bin/env node
/**
 * mcp-bridge.mjs — zero-dependency stdio/HTTP MCP bridge with pluggable auth.
 * Part of mcp-pacemaker. MIT.
 *
 * WHY
 *   Editor clients (VS Code, Cursor, Claude Desktop) spawn stdio MCP servers as children
 *   of their extension host. When the host restarts or crashes, every stdio server dies at
 *   once. This bridge runs the servers as children of a long-lived process and exposes each
 *   over the MCP HTTP+SSE transport, so the client simply RECONNECTS after a host restart —
 *   the servers keep running.
 *
 * ZERO DEPENDENCIES
 *   Node built-ins only. Nothing is pulled from a package registry at runtime.
 *
 * AUTH (per http server)
 *   "auth": { "type": "command", "command": "<cli that prints a token>", "refreshMinutes": 50 }
 *   "auth": { "type": "env", "var": "MY_TOKEN" }
 *   "auth": { "type": "static", "header": "Authorization", "value": "Bearer ..." }
 *   "auth": { "type": "none" }
 *   Back-compat: a bare "audience": "<res>" is treated as an `az account get-access-token` command.
 *
 * USAGE
 *   node mcp-bridge.mjs [--port 8791] [--host 127.0.0.1] [--config servers.json] [--cwd <dir>]
 */
import http from 'node:http';
import https from 'node:https';
import { spawn, exec, execFile, execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync, appendFileSync, statSync, renameSync, watch } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, extname } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { checkServerPaths, checkReservedName } from './config-checks.mjs';
import { ServerMetrics } from './server-metrics.mjs';
import { MAX_MIN_WARM } from './pooling-config.mjs';
import { PoolingConfigWriter } from './pooling-writer.mjs';
import { POOLING_BUDGET_MS } from './pooling-execution.mjs';
import { SharedSessionManager, SHARED_DEFAULTS } from './shared-sessions.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const getArg = (name, def) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : def;
};

const HOME = resolve(homedir(), '.mcp-pacemaker');
const defaultConfig = existsSync(resolve(process.cwd(), 'servers.json'))
  ? resolve(process.cwd(), 'servers.json')
  : resolve(HOME, 'servers.json');
const CONFIG = resolve(process.cwd(), getArg('--config', defaultConfig));
const PORT = parseInt(getArg('--port', '8791'), 10);
const HOST = getArg('--host', '127.0.0.1');
const VERSION = (() => { try { return JSON.parse(readFileSync(resolve(__dirname, '..', 'package.json'), 'utf8')).version; } catch { return '0'; } })();
// Base working directory for relative server commands/args. Defaults to the config's folder.
const BASE_CWD = resolve(getArg('--cwd', dirname(CONFIG)));

/** @type {Record<string, any>} */
const servers = JSON.parse(readFileSync(CONFIG, 'utf8'));
const poolingConfig = new PoolingConfigWriter(CONFIG);

/* ----------------------------- dashboard backbone --------------------------- */
const startedAt = Date.now();
const instanceId = randomUUID();
const serverMetrics = new ServerMetrics();
const ADMIN_NONCE = randomUUID();
const NONCE_FILE = resolve(dirname(CONFIG), 'admin.nonce');
const logBuffer = [];
const logClients = new Set();
const snapClients = new Set();
const stats = new Map(); // name -> see stat()
const stat = (name) => {
  let s = stats.get(name);
  if (!s) { s = { requests: 0, lastError: null, lastErrorAt: 0, lastActivity: 0, lastSuccess: 0, consecutiveFailures: 0, lastProbe: 0 }; stats.set(name, s); }
  return s;
};

/* ------------------------------- server health ------------------------------ */
// `lastError` alone is not a health signal: it is sticky, so a server that failed once last week
// looks identical to one that is failing right now, and one that recovered still shows the old
// error. A server 401ing on every call sat that way for hours here while the dashboard showed
// nothing wrong. Health is therefore a running verdict — did the last attempt work, and how many
// in a row have not — rather than a string that only ever accumulates.
function noteSuccess(name) {
  const s = stat(name);
  if (s.consecutiveFailures > 0) log(`[${name}] recovered after ${s.consecutiveFailures} consecutive failure(s)`);
  s.consecutiveFailures = 0;
  s.lastSuccess = Date.now();
  s.lastError = null;
}

function noteFailure(name, detail) {
  const s = stat(name);
  if (s.consecutiveFailures === 0) log(`[${name}] now failing: ${detail}`);
  s.consecutiveFailures++;
  s.lastError = detail;
  s.lastErrorAt = Date.now();
}

// 'unknown' is deliberately distinct from 'ok'. Reporting a server nobody has called as healthy
// is the exact lie this feature exists to stop.
function healthOf(name) {
  const s = stat(name);
  const state = s.consecutiveFailures > 0 ? 'failing' : (s.lastSuccess ? 'ok' : 'unknown');
  return {
    state,
    consecutiveFailures: s.consecutiveFailures,
    lastSuccessSec: s.lastSuccess ? Math.round((Date.now() - s.lastSuccess) / 1000) : null,
    lastErrorSec: s.lastErrorAt ? Math.round((Date.now() - s.lastErrorAt) / 1000) : null,
  };
}

// A durable log next to the config. The in-memory buffer is all the dashboard and `/api/logs`
// have, and a single chatty client fills it in minutes — on a real setup a client polling every
// 30s left roughly two minutes of history, which is useless for diagnosing something that
// happened overnight. stderr alone does not help either: the supervisor starts the bridge
// without redirecting it, and on Windows that output goes nowhere. So write here too, and roll
// the file at a fixed size so it cannot grow without bound.
const LOG_FILE = resolve(dirname(CONFIG), 'bridge.log');
const LOG_MAX_BYTES = parseInt(process.env.MCP_LOG_MAX_BYTES || String(5 * 1024 * 1024), 10);
let logBytes = -1; // -1 until the existing file has been measured once
function appendLog(line) {
  if (LOG_MAX_BYTES <= 0) return;
  try {
    if (logBytes < 0) logBytes = existsSync(LOG_FILE) ? statSync(LOG_FILE).size : 0;
    if (logBytes >= LOG_MAX_BYTES) {
      renameSync(LOG_FILE, LOG_FILE + '.1'); // keep one previous file, overwriting any older one
      logBytes = 0;
    }
    const buf = line + '\n';
    appendFileSync(LOG_FILE, buf);
    logBytes += Buffer.byteLength(buf);
  } catch { /* logging must never take the bridge down */ }
}

const log = (m) => {
  const line = `[mcp-bridge] ${new Date().toISOString()} ${m}`;
  process.stderr.write(line + '\n');
  appendLog(line);
  logBuffer.push(line); if (logBuffer.length > 500) logBuffer.shift();
  for (const c of logClients) { try { c.write(`data: ${JSON.stringify(line)}\n\n`); } catch { /* gone */ } }
};

// Token expiry (seconds) for an http server's cached command/az token, if any — for the dashboard.
//
// A bare `audience` is shorthand for an Azure CLI token command. It is expanded in exactly one
// place because the expanded string is also the token cache key: two copies that drift would
// mint under one key and look it up under another, quietly disabling the cache.
const azTokenCommand = (audience) =>
  `az account get-access-token --resource ${audience} --query accessToken -o tsv`;
function normalizedAuth(def) {
  if (def.auth) return def.auth;
  if (def.audience) return { type: 'command', command: azTokenCommand(def.audience), refreshMinutes: 50 };
  return null;
}
function authCacheKey(def) {
  const auth = normalizedAuth(def);
  return auth && auth.type === 'command' ? auth.command : null;
}
function tokenExpiryFor(def) {
  const key = authCacheKey(def);
  if (!key) return null;
  const c = tokenCache.get(key);
  return c ? Math.max(0, Math.round((c.exp - Date.now()) / 1000)) : null;
}

// Rich per-server snapshot for the dashboard (/api/status, /api/events).
function richSnapshot() {
  const byName = {};
  for (const name of Object.keys(servers)) {
    const def = servers[name];
    const st = stat(name);
    byName[name] = { name, type: def.type === 'http' ? 'http' : 'stdio', sessions: 0, cappedSessions: 0, pids: [], clients: [], sharing: def.sharing || 'isolated', warm: (warmPool.get(name) || []).length, minWarm: poolTarget(name), recycleMinutes: recycleMinutesFor(name) || null, maxSessions: (def.maxSessions ?? MAX_SESSIONS_PER_SERVER) || null, requests: st.requests, lastError: st.lastError, lastActivitySec: st.lastActivity ? Math.round((Date.now() - st.lastActivity) / 1000) : null, health: healthOf(name), spawn: spawnStats(name), peakConcurrency: peakConcurrency(name), advice: poolAdvice(name) };
    byName[name].prewarming = prewarmingState(name);
    byName[name].shared = sharedManager.inspect(name);
    if (byName[name].shared?.pid) byName[name].pids.push(byName[name].shared.pid);
    byName[name].startingSessions = startingSessions.get(name) || 0;
    byName[name].cappedSessions += byName[name].startingSessions;
    if (def.type === 'http') { byName[name].url = def.url; byName[name].tokenExpiresIn = tokenExpiryFor(def); }
  }
  // `sessions` sums both transports for display, but `maxSessions` only governs the streamable
  // pool — so a classic SSE session made the card read "33/32" as though the cap had been
  // breached. Report the number the cap actually counts alongside it.
  for (const s of sessions.values()) { const b = byName[s.name]; if (b) { b.sessions++; if (s.child?.pid) b.pids.push(s.child.pid); } }
  for (const s of httpSessions.values()) { const b = byName[s.name]; if (b) { b.sessions++; b.cappedSessions++; if (s.child?.pid && !b.pids.includes(s.child.pid)) b.pids.push(s.child.pid); if (s.clientInfo && s.clientInfo.name && !b.clients.includes(s.clientInfo.name)) b.clients.push(s.clientInfo.name); } }
  const prewarm = { revision: createHash('sha256').update(lastConfigText ?? '').digest('hex'), maxWarm: MAX_MIN_WARM };
  return { ok: true, service: 'mcp-pacemaker', version: VERSION, port: PORT, instanceId, startedAt: new Date(startedAt).toISOString(), prewarm, uptimeSec: Math.round((Date.now() - startedAt) / 1000), sessions: sessions.size + httpSessions.size, restart: restartStatus(), servers: Object.values(byName) };
}

function prewarmingState(name) {
  const def = servers[name];
  let reason;
  if (def.type === 'http' ||
      !def.command ||
      def.url) {
    reason = 'HTTP proxies have no local child to pre-warm.';
  } else if (def.sharing === 'shared') {
    reason = 'Shared mode reuses initialized children; switch to isolated mode before enabling a warm pool.';
  }
  const desired = poolAdvice(name)?.suggest.minWarm ?? poolTarget(name) ?? 1;
  return {
    eligible: !reason,
    reason,
    suggestedMinWarm: Math.max(1, Math.min(MAX_MIN_WARM, desired || 1)),
    configuredMinWarm: def.minWarm ?? null,
  };
}

// After a restart, a client whose session the bridge is holding open for it but which has not
// come back is very likely wedged: some clients treat one connection failure as permanent and
// never retry, so the user has to reload them by hand. The bridge cannot fix that from here,
// but it can stop the user having to guess.
const RESTART_NOTICE_MS = 30 * 60_000;
// How far back a resume record still implies a live client. The resume file keeps a day of
// records, most of which belong to sessions that ended normally long before the restart.
const STALE_CLIENT_WINDOW_MS = 30 * 60_000;
function restartStatus() {
  const sinceSec = Math.round((Date.now() - startedAt) / 1000);
  if (sinceSec * 1000 > RESTART_NOTICE_MS) return null;
  let stale = 0;
  for (const [id, r] of resumable) {
    // A client that was live when the bridge went down: recorded before this process started,
    // not seen since, and enough time has passed that an active one would have come back.
    // Bounded to recently-active records, because the resume file holds a day of churn — one
    // polling client here left hundreds of dead ids, and counting all of them reported 326
    // stale clients where there were three.
    const recordedBeforeRestart = (r.at || 0) < startedAt;
    const activeNearTheRestart = (r.at || 0) > startedAt - STALE_CLIENT_WINDOW_MS;
    const hasNotComeBack = !httpSessions.has(id);
    const longEnoughToJudge = Date.now() - startedAt > 120_000;
    if (recordedBeforeRestart &&
        activeNearTheRestart &&
        hasNotComeBack &&
        longEnoughToJudge) {
      stale++;
    }
  }
  return { sinceSec, resumable: resumable.size, staleClients: stale };
}

// Health checks for the dashboard Health page (fast, no network).
function runDoctor() {
  const checks = [];
  const major = parseInt(process.versions.node.split('.')[0], 10);
  checks.push({ name: 'Node.js', status: major >= 20 ? 'ok' : 'bad', detail: process.versions.node });
  const names = Object.keys(servers);
  checks.push({ name: 'config', status: names.length ? 'ok' : 'warn', detail: `${names.length} server(s)` });
  for (const n of names) {
    const d = servers[n];
    const reserved = checkReservedName(n);
    if (reserved) { checks.push(reserved); continue; }
    if (!d.command && !d.url) { checks.push({ name: n, status: 'bad', detail: 'missing command/url' }); continue; }
    if (d.type === 'http' && !d.auth && !d.audience && !d.headers) { checks.push({ name: n, status: 'warn', detail: 'http server with no auth' }); continue; }
    const pathCheck = checkServerPaths(n, d, BASE_CWD);
    if (pathCheck) { checks.push(pathCheck); continue; }
    const h = healthOf(n);
    if (h.state === 'failing') { checks.push({ name: n, status: 'bad', detail: `failing — ${h.consecutiveFailures} in a row: ${stat(n).lastError}` }); continue; }
    checks.push({ name: n, status: 'ok', detail: d.type === 'http' ? `http ${d.url}` : `stdio ${d.command}` });
  }
  checks.push({ name: 'admin nonce', status: existsSync(NONCE_FILE) ? 'ok' : 'warn', detail: NONCE_FILE });
  return { ran: new Date().toISOString(), checks };
}

function handleApi(sub, req, res) {
  if (sub === 'status') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(richSnapshot())); return; }
  if (sub === 'doctor') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(runDoctor())); return; }
  if (sub === 'events') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' });
    res.write(`data: ${JSON.stringify(richSnapshot())}\n\n`);
    snapClients.add(res);
    req.on('close', () => snapClients.delete(res));
    return;
  }
  if (sub === 'logs') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' });
    for (const line of logBuffer.slice(-100)) res.write(`data: ${JSON.stringify(line)}\n\n`);
    logClients.add(res);
    req.on('close', () => logClients.delete(res));
    return;
  }
  res.writeHead(404).end('unknown api');
}

// Loopback + nonce guarded control surface. The nonce is written to admin.nonce next to the
// config, so only same-box tooling (the CLI, the served dashboard) can read it.
function handleAdmin(url, req, res) {
  const host = (req.headers.host || '').split(':')[0];
  if (host !== '127.0.0.1' && host !== 'localhost') { res.writeHead(403).end('forbidden'); return; }
  if (req.headers['x-mcp-nonce'] !== ADMIN_NONCE) { res.writeHead(401).end('bad nonce'); return; }
  const parts = url.pathname.split('/').filter(Boolean); // ['admin','recycle'|'reload', <name>?]
  if (req.method === 'POST' &&
      parts.length === 4 &&
      parts[1] === 'servers' &&
      parts[3] === 'pooling') {
    handlePoolingChange(parts[2], req, res);
    return;
  }
  if (req.method === 'POST' && parts[1] === 'reload') {
    const r = reloadConfig('admin request');
    res.writeHead(r.ok ? 200 : 400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(r));
    return;
  }
  if (req.method === 'POST' && parts[1] === 'recycle') {
    const target = parts[2];
    const killed = recycleServer(target);
    log(`admin: recycled ${killed} session(s)${target ? ` for ${target}` : ''}`);
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true, recycled: killed }));
    return;
  }
  res.writeHead(404).end('unknown admin action');
}

function handlePoolingChange(encodedName, req, res) {
  const reply = (status, body) => {
    if (res.destroyed ||
        res.writableEnded) return;
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  if (shuttingDown) {
    reply(503, { error: 'Bridge is shutting down.' });
    req.resume();
    return;
  }
  const origin = req.headers.origin;
  if (origin &&
      origin !== `http://${req.headers.host}`) {
    reply(403, { error: 'Pooling changes require the dashboard origin.' });
    req.resume();
    return;
  }
  const chunks = [];
  let bytes = 0;
  let rejected = false;
  const controller = new AbortController();
  const execution = {
    signal: controller.signal,
    deadline: process.hrtime.bigint() + BigInt(POOLING_BUDGET_MS) * 1000000n,
    onLateSettlement: ({ error, committed, commitStarted }) => {
      if (error &&
          error.code !== 'WRITER_CANCELLED' &&
          error.code !== 'WRITER_DEADLINE') {
        log(`pooling operation settled without a normal result (${error.code}); reread the config`);
      }
      if (!committed &&
          !commitStarted) return;
      const reloaded = reloadConfig('pooling commit settled without a normal result');
      if (!reloaded.ok) log('pooling commit settled but reload failed; reread the config');
    },
  };
  const bodyTimer = setTimeout(() => {
    rejected = true;
    chunks.length = 0;
    controller.abort();
    reply(408, { error: 'Pooling request body deadline exceeded. No change was submitted.' });
  }, POOLING_BUDGET_MS);
  res.on('close', () => {
    clearTimeout(bodyTimer);
    if (!res.writableFinished) controller.abort();
  });
  req.on('error', () => {
    clearTimeout(bodyTimer);
    controller.abort();
    rejected = true;
    chunks.length = 0;
    log('pooling request interrupted before completion');
  });
  req.on('data', (chunk) => {
    if (rejected) return;
    bytes += chunk.length;
    if (bytes > 4096) {
      rejected = true;
      chunks.length = 0;
      reply(413, { error: 'Pooling request exceeds 4096 bytes.' });
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', async () => {
    clearTimeout(bodyTimer);
    if (rejected) return;
    let body;
    let name;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      name = decodeURIComponent(encodedName);
    } catch {
      reply(400, { error: 'Invalid JSON or server name.' });
      return;
    }
    if (!body ||
        typeof body !== 'object' ||
        Array.isArray(body) ||
        Object.hasOwn(body, 'name')) {
      reply(400, { error: 'A pooling request object is required; the route selects the server.' });
      return;
    }
    try {
      const result = Object.hasOwn(body, 'undoId')
        ? await poolingConfig.undo({ ...body, name }, execution)
        : await poolingConfig.apply({ ...body, name }, execution);
      const reloaded = reloadConfig('pooling action');
      if (!reloaded.ok) {
        log(`[${name}] pooling settings saved but reload failed`);
        reply(500, { error: 'Settings were saved, but could not be activated. Reread the config before retrying.', revision: result.revision });
        return;
      }
      log(`[${name}] pooling ${Object.hasOwn(body, 'undoId') ? 'undo' : result.mode} applied`);
      reply(200, { ...result, snapshot: richSnapshot() });
    } catch (error) {
      const status = Number.isInteger(error.statusCode) ? error.statusCode : 500;
      log(`pooling action rejected (${error.code || 'IO_ERROR'})`);
      reply(status, { error: error.statusCode ? error.message : 'Unable to apply pooling settings.' });
    }
  });
}

/* ------------------------------ static dashboard ---------------------------- */
const UI_DIR = resolve(__dirname, '..', 'ui', 'dist');
const UI_MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png', '.woff2': 'font/woff2', '.map': 'application/json' };
function handleUi(pathname, res) {
  let rel = pathname.replace(/^\/ui\/?/, '');
  if (rel === '') rel = 'index.html';
  let file = resolve(UI_DIR, rel);
  // path-traversal guard + SPA fallback to index.html
  if (!file.startsWith(UI_DIR) || !existsSync(file)) file = resolve(UI_DIR, 'index.html');
  if (!existsSync(file)) { res.writeHead(404).end('dashboard not built (run: npm --prefix ui run build)'); return; }
  const ext = extname(file);
  if (ext === '.html') { res.writeHead(200, { 'Content-Type': UI_MIME['.html'] }); res.end(readFileSync(file, 'utf8').replace('__MCP_NONCE__', ADMIN_NONCE)); return; }
  res.writeHead(200, { 'Content-Type': UI_MIME[ext] ?? 'application/octet-stream' });
  res.end(readFileSync(file));
}

// Push snapshots to /api/events subscribers on an interval.
setInterval(() => { if (!snapClients.size) return; const p = `data: ${JSON.stringify(richSnapshot())}\n\n`; for (const c of snapClients) { try { c.write(p); } catch { /* gone */ } } }, 2000).unref();

/* ------------------------------ pluggable auth ------------------------------ */
const tokenCache = new Map(); // key -> { value, exp }
// key -> in-flight mint promise. On startup every server asks for its token at once; without
// this, each one spawns its own `az` and the concurrent calls are what make az exit 0 with no
// output. One mint per key, shared by all waiters.
const tokenInFlight = new Map();

// exec (not execFile with an explicit shell) so the command line is passed to the shell
// verbatim. Building `cmd /c <command>` by hand re-escapes any embedded quotes, which breaks
// every auth command that quotes an argument — a path containing spaces, for instance.
function runCommand(cmd) {
  return new Promise((res, rej) => {
    exec(cmd, { maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout) => (err ? rej(err) : res(stdout.toString().trim())));
  });
}

// How long a minted credential can be trusted.
//
// `refreshMinutes` is only a fallback. An auth command usually returns a JWT, and the command
// often serves it from the provider's OWN cache — `az account get-access-token` hands back a
// token it minted earlier, which may be most of the way through its life already. Caching that
// for a fixed window serves an expired credential until the window is up, and every request in
// between comes back 401 while the bridge reports a healthy token.
//
// So prefer the token's own `exp` claim when there is one. The payload is only read, never
// trusted for authorization, so parsing it unverified is safe here: the upstream is what
// validates the signature. Anything unparseable (an opaque token, an API key) falls back to
// `refreshMinutes`. A safety margin covers clock skew and the request still in flight.
const TOKEN_EXPIRY_MARGIN_MS = 60_000;
function tokenLifetimeMs(value, fallbackMs) {
  const parts = String(value).split('.');
  if (parts.length !== 3) return fallbackMs; // not a JWT
  try {
    const pad = '='.repeat((4 - (parts[1].length % 4)) % 4);
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8'));
    if (typeof payload.exp !== 'number') return fallbackMs;
    const remaining = payload.exp * 1000 - Date.now() - TOKEN_EXPIRY_MARGIN_MS;
    // A token already at or past its expiry is still returned to the caller — the upstream is
    // the authority on that — but it must not be cached.
    return remaining > 0 ? Math.min(remaining, fallbackMs) : 0;
  } catch { return fallbackMs; }
}

// Drop a server's cached credential so the next request mints a fresh one. Used when the
// upstream rejects it: continuing to serve a credential known to be refused just repeats the
// failure for the rest of its cache window.
function invalidateToken(def) {
  const key = authCacheKey(def);
  if (key) tokenCache.delete(key);
}

// Normalize a server's auth config into { header, getValue() } or null.
function resolveAuth(def) {
  const auth = normalizedAuth(def);
  if (!auth || auth.type === 'none') return null;

  const header = auth.header || 'Authorization';
  const prefix = auth.prefix != null ? auth.prefix : (header.toLowerCase() === 'authorization' ? 'Bearer ' : '');

  if (auth.type === 'static') return { header, getValue: async () => prefix + (auth.value ?? '') };
  if (auth.type === 'env') {
    return { header, getValue: async () => {
      const v = process.env[auth.var];
      if (!v) throw new Error(`env var ${auth.var} is not set`);
      return prefix + v;
    } };
  }
  if (auth.type === 'command') {
    const key = auth.command;
    const ttl = (auth.refreshMinutes ?? 50) * 60 * 1000;
    return { header, getValue: async () => {
      const c = tokenCache.get(key);
      if (c && c.exp > Date.now()) return prefix + c.value;
      const pending = tokenInFlight.get(key);
      if (pending) return prefix + (await pending);
      const mint = (async () => {
        const value = await runCommand(auth.command);
        // An auth command can exit 0 and print nothing. Caching that would serve an empty
        // credential for the whole TTL, so every upstream request 401s until it expires.
        if (!value) throw new Error(`auth command returned an empty value: ${auth.command}`);
        const life = tokenLifetimeMs(value, ttl);
        if (life > 0) tokenCache.set(key, { value, exp: Date.now() + life });
        else tokenCache.delete(key); // already expired on arrival — re-mint next time
        return value;
      })();
      const tracked = mint.finally(() => tokenInFlight.delete(key));
      tokenInFlight.set(key, tracked);
      return prefix + (await tracked);
    } };
  }
  throw new Error(`unknown auth.type "${auth.type}"`);
}

/* ---------------------- stdio servers (HTTP+SSE transport) ------------------ */
const sessions = new Map(); // sessionId -> { child, res, name }

// Quote one argument for a Windows `cmd /d /s /c` line using MSVCRT / CommandLineToArgvW
// rules, wrapping in double quotes to also neutralize cmd metacharacters. (`%` and `!` can't
// be escaped inside `cmd /c`; server commands come from the user's own trusted config.)
function quoteWinArg(s) {
  s = String(s);
  if (s !== '' && !/[\s"&|<>()^%!]/.test(s)) return s;
  let out = '"';
  let bs = 0;
  for (const c of s) {
    if (c === '\\') { bs++; }
    else if (c === '"') { out += '\\'.repeat(bs * 2 + 1) + '"'; bs = 0; }
    else { out += '\\'.repeat(bs) + c; bs = 0; }
  }
  return out + '\\'.repeat(bs * 2) + '"';
}

// Spawn a stdio server child. Bare Windows command names (npx/uvx/dnx `.cmd` shims) must run
// through cmd.exe; we build the command line ourselves and pass windowsVerbatimArguments so
// Node doesn't re-quote it. This avoids `shell:true` (and its DEP0190 deprecation + arg-
// injection footgun) while still resolving `.cmd` shims via PATHEXT. Absolute/`.exe` paths
// and every non-Windows platform spawn the command directly with shell disabled.
function spawnServer(name, def) {
  const args = def.args ?? [];
  const opts = {
    cwd: def.cwd ? resolve(BASE_CWD, def.cwd) : BASE_CWD,
    env: { ...process.env, ...(def.env ?? {}) },
    stdio: ['pipe', 'pipe', 'pipe'],
  };
  const bareWin = process.platform === 'win32' && !/[\\/]/.test(def.command) && !/\.(exe|com)$/i.test(def.command);
  serverMetrics.attemptingSpawn(name);
  let child;
  try {
    child = bareWin
      ? spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', '"' + [def.command, ...args].map(quoteWinArg).join(' ') + '"'], { ...opts, windowsVerbatimArguments: true })
      : spawn(def.command, args, opts);
  } catch (error) {
    serverMetrics.failedSpawn(name);
    throw error;
  }
  let spawned = false;
  child.once('spawn', () => {
    spawned = true;
    serverMetrics.spawned(name);
  });
  child.once('error', () => {
    if (!spawned) serverMetrics.failedSpawn(name);
  });
  child.__spawnedAt = Date.now(); // start of the cold-start clock; stopped when initialize lands
  return child;
}

/* --------------------------- child failure reporting ------------------------ */
// Remember the tail of a child's stderr so a non-zero exit can be reported with its reason.
// Without this, a server that starts and then crashes leaves lastError empty: /api/status and
// `doctor` look healthy while every session dies on spawn.
const stderrTails = new Map(); // child -> recent stderr text
function pipeStderr(name, child) {
  child.stderr.on('data', (d) => {
    const s = d.toString();
    stderrTails.set(child, ((stderrTails.get(child) ?? '') + s).slice(-2000));
    log(`[${name}] (stderr) ${s.trimEnd()}`);
  });
}
function noteExit(name, child, code) {
  // Only an exit we did not cause is a failure worth reporting.
  if (code && !child.__bridgeKilled) {
    const tail = (stderrTails.get(child) ?? '').trim().split(/\r?\n/).filter(Boolean).slice(-3).join(' | ');
    noteFailure(name, `exited code ${code}${tail ? `: ${tail}` : ''}`);
  }
  stderrTails.delete(child);
}

// Terminate a server child and everything it spawned.
//
// On Windows a bare command runs under a cmd.exe wrapper (see spawnServer), and child.kill()
// signals only that wrapper — the real server process survives, keeps its port/token, and is
// reparented. That orphans a process on every recycle, idle reap, session close and shutdown.
// `taskkill /T` takes down the whole tree instead. POSIX spawns the command directly, so
// kill() already targets the server itself.
function killTree(child, sync = false) {
  if (!child) return;
  if (child.__sharedSession) {
    child.detach();
    return;
  }
  // Teardown we initiated. taskkill /F reports exit code 1, so without this every recycle,
  // idle reap and session close would be recorded as a crash.
  child.__bridgeKilled = true;
  const pid = child.pid;
  if (process.platform !== 'win32' || !pid) {
    try { child.kill(); } catch { /* already gone */ }
    return;
  }
  const args = ['/PID', String(pid), '/T', '/F'];
  // Shutdown exits the process immediately, so it can't wait on an async callback.
  if (sync) {
    try { execFileSync('taskkill', args, { stdio: 'ignore' }); } catch { /* already gone */ }
    return;
  }
  execFile('taskkill', args, () => {
    // taskkill exits non-zero when the tree is already gone; kill() is a harmless backstop
    // for the case where taskkill itself is unavailable.
    try { child.kill(); } catch { /* already gone */ }
  });
}

function startChild(name, res) {
  const def = servers[name];
  const sessionId = randomUUID();
  const child = spawnServer(name, def);
  serverMetrics.openedSession(name);
  sessions.set(sessionId, { child, res, name });
  log(`[${name}] session ${sessionId.slice(0, 8)} started (pid ${child.pid ?? '?'})`);

  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const t = line.trim();
    if (!t) return;
    try { JSON.parse(t); } catch { log(`[${name}] (non-json stdout) ${t}`); return; }
    noteSuccess(name); // the classic transport is fire-and-forget, so a reply is the only signal
    try { res.write(`event: message\ndata: ${t}\n\n`); } catch { /* client gone */ }
  });
  pipeStderr(name, child);
  child.on('error', (e) => { noteFailure(name, e.message); log(`[${name}] spawn error: ${e.message}`); });
  child.on('exit', (code) => {
    noteExit(name, child, code);
    log(`[${name}] session ${sessionId.slice(0, 8)} exited (code ${code})`);
    try { res.end(); } catch { /* noop */ }
    sessions.delete(sessionId);
  });
  return sessionId;
}

/* ---------------- stdio servers (Streamable HTTP transport) ------------------ */
// Newer MCP clients speak Streamable HTTP: POST /<name>/mcp for JSON-RPC, GET for a
// server->client SSE stream, DELETE to end. Unlike the SSE transport, one child persists
// ACROSS posts (keyed by Mcp-Session-Id), so we route responses back by JSON-RPC id.
const httpSessions = new Map(); // sessionId -> { child, name, pending, sseRes, lastActivity, clientInfo }
const bridgeReplies = new WeakMap();
function bridgeReply(id, code, message, kind) {
  const reply = { jsonrpc: '2.0', id, error: { code, message } };
  bridgeReplies.set(reply, kind);
  return reply;
}

// How long the bridge waits for an upstream JSON-RPC response. `initialize` is separate
// because it also pays for spawning the server: a cold start that downloads the server on
// first run can take minutes, while a steady-state call that slow is a hang.
const REQUEST_TIMEOUT_MS = parseInt(process.env.MCP_REQUEST_TIMEOUT_MS || '30000', 10);
const INIT_TIMEOUT_MS = parseInt(process.env.MCP_INIT_TIMEOUT_MS || '180000', 10);

// Idle reaper: kill Streamable HTTP children idle longer than MCP_IDLE_TIMEOUT_MS (0 = off).
// On by default. Clients are not obliged to send DELETE, and some never do — one observed
// client opened a session per run and left 241 servers running in an hour. A service that
// stays up for weeks cannot rely on clients tidying up after themselves. Reaping is safe here
// because a reaped session is transparently re-established if that client comes back, so the
// only cost of reaping too eagerly is one server restart.
const IDLE_TIMEOUT_MS = parseInt(process.env.MCP_IDLE_TIMEOUT_MS || String(30 * 60 * 1000), 10);
// Optional per-server concurrency cap (0 = unlimited). Env default; per-server def.maxSessions overrides.
const MAX_SESSIONS_PER_SERVER = parseInt(process.env.MCP_MAX_SESSIONS_PER_SERVER || '0', 10);
// When at the cap, wait this long for a slot before giving up. A cap alone turns a burst into
// failed requests; a short wait absorbs the burst, while still refusing rather than queueing
// without limit. 0 disables waiting and rejects immediately.
const QUEUE_TIMEOUT_MS = parseInt(process.env.MCP_QUEUE_TIMEOUT_MS || '10000', 10);
const sessionCount = (name) => { let n = 0; for (const s of httpSessions.values()) if (s.name === name) n++; return n; };
const startingSessions = new Map();

function reserveSession(name, cap) {
  const starting = startingSessions.get(name) || 0;
  if (sessionCount(name) + starting >= cap) return false;
  startingSessions.set(name, starting + 1);
  return true;
}

function releaseSessionReservation(name) {
  const remaining = (startingSessions.get(name) || 0) - 1;
  if (remaining > 0) startingSessions.set(name, remaining);
  else startingSessions.delete(name);
  slotFreed(name);
}

// Resolve when a session slot is free for `name`, or false if the wait ran out.
const waiters = new Map(); // name -> [resolve, ...]
function slotFreed(name) {
  const q = waiters.get(name);
  if (q &&
      q.length) q[0](true);
}
function awaitSlot(name, cap) {
  if (reserveSession(name, cap)) return Promise.resolve(true);
  if (QUEUE_TIMEOUT_MS <= 0) return Promise.resolve(false);
  return new Promise((res) => {
    if (!waiters.has(name)) waiters.set(name, []);
    const q = waiters.get(name);
    const done = (ok) => {
      if (ok &&
          !reserveSession(name, cap)) return;
      const i = q.indexOf(done);
      if (i >= 0) q.splice(i, 1);
      clearTimeout(timer);
      res(ok);
    };
    const timer = setTimeout(() => done(false), QUEUE_TIMEOUT_MS);
    q.push(done);
  });
}
if (IDLE_TIMEOUT_MS > 0) {
  setInterval(() => {
    const now = Date.now();
    for (const [sid, s] of httpSessions) {
      // A session with a request in flight is working, not idle. `lastActivity` is stamped when
      // a request arrives, so a call that runs longer than the timeout would otherwise have its
      // server killed mid-request and the caller left waiting for a reply that can never come.
      if (s.pending.size > 0) continue;
      if (s.lastActivity && now - s.lastActivity > IDLE_TIMEOUT_MS) {
        log(`[${s.name}] reaping idle session ${sid.slice(0, 8)} (idle ${Math.round((now - s.lastActivity) / 1000)}s)`);
        killTree(s.child);
        httpSessions.delete(sid);
      }
    }
  }, Math.min(IDLE_TIMEOUT_MS, 15000)).unref();
}

function writeSessionMessage(session, message) {
  if (session.child.__sharedSession) {
    session.child.writeMessage(message);
  } else {
    session.child.stdin.write(JSON.stringify(message) + '\n');
  }
}

function writeSharedEvent(session, response, message) {
  if (response.destroyed) return false;
  const frame = `event: message\ndata: ${JSON.stringify(message)}\n\n`;
  if (response.writableLength + Buffer.byteLength(frame) > session.sharedBufferLimit) {
    log(`[${session.name}] shared response stream exceeded its buffer limit`);
    response.destroy();
    return false;
  }
  response.write(frame);
  return true;
}

function startStreamableChild(name, warmChild, forcedSessionId) {
  const def = servers[name];
  const sessionId = forcedSessionId || randomUUID();
  const child = warmChild || spawnServer(name, def);
  serverMetrics.openedSession(name, Boolean(forcedSessionId));
  const session = { child, name, pending: new Map(), sseRes: null, lastActivity: Date.now(), clientInfo: null };
  session.sharedBufferLimit = def.sharedMaxBufferBytes ?? SHARED_DEFAULTS.sharedMaxBufferBytes;
  httpSessions.set(sessionId, session);
  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const t = line.trim();
    if (!t) return;
    let msg;
    try { msg = JSON.parse(t); } catch { log(`[${name}] (non-json stdout) ${t}`); return; }
    if (!msg ||
        typeof msg !== 'object') {
      log(`[${name}] ignored invalid upstream message`);
      return;
    }
    const id = msg.method === undefined ? msg.id : undefined;
    const p = id != null ? session.pending.get(id) : undefined;
    if (p) { session.pending.delete(id); clearTimeout(p.timer); p.resolve(msg); }
    else if (session.sseRes) {
      if (child.__sharedSession) {
        if (msg.method !== undefined) writeSharedEvent(session, session.sseRes, msg);
      } else {
        try { session.sseRes.write(`event: message\ndata: ${t}\n\n`); } catch { /* noop */ }
      }
    }
  });
  if (!warmChild) pipeStderr(name, child);
  if (child.__sharedSession) {
    child.on('sharedFailure', (detail) => { session.sharedFailure = detail; });
    child.on('sharedProgress', ({ requestId, message }) => {
      const pending = session.pending.get(requestId);
      if (!pending?.stream ||
          pending.stream.destroyed) return;
      writeSharedEvent(session, pending.stream, message);
    });
  }
  child.on('error', (e) => { noteFailure(name, e.message); log(`[${name}] spawn error: ${e.message}`); });
  child.on('exit', (code) => {
    if (!child.__sharedSession) noteExit(name, child, code);
    log(`[${name}] streamable session ${sessionId.slice(0, 8)} exited (code ${code})`);
    // A child that dies with requests in flight must fail them now. Nothing did, so the caller
    // waited out the full budget — 180s for an initialize — for an answer that could never come.
    // A config reload recycling a server mid-request hits this exactly, and it surfaced as a
    // three-minute CI hang rather than as the immediate failure it is.
    for (const [id, p] of session.pending) {
      clearTimeout(p.timer);
      const reply = bridgeReply(id, -32000, `bridge: server exited (code ${code}) before answering`, 'exit');
      if (session.sharedFailure) {
        reply.error.data = { ...session.sharedFailure, phase: 'execution', execution: 'potentially-executed' };
      }
      p.resolve(reply);
    }
    session.pending.clear();
    if (session.sseRes) { try { session.sseRes.end(); } catch { /* noop */ } }
    // The same session id may already have been re-established on a fresh child by the time this
    // fires: `taskkill /F /T` takes about a second on Windows, so a reap followed by a resume
    // lands the replacement first. Only drop the mapping if it still points at this child, or a
    // late exit tears down the session that replaced it.
    if (httpSessions.get(sessionId) === session) httpSessions.delete(sessionId);
    slotFreed(name); // a capped server may have a request waiting for this slot
  });
  log(`[${name}] streamable session ${sessionId.slice(0, 8)} ${child.__sharedSession ? 'attached to shared child' : 'started'} (pid ${child.pid ?? '?'})`);
  return sessionId;
}

/* ------------------- cold-start cost, concurrency, spawn gating ------------- */
// The bridge spawns every child, so it is the only component positioned to know what a cold
// start actually costs — and it was discarding that. Without it there is no way to tell a server
// that starts in 200ms from one that shells out to a package manager and takes 20s, which is why
// the pool ended up full for a fast server and empty for the slow one that needed it.
function noteSpawnCost(name, ms) {
  serverMetrics.initialized(name, ms);
}
function spawnStats(name) {
  if (servers[name]?.type === 'http') return null;
  return serverMetrics.snapshot(name);
}

// Rolling peak concurrency, so a pool can be sized from what a server is actually asked to do
// rather than from a number the user had to guess. Bucketed by 5 minutes over the last hour: a
// single burst should still size the pool, but yesterday's burst should not hold it open forever.
const CONCURRENCY_BUCKET_MS = 5 * 60_000;
const CONCURRENCY_BUCKETS = 12;
const concurrency = new Map(); // name -> [{ slot, peak }, ...]
function noteConcurrency(name, n) {
  const slot = Math.floor(Date.now() / CONCURRENCY_BUCKET_MS);
  const arr = concurrency.get(name) || [];
  if (arr[0] && arr[0].slot === slot) arr[0].peak = Math.max(arr[0].peak, n);
  else arr.unshift({ slot, peak: n });
  if (arr.length > CONCURRENCY_BUCKETS) arr.length = CONCURRENCY_BUCKETS;
  concurrency.set(name, arr);
}
const peakConcurrency = (name) => {
  const arr = concurrency.get(name);
  return arr && arr.length ? Math.max(...arr.map((b) => b.peak)) : 0;
};

// Running many package-manager-backed servers at once is how a shared npm/uv cache gets
// corrupted: 17 simultaneous `npx` invocations on one machine produced
// `npm error code ECOMPROMISED / Lock compromised`, and every one of those sessions failed. No
// server definition can fix that — it is a property of the concurrency, not of any one command —
// so the bridge has to own it. Global rather than per-server, because the cache is shared across
// servers.
//
// Two limits on how far this is allowed to go, both learned by getting it wrong:
//
// 1. Only commands that actually go through a package manager are gated. A plain `node server.js`
//    shares no cache and was never at risk, and gating it put a global semaphore in front of every
//    cold start — including a test that opens 60 sessions in a loop, which then took the full
//    180s init budget and failed on CI.
// 2. Waiting for a slot is bounded. If one does not come free in time the spawn proceeds anyway:
//    a corrupted cache is a risk, but hanging a client request is a certainty, and the whole
//    point of this bridge is that a client request does not hang.
const MAX_CONCURRENT_SPAWNS = Number(process.env.MCP_MAX_CONCURRENT_SPAWNS ?? 2);
const SPAWN_GATE_WAIT_MS = Number(process.env.MCP_SPAWN_GATE_WAIT_MS ?? 15_000);
const PACKAGE_RUNNERS = /(^|[\\/])(npx|pnpx|bunx|uvx|pipx|dnx)(\.cmd|\.exe|\.ps1)?$/i;
function usesSharedPackageCache(def) {
  if (!def || !def.command) return false;
  // Explicit wins: a wrapper script that shells out to a package manager is invisible to the
  // heuristic below, and its author is the only one who knows.
  if (typeof def.sharedPackageCache === 'boolean') return def.sharedPackageCache;
  if (PACKAGE_RUNNERS.test(def.command)) return true;
  // `npm exec`, `pnpm dlx`, `yarn dlx`, `uv run` — the runner is the first argument.
  const first = (def.args && def.args[0]) || '';
  return /^(npm|pnpm|yarn|uv|pip)$/i.test(def.command) && /^(exec|dlx|run|x)$/i.test(first);
}

const spawnGate = { active: 0, queue: [] };
// One release per acquisition, idempotent, so a double call cannot inflate the pool and a
// throw between acquire and release cannot strand a slot forever.
function makeRelease() {
  let done = false;
  return () => {
    if (done) return;
    done = true;
    const next = spawnGate.queue.shift();
    if (next) next(); // hand the slot straight over rather than dropping and re-taking it
    else spawnGate.active = Math.max(0, spawnGate.active - 1);
  };
}
const NOOP_RELEASE = () => {};
function acquireSpawn() {
  if (MAX_CONCURRENT_SPAWNS <= 0) return Promise.resolve(NOOP_RELEASE);
  if (spawnGate.active < MAX_CONCURRENT_SPAWNS) {
    spawnGate.active++;
    return Promise.resolve(makeRelease());
  }
  return new Promise((resolve) => {
    let settled = false;
    const waiter = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(makeRelease());
    };
    spawnGate.queue.push(waiter);
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const i = spawnGate.queue.indexOf(waiter);
      if (i >= 0) spawnGate.queue.splice(i, 1);
      resolve(NOOP_RELEASE); // proceed ungated rather than hold the caller any longer
    }, SPAWN_GATE_WAIT_MS);
    timer.unref?.();
  });
}

// Pooling stays opt-in: the bridge says what it would cost and what it would size to, and the
// user decides. Turning it on automatically would spend a resident process per warm slot on
// someone's machine without asking.
const POOL_ADVICE_MS = Number(process.env.MCP_POOL_ADVICE_MS ?? 2000);
const WARM_MAX_PER_SERVER = Number(process.env.MCP_WARM_MAX ?? 8);
function poolAdvice(name) {
  const def = servers[name];
  if (!def ||
      def.sharing === 'pool' ||
      def.sharing === 'shared' ||
      def.type === 'http') {
    return null;
  }
  const st = spawnStats(name);
  const enoughSamples = st && st.samples >= 3;
  if (!enoughSamples ||
      st.p50Ms < POOL_ADVICE_MS) {
    return null;
  }
  return {
    reason: `cold start p50 ${(st.p50Ms / 1000).toFixed(1)}s over ${st.samples} spawns`,
    suggest: { sharing: 'pool', minWarm: Math.max(1, Math.min(peakConcurrency(name) || 1, WARM_MAX_PER_SERVER)) },
  };
}

/* --------------------- keep-warm pool (sharing: "pool") --------------------- */
// For servers marked sharing:"pool", keep `minWarm` pre-spawned (un-initialized) children ready
// so a new session adopts a warm child (process already started + imports loaded) instead of a
// cold spawn. The warm child receives its FIRST initialize from the real client (safe — no
// re-initialize). Shared mode instead retains one initialized child.
const warmPool = new Map(); // name -> [child, ...]
const warmPending = new Map(); // name -> spawns in flight, so a refill pass cannot double-order
// Explicit minWarm always wins. Without one, size from observed peak concurrency — the number a
// user cannot reasonably know and the bridge measures for free. Opting into pooling and still
// getting a pool of one is how a burst of 17 sessions ended up with 16 cold starts.
const poolTarget = (name) => {
  const def = servers[name];
  if (!def ||
      def.sharing !== 'pool') {
    return 0;
  }
  if (def.minWarm != null) return def.minWarm;
  return Math.max(1, Math.min(peakConcurrency(name) || 1, WARM_MAX_PER_SERVER));
};
// Hold a spawn-gate slot until the child looks alive rather than until spawn() returns: the cost
// being serialized is the package manager's, which happens after the process exists and before
// it says anything. First output is the cheapest available proxy for "the expensive part is
// over"; the timeout stops a silent child from wedging the gate.
function releaseOnReady(child, release, maxMs = 30_000) {
  let done = false;
  const rel = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    release();
  };
  const timer = setTimeout(rel, maxMs);
  timer.unref?.();
  child.stdout?.once('data', rel);
  child.stderr?.once('data', rel);
  child.once('exit', rel);
}

const sharedManager = new SharedSessionManager({
  async spawn(name, definition) {
    const release = usesSharedPackageCache(definition) ? await acquireSpawn() : NOOP_RELEASE;
    try {
      if (shuttingDown ||
          sharedManager.inspect(name)?.state !== 'starting') {
        throw sharedManager.error('SHARED_RETIRED', 'spawn', 'unsent');
      }
      const child = spawnServer(name, definition);
      pipeStderr(name, child);
      releaseOnReady(child, release);
      child.once('close', () => stderrTails.delete(child));
      return child;
    } catch (error) {
      release();
      throw error;
    }
  },
  kill: (child) => killTree(child, shuttingDown),
  onFailure: (name, detail) => noteFailure(name, `shared: ${detail.kind}`),
  onInitialized: (name, ms) => { noteSpawnCost(name, ms); noteSuccess(name); },
  onResponse: (name) => noteSuccess(name),
  log: (name, text) => log(`[${name}] ${text}`),
  initTimeoutMs: INIT_TIMEOUT_MS,
  requestTimeoutMs: REQUEST_TIMEOUT_MS,
});
sharedManager.on('draining', ({ name, generation, reason }) => log(`[${name}] shared generation ${generation} draining (${reason})`));
sharedManager.on('retired', ({ name, generation, reason }) => log(`[${name}] shared generation ${generation} retired (${reason})`));

async function startAdmittedSession(name, initializeParams, forcedSessionId, stillWanted) {
  const definition = servers[name];
  if (!definition) throw Object.assign(new Error('server was removed'), { statusCode: 404 });
  const cap = definition.maxSessions ?? MAX_SESSIONS_PER_SERVER;
  if (cap > 0 &&
      !(await awaitSlot(name, cap))) {
    noteFailure(name, `bridge refused a session: max sessions (${cap}) reached`);
    throw Object.assign(new Error(`bridge: max sessions (${cap}) reached for ${name}`), { statusCode: 503 });
  }
  let candidate = null;
  let release = NOOP_RELEASE;
  try {
    if (shuttingDown ||
        servers[name] !== definition) {
      throw Object.assign(new Error('server configuration changed while waiting for capacity; retry'), { statusCode: 409 });
    }
    if (!stillWanted()) return null;
    if (definition.sharing === 'shared') {
      candidate = await sharedManager.acquire(name, definition, initializeParams);
    } else {
      candidate = takeWarm(name);
      if (!candidate &&
          usesSharedPackageCache(definition)) release = await acquireSpawn();
    }
    if (shuttingDown ||
        servers[name] !== definition) {
      if (candidate) killTree(candidate);
      throw Object.assign(new Error('server configuration changed while starting; retry'), { statusCode: 409 });
    }
    if (!stillWanted()) {
      if (candidate) killTree(candidate);
      return null;
    }
    const id = startStreamableChild(name, candidate, forcedSessionId);
    const session = httpSessions.get(id);
    session.cold = !candidate;
    releaseOnReady(session.child, release);
    release = NOOP_RELEASE;
    noteConcurrency(name, sessionCount(name));
    return { id, session };
  } finally {
    release();
    if (cap > 0) releaseSessionReservation(name);
  }
}
// A warm child can die on its own: a server that self-exits when idle, a crash, a laptop sleep.
// The exit handler used to remove the corpse and stop there, and nothing else refilled — the pool
// only grew on boot, on take, on recycle and on reload. So a pooled server silently degraded to
// cold-start-every-session, which is the exact failure pooling exists to prevent, and it looked
// like nothing was wrong because an empty pool is indistinguishable from one that has simply not
// been asked for anything yet. Seen on ev2: warm sat at 0 for three hours while kusto stayed full
// purely because kusto is taken often enough that every take triggered a refill.
//
// Refilling on an unattended exit needs a brake, or a child that dies instantly becomes a spawn
// loop. Children that die quickly back off exponentially; one that lived a while refills at once.
const WARM_MIN_LIFETIME_MS = 5000;
const WARM_BACKOFF_CAP_MS = 60_000;
const warmFastExits = new Map(); // name -> consecutive too-fast exits
let shuttingDown = false;
function spawnWarm(name) {
  const child = spawnServer(name, servers[name]);
  const bornAt = Date.now();
  pipeStderr(name, child);
  child.on('exit', (code) => {
    // Once taken, the child belongs to its session, which registers its own exit handler. Both
    // used to run, so every failing child of a pooled server was counted as two failures and
    // drove that server's health down twice as fast as an identical unpooled one.
    if (child.__warmTaken) return;
    noteExit(name, child, code);
    const arr = warmPool.get(name); if (arr) { const i = arr.indexOf(child); if (i >= 0) arr.splice(i, 1); }
    // Deliberate kills refill themselves (recycle) or are meant to leave the pool empty (reload
    // removing a server, shutdown). Only an exit we did not ask for needs replacing here.
    const weAskedForThis = child.__bridgeKilled || shuttingDown;
    if (weAskedForThis ||
        !poolTarget(name)) {
      return;
    }
    const lived = Date.now() - bornAt;
    const fast = lived < WARM_MIN_LIFETIME_MS;
    const strikes = fast ? (warmFastExits.get(name) || 0) + 1 : 0;
    warmFastExits.set(name, strikes);
    const delay = strikes ? Math.min(WARM_BACKOFF_CAP_MS, 1000 * 2 ** (strikes - 1)) : 0;
    log(`[${name}] warm child exited after ${lived}ms (code ${code})${strikes ? `; ${strikes} fast exits, refilling in ${delay}ms` : '; refilling'}`);
    setTimeout(() => refillPool(name), delay).unref();
  });
  return child;
}
function refillPool(name) {
  const target = poolTarget(name);
  if (!target ||
      shuttingDown) {
    return;
  }
  if (!warmPool.has(name)) warmPool.set(name, []);
  const arr = warmPool.get(name);
  // Refill toward the target in one pass instead of one child per take. Reactive single-child
  // refill meant a burst that emptied the pool recovered long after the burst was over, which is
  // the window pooling exists to cover. The spawn gate decides how many actually start at once.
  while (arr.length + (warmPending.get(name) || 0) < target) {
    warmPending.set(name, (warmPending.get(name) || 0) + 1);
    const gated = usesSharedPackageCache(servers[name]);
    const slot = gated ? acquireSpawn() : Promise.resolve(NOOP_RELEASE);
    slot.then((release) => {
      warmPending.set(name, Math.max(0, (warmPending.get(name) || 1) - 1));
      const want = poolTarget(name);
      const cur = warmPool.get(name);
      // The wait for a slot can be long enough for the answer to change: a reload removed the
      // server, a shutdown started, or other refills already met the target.
      const noLongerWanted = shuttingDown || !want || !cur;
      const alreadyMet = cur && cur.length >= want;
      if (noLongerWanted ||
          alreadyMet) {
        release();
        return;
      }
      const child = spawnWarm(name);
      cur.push(child);
      log(`[${name}] pre-warmed pool child (${cur.length}/${want})`);
      releaseOnReady(child, release);
    });
  }
}
function takeWarm(name) {
  const arr = warmPool.get(name);
  if (arr && arr.length) {
    const c = arr.shift();
    serverMetrics.adoptedWarmChild(name);
    c.__warmTaken = true; // hand ownership to the session; the warm exit handler stands down
    warmFastExits.delete(name); // a child that survived to be used clears the backoff
    setImmediate(() => refillPool(name));
    return c;
  }
  return null;
}
for (const poolName of Object.keys(servers)) refillPool(poolName); // pre-warm pool servers at boot

/* --------------------- resumable sessions (survive a restart) --------------- */
// Streamable HTTP session ids live only in memory, so restarting the bridge — or recycling a
// server — made every live client session 404. The spec says a client should then re-initialize,
// but in practice clients surface the failure instead, which is exactly the outage this project
// exists to prevent: a keep-alive service must survive its own restart.
//
// The client's initialize request is recorded, so an id this process has never seen can still be
// re-established: spawn the server, replay that initialize, then serve the request that arrived.
// Only the handshake is replayed. Any state the server accumulated is genuinely gone, so this
// restores the session, not its history.
const RESUME_ENABLED = process.env.MCP_RESUME !== '0';
const RESUME_TTL_MS = parseInt(process.env.MCP_RESUME_TTL_MS || String(24 * 60 * 60 * 1000), 10);
const RESUME_FILE = resolve(dirname(CONFIG), 'sessions.json');
const resumable = new Map(); // sessionId -> { server, initialize, at }
const resuming = new Map(); // sessionId -> handshake promise, before any asynchronous admission

function saveResumable() {
  if (!RESUME_ENABLED) return;
  try { writeFileSync(RESUME_FILE, JSON.stringify(Object.fromEntries(resumable))); } catch { /* best effort */ }
}
// Records past the TTL are dropped. Without this the window was only ever applied when the file
// was loaded at startup, so a long-running bridge kept honouring — and re-persisting — records
// far older than the retention window it documents. Returns true if anything was removed.
// Session ids we know existed and can no longer honour. Every released revision that has
// sessions (2025-03-26 through 2025-11-25, Streamable HTTP / Session Management §3) requires 404
// for a terminated session, and §4 makes re-initializing on 404 a client MUST — so the status
// code stays 404. A 410 would read better to a human but would put a compliant client into
// undefined territory and lose the one recovery path the spec defines. (The draft revision drops
// sessions from this transport altogether, so 404 is also the last word on the subject.)
// We keep the set purely to tell "known-gone" from "never existed" in the log, which is what
// actually distinguishes a stale client after a restart from a misconfigured one.
const GONE_MAX = 500;
const goneSessions = new Set();
function markGone(sessionId) {
  goneSessions.add(sessionId);
  if (goneSessions.size > GONE_MAX) goneSessions.delete(goneSessions.values().next().value);
}

function pruneResumable(now = Date.now()) {
  let dropped = false;
  for (const [id, r] of resumable) {
    if (now - (r.at || 0) >= RESUME_TTL_MS) { resumable.delete(id); markGone(id); dropped = true; }
  }
  return dropped;
}
function rememberSession(sessionId, name, initMsg) {
  if (!RESUME_ENABLED || !initMsg) return;
  resumable.set(sessionId, { server: name, initialize: initMsg.params ?? {}, at: Date.now() });
  goneSessions.delete(sessionId); // a live id again
  pruneResumable();
  saveResumable();
}
function forgetSession(sessionId) {
  if (resumable.delete(sessionId)) saveResumable();
  markGone(sessionId); // an explicit DELETE is gone for good, not "never existed"
}
if (RESUME_ENABLED) {
  try {
    const raw = JSON.parse(readFileSync(RESUME_FILE, 'utf8'));
    const now = Date.now();
    for (const [id, r] of Object.entries(raw)) {
      // Drop records for servers that no longer exist, and anything past the TTL.
      if (r && r.server && servers[r.server] && now - (r.at || 0) < RESUME_TTL_MS) resumable.set(id, r);
    }
    if (resumable.size) log(`${resumable.size} session(s) resumable after restart`);
  } catch { /* no prior state */ }
}

// Re-establish a session the client still believes in.
async function resumeSession(name, sessionId) {
  const rec = resumable.get(sessionId);
  if (!rec || rec.server !== name) return null;
  if (resuming.has(sessionId)) return resuming.get(sessionId);
  // The retention window is a promise about how long a session id stays valid, so it has to be
  // checked here too — not only when the file is read at startup.
  if (Date.now() - (rec.at || 0) >= RESUME_TTL_MS) {
    resumable.delete(sessionId);
    markGone(sessionId);
    saveResumable();
    return null;
  }
  const pending = restoreSession(name, sessionId, rec);
  resuming.set(sessionId, pending);
  try {
    return await pending;
  } finally {
    if (resuming.get(sessionId) === pending) resuming.delete(sessionId);
  }
}

async function restoreSession(name, sessionId, rec) {
  const stillWanted = () => resumable.get(sessionId) === rec && !goneSessions.has(sessionId);
  const restored = await startAdmittedSession(name, rec.initialize, sessionId, stillWanted);
  if (!restored) return null;
  const { session } = restored;
  const initId = `bridge-resume-${randomUUID()}`;
  const reply = await new Promise((resolveWait) => {
    const timer = setTimeout(() => { session.pending.delete(initId); resolveWait(null); }, INIT_TIMEOUT_MS);
    session.pending.set(initId, { resolve: resolveWait, timer });
    try {
      writeSessionMessage(session, { jsonrpc: '2.0', id: initId, method: 'initialize', params: rec.initialize });
    } catch { clearTimeout(timer); session.pending.delete(initId); resolveWait(null); }
  });
  if (!reply ||
      reply.error ||
      !stillWanted()) {
    killTree(session.child);
    if (httpSessions.get(sessionId) === session) httpSessions.delete(sessionId);
    slotFreed(name);
    log(`[${name}] could not resume session ${sessionId.slice(0, 8)}`);
    if (!stillWanted()) return null;
    throw Object.assign(new Error('bridge: session initialization failed'), { upstreamError: reply?.error, statusCode: 502 });
  }
  writeSessionMessage(session, { jsonrpc: '2.0', method: 'notifications/initialized' });
  session.clientInfo = rec.initialize.clientInfo ?? null;
  session.protocolVersion = reply.result.protocolVersion;
  if (session.cold) {
    noteSpawnCost(name, Date.now() - session.child.__spawnedAt);
    session.cold = false;
  }
  rec.at = Date.now();
  saveResumable();
  log(`[${name}] resumed session ${sessionId.slice(0, 8)}`);
  return session;
}

/* ------------------------------ scheduled recycle --------------------------- */
// Some servers hold a credential they can only refresh interactively, so they have to be
// restarted periodically. Now that an unknown session id is transparently re-established, a
// recycle is invisible to connected clients, so the bridge can do it itself rather than needing
// anything driving it from inside an editor. Per-server `recycleMinutes`, or MCP_RECYCLE_MINUTES
// for all.
const RECYCLE_MINUTES = parseFloat(process.env.MCP_RECYCLE_MINUTES || '0');
const recycleMinutesFor = (name) => (servers[name] && servers[name].recycleMinutes) || RECYCLE_MINUTES;
const lastRecycle = new Map();

function recycleServer(name) {
  let killed = 0;
  // A session with a request in flight is left alone, the same rule the idle reaper already
  // follows: killing the child underneath a caller means it waits for a reply that can never
  // arrive. Its credential is replaced on the next request instead, which is a moment later.
  const busy = (s) => s.pending && s.pending.size > 0;
  for (const s of sessions.values()) if ((!name || s.name === name) && !busy(s)) { killTree(s.child); killed++; }
  for (const s of httpSessions.values()) {
    if ((!name || s.name === name) &&
        !s.child.__sharedSession &&
        !busy(s)) { killTree(s.child); killed++; }
  }
  // Warm children hold the same stale credential, so they have to go too, or a recycled server
  // is immediately replaced by a pre-spawned copy of what was just discarded.
  for (const n of (name ? [name] : Object.keys(servers))) {
    if (sharedManager.recycle(n).found) killed++;
    for (const c of (warmPool.get(n) || []).slice()) killTree(c);
    setTimeout(() => refillPool(n), 1000).unref();
  }
  return killed;
}

// The tick adapts to the shortest configured period, so it has to be rebuilt whenever the config
// changes: a reload can introduce the first `recycleMinutes` on a bridge that had none, or
// shorten the interval below the current tick.
let recycleTimer = null;
function ensureRecycleTimer() {
  const periods = Object.keys(servers).map(recycleMinutesFor).filter((m) => m > 0);
  if (recycleTimer) { clearInterval(recycleTimer); recycleTimer = null; }
  if (!periods.length) return;
  // Check often enough to honour the shortest configured period, but never busier than needed.
  const tick = Math.max(200, Math.min(30_000, (Math.min(...periods) * 60_000) / 2));
  recycleTimer = setInterval(() => {
    const now = Date.now();
    for (const name of Object.keys(servers)) {
      const mins = recycleMinutesFor(name);
      if (!mins) continue;
      const last = lastRecycle.get(name) || startedAt;
      if (now - last < mins * 60_000) continue;
      const killed = recycleServer(name);
      lastRecycle.set(name, now);
      log(`[${name}] scheduled recycle after ${mins}m (${killed} session(s))`);
    }
  }, tick);
  recycleTimer.unref();
}
ensureRecycleTimer();

/* ------------------------------- config reload ------------------------------ */
// Apply an edited servers.json without restarting.
//
// A restart is the blunt alternative, and it costs every live session on every server — adding
// one server should not disturb the fourteen that were working. So the reload is a diff: servers
// whose definition is unchanged are left completely alone, and only the ones that actually
// changed are torn down so the next request picks up the new definition.
//
// `servers` is mutated in place rather than rebound, because the rest of the bridge closes over
// that object; rebinding it would leave timers and handlers reading the old config forever.
function diffConfig(next) {
  const before = Object.keys(servers);
  const after = Object.keys(next);
  return {
    added: after.filter((n) => !before.includes(n)),
    removed: before.filter((n) => !after.includes(n)),
    changed: after.filter((n) => before.includes(n) && JSON.stringify(servers[n]) !== JSON.stringify(next[n])),
  };
}

function applyConfig(next) {
  const { added, removed, changed } = diffConfig(next);
  let restarted = 0;
  // A changed or removed server's children were started from the old definition, so they are
  // stale. Untouched servers are deliberately not disturbed.
  for (const name of [...removed, ...changed]) {
    if (next[name] &&
        onlyPoolingPolicyChanged(servers[name], next[name])) {
      continue;
    }
    invalidateToken(servers[name]);
    restarted += recycleServer(name);
  }
  for (const name of removed) {
    sharedManager.remove(name);
    delete servers[name];
    warmPool.delete(name); // recycleServer queued a refill; it must not resurrect a deleted server
  }
  for (const name of [...added, ...changed]) servers[name] = next[name];
  for (const name of [...added, ...changed]) {
    const pool = warmPool.get(name);
    const target = poolTarget(name);
    while (pool &&
           pool.length > 0 &&
           pool.length > target) {
      killTree(pool.pop());
    }
    refillPool(name);
  }
  ensureRecycleTimer(); // a reload can add the first recycleMinutes, or shorten the interval
  return { added, removed, changed, restarted };
}

function onlyPoolingPolicyChanged(before, after) {
  if (before.sharing === 'shared' ||
      after.sharing === 'shared') {
    return false;
  }
  const withoutPolicy = ({ sharing, minWarm, ...rest }) => rest;
  return JSON.stringify(withoutPolicy(before)) === JSON.stringify(withoutPolicy(after));
}

let lastConfigText = (() => { try { return readFileSync(CONFIG, 'utf8'); } catch { return null; } })();

function reloadConfig(reason) {
  let text;
  try { text = readFileSync(CONFIG, 'utf8'); }
  catch (e) { return { ok: false, error: `cannot read ${CONFIG}: ${e.message}` }; }
  if (text === lastConfigText) return { ok: true, unchanged: true, added: [], removed: [], changed: [], restarted: 0 };

  // An invalid file must never take working servers down — a half-written save from an editor
  // looks exactly like this. Keep serving what is already in memory and report the problem.
  let next;
  try { next = JSON.parse(text); }
  catch (e) { log(`config reload rejected: invalid JSON (${e.message})`); return { ok: false, error: `invalid JSON: ${e.message}` }; }
  if (!next || typeof next !== 'object' || Array.isArray(next)) {
    log('config reload rejected: top level must be an object of server definitions');
    return { ok: false, error: 'top level must be an object of server definitions' };
  }
  for (const [n, d] of Object.entries(next)) {
    if (!d || typeof d !== 'object' || (!d.command && !d.url)) {
      log(`config reload rejected: "${n}" has neither "command" nor "url"`);
      return { ok: false, error: `server "${n}" has neither "command" nor "url"` };
    }
  }

  lastConfigText = text;
  const r = applyConfig(next);
  const summary = [
    r.added.length ? `+${r.added.join(', ')}` : null,
    r.removed.length ? `-${r.removed.join(', ')}` : null,
    r.changed.length ? `~${r.changed.join(', ')}` : null,
  ].filter(Boolean).join('  ');
  log(summary
    ? `config reloaded (${reason}): ${summary} — ${r.restarted} session(s) restarted`
    : `config reloaded (${reason}): no server definitions changed`);
  return { ok: true, ...r };
}

// Watching the file makes an edit take effect on its own, which is the point: the config exists
// to be edited. Debounced because editors save in bursts (write, rename, truncate), and re-armed
// after each burst because an atomic save replaces the inode the watcher was holding.
if (process.env.MCP_CONFIG_WATCH !== '0') {
  let timer = null;
  let watcher = null;
  const arm = () => {
    try {
      watcher = watch(CONFIG, () => {
        clearTimeout(timer);
        timer = setTimeout(() => { reloadConfig('file changed'); rearm(); }, 300);
      });
      watcher.unref?.();
    } catch { /* watching is best effort; /admin/reload still works */ }
  };
  const rearm = () => { try { watcher?.close(); } catch { /* noop */ } arm(); };
  arm();
}

/* --------------------------- active health probing -------------------------- */
// Passive health above only learns anything when somebody makes a request. A server nobody has
// called today therefore reads 'unknown' indefinitely — which is honest, but it also means a
// credential can expire overnight and you find out from a failed tool call rather than the
// dashboard. Probing closes that gap for HTTP servers, where the failure is a silent 401.
//
// Off by default: a probe is a real request to somebody else's service, and how often that is
// acceptable is not the bridge's call to make. stdio servers are not probed — a probe would mean
// spawning a process, which costs more than the request it is meant to pre-empt, and their
// failures (spawn error, non-zero exit) are already observed for free.
const HEALTH_INTERVAL_MS = Number(process.env.MCP_HEALTH_INTERVAL_MS || 0);

function probeServer(name) {
  const def = servers[name];
  if (!def || def.type !== 'http' || !def.url) return;
  // A server the client authenticates cannot be probed usefully: the bridge holds no credential
  // for it, so every probe would 401 and report a working server as broken.
  if (!resolveAuth(def) && !def.headers) return;
  stat(name).lastProbe = Date.now();
  const body = JSON.stringify({
    jsonrpc: '2.0', id: `probe-${Date.now()}`, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-pacemaker-health', version: VERSION } },
  });
  (async () => {
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'content-length': Buffer.byteLength(body) };
    const a = resolveAuth(def);
    if (a) headers[a.header.toLowerCase()] = await a.getValue();
    for (const [k, v] of Object.entries(def.headers ?? {})) headers[k] = v;
    const target = new URL(def.url);
    const lib = target.protocol === 'https:' ? https : http;
    return new Promise((done) => {
      const r = lib.request(target, { method: 'POST', headers }, (resp) => {
        const code = resp.statusCode ?? 502;
        resp.resume();
        if (code === 401 || code === 403 || code >= 500) noteFailure(name, `health probe: upstream returned ${code}`);
        else noteSuccess(name);
        done();      });
      r.on('error', (e) => { noteFailure(name, `health probe: ${e.message}`); done(); });
      r.setTimeout(10_000, () => { r.destroy(new Error('timed out')); });
      r.end(body);
    });
  })().catch((e) => noteFailure(name, `health probe: ${e.message}`));
}

if (HEALTH_INTERVAL_MS > 0) {
  const tick = Math.max(1000, Math.min(HEALTH_INTERVAL_MS, 60_000));
  setInterval(() => {
    const now = Date.now();
    for (const name of Object.keys(servers)) {
      const def = servers[name];
      if (def.type !== 'http') continue;
      // A per-server interval of 0 opts one server out of an otherwise global schedule.
      const every = def.healthIntervalMinutes != null ? def.healthIntervalMinutes * 60_000 : HEALTH_INTERVAL_MS;
      if (!every) continue;
      const s = stat(name);
      // A server that just served a real request has already proven itself; probing it as well
      // is pure extra load on the upstream.
      if (now - Math.max(s.lastProbe, s.lastSuccess, s.lastErrorAt) < every) continue;
      probeServer(name);
    }
  }, tick).unref();
  log(`health probing every ${Math.round(HEALTH_INTERVAL_MS / 1000)}s (http servers only)`);
}

/* --------------------------- proactive token refresh ------------------------ */
// Renew a cached credential shortly before it expires instead of discovering the expiry on a
// request. A bridge that stays up for days would otherwise sit on a dead token until the next
// call, which then pays the mint cost or fails outright.
const TOKEN_REFRESH_LEAD_MS = parseInt(process.env.MCP_TOKEN_REFRESH_LEAD_MS || String(5 * 60 * 1000), 10);
if (TOKEN_REFRESH_LEAD_MS > 0) {
  // Check often enough to act inside the lead window, but no busier than that requires.
  const tick = Math.max(500, Math.min(60_000, TOKEN_REFRESH_LEAD_MS / 2));
  setInterval(() => {
    const now = Date.now();
    for (const [name, def] of Object.entries(servers)) {
      const key = authCacheKey(def);
      if (!key) continue;
      const cached = tokenCache.get(key);
      // Only refresh credentials already in use; never mint for a server nobody has touched.
      if (!cached || cached.exp - now > TOKEN_REFRESH_LEAD_MS) continue;
      tokenCache.delete(key);
      const auth = resolveAuth(def);
      if (!auth) continue;
      auth.getValue()
        .then(() => log(`[${name}] refreshed credential ahead of expiry`))
        .catch((e) => { noteFailure(name, `token refresh failed: ${e.message}`); log(`[${name}] token refresh failed: ${e.message}`); });
    }
  }, tick).unref();
}

function handleStreamable(name, req, res) {
  const sid = req.headers['mcp-session-id'];
  const boundName = httpSessions.get(sid)?.name ?? resumable.get(sid)?.server;
  if (boundName &&
      boundName !== name) {
    res.writeHead(404).end('no such session');
    return;
  }

  if (req.method === 'GET') {
    const session = sid ? httpSessions.get(sid) : null;
    if (!session) { res.writeHead(404).end('no such session'); return; }
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' });
    session.sseRes = res;
    const ka = setInterval(() => { try { res.write(': keepalive\n\n'); } catch { /* noop */ } }, 15000);
    req.on('close', () => { clearInterval(ka); if (session.sseRes === res) session.sseRes = null; });
    return;
  }

  if (req.method === 'DELETE') {
    const session = sid ? httpSessions.get(sid) : null;
    if (session) { killTree(session.child); httpSessions.delete(sid); slotFreed(name); }
    // An explicit DELETE ends the session for good; it must not come back on the next request.
    if (sid) forgetSession(sid);
    res.writeHead(204).end();
    return;
  }

  if (req.method === 'POST') {
    const definition = servers[name];
    const chunks = [];
    let bytes = 0;
    let tooLarge = false;
    const shared = servers[name].sharing === 'shared';
    const configuredLimit = servers[name].sharedMaxLineBytes;
    const validLimit = Number.isSafeInteger(configuredLimit) && configuredLimit > 0;
    const bodyLimit = shared ? Math.min(validLimit ? configuredLimit : SHARED_DEFAULTS.sharedMaxLineBytes, 16_777_216) : Infinity;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      bytes += chunk.length;
      if (bytes > bodyLimit) {
        tooLarge = true;
        chunks.length = 0;
        res.writeHead(413).end('shared request exceeds the input limit');
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', async () => {
      if (tooLarge ||
          res.destroyed) return;
      if (servers[name] !== definition) {
        res.writeHead(409).end('server configuration changed while receiving request; retry');
        return;
      }
      let parsed;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString() || 'null'); } catch { res.writeHead(400).end('invalid json'); return; }
      const messages = Array.isArray(parsed) ? parsed : (parsed == null ? [] : [parsed]);
      const isInit = messages.some((m) => m && m.method === 'initialize');
      const initMessage = messages.find((m) => m && m.method === 'initialize');
      if (shared) {
        const invalidMessage = messages.some((message) => !message ||
          typeof message !== 'object' || Array.isArray(message) ||
          message.jsonrpc !== '2.0' || typeof message.method !== 'string' ||
          (Object.hasOwn(message, 'id') && !sharedManager.validId(message.id)));
        const invalidInitialize = isInit && (Array.isArray(parsed) || messages.length !== 1 || !Object.hasOwn(initMessage, 'id'));
        if (!messages.length ||
            invalidMessage ||
            invalidInitialize) {
          res.writeHead(400).end('invalid shared JSON-RPC request');
          return;
        }
      }
      try {
        let sessionId = sid;
        let session = sid ? httpSessions.get(sid) : null;
        if (sid &&
            (!session || resuming.has(sid))) {
          // An id this process has not seen: it may predate a restart or a recycle.
          session = await resumeSession(name, sid);
          if (session) sessionId = sid;
        }
        if (!session) {
          if (!isInit) {
            // Both cases are 404 because the spec requires it, but they mean different things to
            // an operator: a known-gone id is a client that outlived a restart, an unknown id is a
            // client that never initialized here. Say which in the body and the log.
            if (sid &&
                goneSessions.has(sid)) {
              log(`${name}: rejecting known-gone session ${sid} (client predates a restart; it must re-initialize)`);
              res.writeHead(404).end('session terminated (re-initialize)');
              return;
            }
            res.writeHead(404).end('no session (send initialize first)');
            return;
          }
          const started = await startAdmittedSession(name, initMessage.params, undefined, () => !res.destroyed);
          if (!started) return;
          ({ id: sessionId, session } = started);
        }
        session.lastActivity = Date.now();
        if (session.child.__sharedSession) {
          const wrongVersion = !isInit && req.headers['mcp-protocol-version'] &&
            req.headers['mcp-protocol-version'] !== session.protocolVersion;
          const unsupportedBatch = Array.isArray(parsed) && session.protocolVersion !== '2025-03-26';
          if (wrongVersion ||
              unsupportedBatch) {
            res.writeHead(400).end('request does not match the negotiated shared protocol version');
            return;
          }
        }
        if (isInit) {
          const im = messages.find((m) => m && m.method === 'initialize');
          const ci = im && im.params && im.params.clientInfo;
          if (ci) session.clientInfo = { name: ci.name, version: ci.version };
        }
        const requestIds = messages.filter((m) => m && m.id != null && m.method).map((m) => m.id);
        if (new Set(requestIds).size !== requestIds.length ||
            requestIds.some((id) => session.pending.has(id))) {
          res.writeHead(400).end('duplicate pending JSON-RPC request id');
          return;
        }
        const headers = { 'Mcp-Session-Id': sessionId };
        const hasProgress = messages.some((message) => message?.params?._meta &&
          Object.hasOwn(message.params._meta, 'progressToken'));
        const stream = session.child.__sharedSession && requestIds.length > 0 && hasProgress;
        const arrayResponse = requestIds.length > 1 || (session.child.__sharedSession && Array.isArray(parsed));
        let resultBytes = arrayResponse ? 1 : 0;
        let responseOverflow = false;
        const collect = (resolveWait, reply) => {
          if (responseOverflow) { resolveWait(null); return; }
          if (session.child.__sharedSession) {
            try {
              resultBytes += Buffer.byteLength(JSON.stringify(reply)) + (arrayResponse ? 1 : 0);
            } catch (error) {
              if (!(error instanceof RangeError)) throw error;
              resultBytes = Infinity;
            }
            if (resultBytes > session.sharedBufferLimit) {
              responseOverflow = true;
              noteFailure(name, 'shared response exceeds the output limit');
              if (res.headersSent) res.destroy();
              else res.writeHead(502, { 'Content-Type': 'application/json' }).end(JSON.stringify({
                error: {
                  code: -32002, message: 'shared response exceeds the output limit; calls were not replayed',
                  data: { execution: 'potentially-executed' },
                },
              }));
              for (const id of requestIds) {
                const pending = session.pending.get(id);
                if (!pending) continue;
                clearTimeout(pending.timer);
                session.pending.delete(id);
                pending.resolve(null);
                if (session.child.stdin.writable) {
                  writeSessionMessage(session, {
                    jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id },
                  });
                }
              }
              resolveWait(null);
              return;
            }
          }
          resolveWait(reply);
        };
        if (stream) {
          res.writeHead(200, { ...headers, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform' });
          res.flushHeaders();
        }
        // initialize is the request that pays for spawning the server, and a cold start can be
        // slow (a package manager fetching the server on first run), so it gets a longer budget
        // than steady-state calls.
        const budget = isInit ? INIT_TIMEOUT_MS : REQUEST_TIMEOUT_MS;
        const waits = requestIds.map((id) => new Promise((resolveWait) => {
          const timer = setTimeout(() => {
            if (session.pending.has(id)) {
              session.pending.delete(id);
              resolveWait(bridgeReply(id, -32001, 'bridge: upstream timeout', 'timeout'));
            }
          }, budget);
          if (session.child.__sharedSession) clearTimeout(timer);
          session.pending.set(id, { resolve: (reply) => collect(resolveWait, reply), timer, stream: stream ? res : null });
        }));
        try {
          for (const message of messages) {
            if (responseOverflow) break;
            writeSessionMessage(session, message);
          }
        }
        catch (error) {
          for (const id of requestIds) {
            const pending = session.pending.get(id);
            if (!pending) continue;
            clearTimeout(pending.timer);
            session.pending.delete(id);
            pending.resolve(bridgeReply(id, -32000, 'bridge: upstream write failed', 'write'));
          }
          throw error;
        }
        if (!requestIds.length) { res.writeHead(202, headers).end(); return; }
        const results = await Promise.all(waits);
        if (responseOverflow) return;
        // A JSON-RPC error from the server is the server working — it answered. Only the bridge's
        // own synthetic errors mean the server is unhealthy, and even then a timeout is worth
        // recording only while the child is alive: if it already exited, its exit code and stderr
        // are the actual reason and must not be overwritten by the symptom.
        if (results.some((reply) => bridgeReplies.get(reply) === 'timeout')) {
          if (session.child.exitCode === null &&
              session.child.signalCode === null) noteFailure(name, 'upstream timeout');
        } else if (results.some((reply) => bridgeReplies.get(reply) === 'exit')) {
          // The child exited mid-request. Its exit handler already recorded the real reason with
          // the stderr tail, so counting it again here would report one dead child as two failures.
        } else if (!session.child.__sharedSession) {
          noteSuccess(name);
          // A cold start is only measurable once the server has answered: spawn() returning tells
          // us nothing about the package manager work that follows it. Recorded once per child.
          const initialized = results.some((reply) => reply.result &&
            messages.some((message) => message && message.method === 'initialize' && message.id === reply.id));
          const measurableColdStart = session.cold && initialized && session.child.__spawnedAt;
          if (measurableColdStart) {
            noteSpawnCost(name, Date.now() - session.child.__spawnedAt);
            session.cold = false;
          }
        }
        const initialized = isInit && results.some((reply) => reply?.result && reply.id === initMessage.id);
        if (initialized) {
          session.protocolVersion = results.find((reply) => reply.id === initMessage.id).result.protocolVersion;
          rememberSession(sessionId, name, initMessage);
        }
        // Stamp again on completion: the idle clock should measure time since the request finished,
        // not since it started, or a call slower than the timeout is reapable the moment it returns.
        session.lastActivity = Date.now();
        if (stream) {
          for (const result of results) {
            if (!writeSharedEvent(session, res, result)) return;
          }
          res.end();
        } else {
          headers['Content-Type'] = 'application/json';
          res.writeHead(200, headers);
          res.end(JSON.stringify(arrayResponse ? results : results[0]));
        }
      } catch (error) {
        log(`[${name}] session request failed: ${error.message}`);
        if (res.headersSent) { res.destroy(); return; }
        const rpcError = error.upstreamError ?? (error.data
          ? { code: -32002, message: error.message, data: error.data } : null);
        if (rpcError) {
          const request = messages.find((message) => message?.id != null);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: request?.id ?? null, error: rpcError }));
        } else {
          res.writeHead(error.statusCode ?? 502).end(error.message);
        }
      }
    });
    return;
  }

  res.writeHead(405).end('method not allowed');
}

/* ---------------------- http servers (reverse proxy + auth) ----------------- */
// OAuth discovery for proxied servers.
//
// A client authenticating against http://127.0.0.1:<port>/<name> derives the metadata URL from
// the bridge's own origin — /.well-known/oauth-protected-resource/<name> — not from the upstream
// it is eventually talking to. Without an answer here the client fails at "could not discover
// authorization server metadata" and can never reach the real login.
//
// The upstream document is relayed with one change, made in `handleWellKnown` below: `resource`
// is rewritten to this bridge's URL. RFC 9728 requires the client to check that field against
// the resource it is actually addressing, so the upstream's own identifier is rejected. The
// authorization server and scopes are relayed untouched, and those are what determine the
// audience of the issued token, so it stays valid for the upstream behind this bridge.
// Hop-by-hop headers are connection-scoped and must not cross a proxy (RFC 9110 §7.6.1).
// Relaying them leaks connection-scoped state to the client: a header the upstream named in its
// own `Connection` header, or a `trailer` it announced, is meaningful only on that hop and is
// misleading or invalid on the next one.
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);
function stripHopByHop(headers) {
  const out = {};
  // Anything named in `Connection` is also hop-by-hop for this message.
  const listed = String(headers.connection ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key) || listed.includes(key)) continue;
    out[k] = v;
  }
  return out;
}

// The upstream document is relayed with one change: `resource` is rewritten to this bridge's URL
// for the server. RFC 9728 requires the client to check that field against the resource it is
// actually addressing; left as the upstream's own identifier, the client rejects the document and
// reports that discovery failed. The authorization server and scopes are untouched, and those
// determine the audience of the issued token, so it stays valid for the upstream behind this
// bridge.
function handleWellKnown(url, req, res) {
  const m = url.pathname.match(/^\/\.well-known\/([^/]+)\/(.+)$/);
  if (!m) return false;
  const [, metadata, rest] = m;
  const name = rest.split('/')[0];
  const def = servers[name];
  if (!def || def.type !== 'http') return false;

  const upstream = new URL(def.url);
  const target = new URL(`/.well-known/${metadata}${upstream.pathname}`, upstream.origin);
  const lib = target.protocol === 'https:' ? https : http;
  const headers = stripHopByHop(req.headers);
  delete headers.host;
  delete headers['content-length'];
  delete headers['accept-encoding']; // keep the body readable so `resource` can be rewritten
  const upReq = lib.request(target, { method: 'GET', headers }, (upRes) => {
    const chunks = [];
    upRes.on('data', (c) => chunks.push(c));
    upRes.on('end', () => {
      const outHeaders = stripHopByHop(upRes.headers);
      let body = Buffer.concat(chunks);
      try {
        const doc = JSON.parse(body.toString('utf8'));
        if (doc && typeof doc === 'object' && doc.resource) {
          doc.resource = `http://${req.headers.host}/${name}`;
          body = Buffer.from(JSON.stringify(doc));
        }
      } catch { /* not JSON — relay untouched */ }
      outHeaders['content-length'] = String(body.length);
      res.writeHead(upRes.statusCode ?? 502, outHeaders);
      res.end(body);
    });
  });
  upReq.on('error', (e) => {
    log(`[${name}] oauth metadata error: ${e.message}`);
    try { res.writeHead(502).end('oauth metadata error'); } catch { /* noop */ }
  });
  upReq.end();
  return true;
}

function proxyHttp(name, def, req, res) {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const body = Buffer.concat(chunks);
    const headers = stripHopByHop(req.headers);
    delete headers.host;
    delete headers['content-length'];
    let bridgeAuthenticates = false;
    try {
      const a = resolveAuth(def);
      if (a) { headers[a.header.toLowerCase()] = await a.getValue(); bridgeAuthenticates = true; }
    } catch (e) {
      noteFailure(name, e.message);
      log(`[${name}] auth error: ${e.message}`);
      try { res.writeHead(502).end('auth error'); } catch { /* noop */ }
      return;
    }
    for (const [k, v] of Object.entries(def.headers ?? {})) headers[k] = v;
    // A static credential in `headers` makes the bridge the authenticating party just as much as
    // an auth command does. Without this, a 401 on such a server counted as neither success nor
    // failure, and its challenge was relayed to a client that cannot act on it.
    if (Object.keys(def.headers ?? {}).some((k) => k.toLowerCase() === 'authorization')) bridgeAuthenticates = true;

    const remainder = req.url.substring(('/' + name).length);
    const target = new URL(remainder ? def.url.replace(/\/$/, '') + remainder : def.url);
    const lib = target.protocol === 'https:' ? https : http;
    const upReq = lib.request(target, { method: req.method, headers }, (upRes) => {
      const outHeaders = stripHopByHop(upRes.headers);
      const wwwKey = Object.keys(outHeaders).find((k) => k.toLowerCase() === 'www-authenticate');
      let healthCounted = false;
      if (upRes.statusCode === 401 && wwwKey) {
        if (bridgeAuthenticates) {
          // The bridge supplied the credential, so a 401 is the bridge's problem, not the
          // client's. Relaying a challenge here starts a login the client cannot win: whatever
          // token it comes back with is overwritten by the bridge's own on the next request, so
          // it 401s again and the client is sent back to the browser, forever. Drop the
          // challenge and surface the failure where an operator will see it instead.
          delete outHeaders[wwwKey];
          const source = def.audience ? `audience ${def.audience}`
            : (def.auth && def.auth.command) ? 'auth.command'
            : 'the configured authorization header';
          const detail = `upstream rejected the credential from ${source} (401)`;
          noteFailure(name, detail);
          healthCounted = true; // this response is already recorded; do not count it twice below
          log(`[${name}] ${detail} — the cached credential is being discarded`);
          // Whatever is cached is not working, so do not keep serving it for the rest of its TTL.
          invalidateToken(def);
        } else {
          // The client authenticates for this server, and it derives the metadata URL from the
          // bridge origin it is addressing. The upstream names its own origin, which the client
          // cannot match, so point it at the bridge's copy — the one that answers with a
          // matching `resource`.
          outHeaders[wwwKey] = String(outHeaders[wwwKey]).replace(
            /resource_metadata="[^"]*"/i,
            `resource_metadata="http://${req.headers.host}/.well-known/oauth-protected-resource/${name}"`,
          );
        }
      }
      res.writeHead(upRes.statusCode ?? 502, outHeaders);
      // Health means "did the client's command work". A 401 challenge on a server the client
      // authenticates is not a failure — it is the first half of the OAuth handshake and the
      // client is about to complete it. Counting those marked a healthy server as failing for
      // the three seconds of every handshake, which is most of what the dashboard showed.
      const code = upRes.statusCode ?? 502;
      const bridgeCredentialRejected = (code === 401 || code === 403) && bridgeAuthenticates;
      if (healthCounted) { /* the challenge branch above already recorded this response */ }
      else if (code >= 500) noteFailure(name, `upstream returned ${code}`);
      else if (bridgeCredentialRejected) noteFailure(name, `upstream rejected the bridge credential (${code})`);
      else if (code < 400) noteSuccess(name);
      upRes.pipe(res);
    });
    upReq.on('error', (e) => {
      noteFailure(name, e.message);
      log(`[${name}] upstream error: ${e.message}`);
      try { res.writeHead(502).end('upstream error'); } catch { /* noop */ }
    });
    if (body.length) upReq.write(body);
    upReq.end();
  });
}

/* --------------------------------- server ---------------------------------- */
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const [name, kind] = url.pathname.split('/').filter(Boolean);

  if (name === 'status' && !kind) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'mcp-pacemaker', version: VERSION, port: PORT, servers: Object.keys(servers), sessions: sessions.size }));
    return;
  }
  if (name === 'api') { handleApi(kind, req, res); return; }
  if (name === 'admin') { handleAdmin(url, req, res); return; }
  if (name === 'ui') { handleUi(url.pathname, res); return; }
  // Must precede the server lookup: ".well-known" is not a server name.
  if (name === '.well-known' && handleWellKnown(url, req, res)) return;
  if (!name || !servers[name]) { res.writeHead(404).end('unknown server'); return; }

  stat(name).requests++; stat(name).lastActivity = Date.now();
  const def = servers[name];
  if (def.type === 'http') { proxyHttp(name, def, req, res); return; }

  if (kind === 'mcp') { handleStreamable(name, req, res); return; }
  if (def.sharing === 'shared') {
    res.writeHead(400).end('shared mode requires Streamable HTTP; use /' + name + '/mcp');
    return;
  }

  if (req.method === 'GET' && kind === 'sse') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' });
    const sessionId = startChild(name, res);
    res.write(`event: endpoint\ndata: http://${req.headers.host}/${name}/message?sessionId=${sessionId}\n\n`);
    const keepAlive = setInterval(() => { try { res.write(': keepalive\n\n'); } catch { /* noop */ } }, 15000);
    req.on('close', () => {
      clearInterval(keepAlive);
      const s = sessions.get(sessionId);
      if (s) { killTree(s.child); sessions.delete(sessionId); }
    });
    return;
  }

  if (req.method === 'POST' && kind === 'message') {
    const s = sessions.get(url.searchParams.get('sessionId'));
    if (!s ||
        s.name !== name) { res.writeHead(404).end('no such session'); return; }
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      let parsed;
      try { parsed = JSON.parse(body); } catch { res.writeHead(400).end('invalid json'); return; }
      const messages = Array.isArray(parsed) ? parsed : [parsed];
      try {
        for (const m of messages) s.child.stdin.write(JSON.stringify(m) + '\n');
        res.writeHead(202).end('accepted');
      } catch (e) {
        log(`[${s.name}] stdin write failed: ${e.message}`);
        res.writeHead(500).end('write failed');
      }
    });
    return;
  }

  res.writeHead(404).end('not found');
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    // P5: classify what already holds the port — a pacemaker peer (adopt) vs a foreign service (collision).
    const probe = http.get({ host: HOST, port: PORT, path: '/status', timeout: 1500 }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c));
      resp.on('end', () => {
        let sig = null; try { sig = JSON.parse(d); } catch { /* not json */ }
        if (sig && sig.service === 'mcp-pacemaker') log(`port ${PORT} already served by mcp-pacemaker v${sig.version ?? '?'} — adopting existing bridge; exiting.`);
        else log(`port ${PORT} is held by a non-pacemaker service — choose another --port or migrate; exiting.`);
        process.exit(3);
      });
    });
    probe.on('error', () => { log(`port ${PORT} in use (status probe failed) — exiting.`); process.exit(3); });
    probe.on('timeout', () => { probe.destroy(); log(`port ${PORT} in use (status probe timeout) — exiting.`); process.exit(3); });
    return;
  }
  log(`server error: ${e.message}`); process.exit(1);
});

// Node closes idle keep-alive sockets after 5s by default. MCP clients pool connections and
// routinely idle far longer than that between tool calls, so the socket is closed underneath
// them and the next request fails with ECONNRESET. Hold sockets open past typical think time;
// headersTimeout must stay above keepAliveTimeout or the two race.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;

server.listen(PORT, HOST, () => {
  try { writeFileSync(NONCE_FILE, ADMIN_NONCE); } catch { /* noop */ }
  log(`listening on http://${HOST}:${PORT}  (config ${CONFIG}, base cwd ${BASE_CWD})`);
  log(`dashboard: http://${HOST}:${PORT}/ui  ·  api /api/status|/api/events|/api/logs  ·  admin nonce -> ${NONCE_FILE}`);
  for (const [n, d] of Object.entries(servers)) {
    log(`  ${n}  ->  ${d.type === 'http' ? `http proxy ${d.url}` : `stdio  /${n}/sse | /${n}/mcp`}`);
  }
});

// Ending the streams before exiting matters: a client that sees its SSE stream close cleanly
// treats it as "reconnect", while a dropped TCP connection reads as a transport fault and some
// clients latch on that permanently. This only helps a graceful stop — a force-kill runs no
// handler at all, which is why the supervisor should ask rather than kill.
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true; // stop warm-pool refills racing the exit
  await poolingConfig.close();
  sharedManager.shutdown();
  for (const s of sessions.values()) { try { s.res?.end(); } catch { /* already gone */ } }
  for (const s of httpSessions.values()) { try { s.sseRes?.end(); } catch { /* already gone */ } }
  for (const s of sessions.values()) killTree(s.child, true);
  for (const s of httpSessions.values()) killTree(s.child, true);
  for (const arr of warmPool.values()) for (const c of arr) killTree(c, true);
  try { server.close(); } catch { /* noop */ }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
