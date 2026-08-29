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
import { randomUUID } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, extname } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { checkServerPaths } from './config-checks.mjs';

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

/* ----------------------------- dashboard backbone --------------------------- */
const startedAt = Date.now();
const ADMIN_NONCE = randomUUID();
const NONCE_FILE = resolve(dirname(CONFIG), 'admin.nonce');
const logBuffer = [];
const logClients = new Set();
const snapClients = new Set();
const stats = new Map(); // name -> { requests, lastError, lastActivity }
const stat = (name) => { let s = stats.get(name); if (!s) { s = { requests: 0, lastError: null, lastActivity: 0 }; stats.set(name, s); } return s; };

const log = (m) => {
  const line = `[mcp-bridge] ${new Date().toISOString()} ${m}`;
  process.stderr.write(line + '\n');
  logBuffer.push(line); if (logBuffer.length > 500) logBuffer.shift();
  for (const c of logClients) { try { c.write(`data: ${JSON.stringify(line)}\n\n`); } catch { /* gone */ } }
};

// Token expiry (seconds) for an http server's cached command/az token, if any — for the dashboard.
function authCacheKey(def) {
  let auth = def.auth;
  if (!auth && def.audience) auth = { type: 'command', command: `az account get-access-token --resource ${def.audience} --query accessToken -o tsv` };
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
    byName[name] = { name, type: def.type === 'http' ? 'http' : 'stdio', sessions: 0, pids: [], clients: [], sharing: def.sharing || 'isolated', warm: (warmPool.get(name) || []).length, minWarm: poolTarget(name), recycleMinutes: recycleMinutesFor(name) || null, maxSessions: def.maxSessions || MAX_SESSIONS_PER_SERVER || null, requests: st.requests, lastError: st.lastError, lastActivitySec: st.lastActivity ? Math.round((Date.now() - st.lastActivity) / 1000) : null };
    if (def.type === 'http') { byName[name].url = def.url; byName[name].tokenExpiresIn = tokenExpiryFor(def); }
  }
  for (const s of sessions.values()) { const b = byName[s.name]; if (b) { b.sessions++; if (s.child?.pid) b.pids.push(s.child.pid); } }
  for (const s of httpSessions.values()) { const b = byName[s.name]; if (b) { b.sessions++; if (s.child?.pid) b.pids.push(s.child.pid); if (s.clientInfo && s.clientInfo.name && !b.clients.includes(s.clientInfo.name)) b.clients.push(s.clientInfo.name); } }
  return { ok: true, service: 'mcp-pacemaker', version: VERSION, port: PORT, uptimeSec: Math.round((Date.now() - startedAt) / 1000), sessions: sessions.size + httpSessions.size, servers: Object.values(byName) };
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
    if (!d.command && !d.url) { checks.push({ name: n, status: 'bad', detail: 'missing command/url' }); continue; }
    if (d.type === 'http' && !d.auth && !d.audience && !d.headers) { checks.push({ name: n, status: 'warn', detail: 'http server with no auth' }); continue; }
    const pathCheck = checkServerPaths(n, d, BASE_CWD);
    if (pathCheck) { checks.push(pathCheck); continue; }
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
  const parts = url.pathname.split('/').filter(Boolean); // ['admin','recycle', <name>?]
  if (req.method === 'POST' && parts[1] === 'recycle') {
    const target = parts[2];
    const killed = recycleServer(target);
    log(`admin: recycled ${killed} session(s)${target ? ` for ${target}` : ''}`);
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true, recycled: killed }));
    return;
  }
  res.writeHead(404).end('unknown admin action');
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

// Normalize a server's auth config into { header, getValue() } or null.
function resolveAuth(def) {
  let auth = def.auth;
  if (!auth && def.audience) {
    auth = {
      type: 'command',
      command: `az account get-access-token --resource ${def.audience} --query accessToken -o tsv`,
      refreshMinutes: 50,
    };
  }
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
        tokenCache.set(key, { value, exp: Date.now() + ttl });
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
function spawnServer(def) {
  const args = def.args ?? [];
  const opts = {
    cwd: def.cwd ? resolve(BASE_CWD, def.cwd) : BASE_CWD,
    env: { ...process.env, ...(def.env ?? {}) },
    stdio: ['pipe', 'pipe', 'pipe'],
  };
  const bareWin = process.platform === 'win32' && !/[\\/]/.test(def.command) && !/\.(exe|com)$/i.test(def.command);
  if (bareWin) {
    const line = '"' + [def.command, ...args].map(quoteWinArg).join(' ') + '"';
    return spawn(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', line], { ...opts, windowsVerbatimArguments: true });
  }
  return spawn(def.command, args, opts);
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
    stat(name).lastError = `exited code ${code}${tail ? `: ${tail}` : ''}`;
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
  const child = spawnServer(def);
  sessions.set(sessionId, { child, res, name });
  log(`[${name}] session ${sessionId.slice(0, 8)} started (pid ${child.pid ?? '?'})`);

  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const t = line.trim();
    if (!t) return;
    try { JSON.parse(t); } catch { log(`[${name}] (non-json stdout) ${t}`); return; }
    try { res.write(`event: message\ndata: ${t}\n\n`); } catch { /* client gone */ }
  });
  pipeStderr(name, child);
  child.on('error', (e) => { stat(name).lastError = e.message; log(`[${name}] spawn error: ${e.message}`); });
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

// Resolve when a session slot is free for `name`, or false if the wait ran out.
const waiters = new Map(); // name -> [resolve, ...]
function slotFreed(name) {
  const q = waiters.get(name);
  if (q && q.length) q.shift()(true);
}
function awaitSlot(name, cap) {
  if (sessionCount(name) < cap) return Promise.resolve(true);
  if (QUEUE_TIMEOUT_MS <= 0) return Promise.resolve(false);
  return new Promise((res) => {
    if (!waiters.has(name)) waiters.set(name, []);
    const q = waiters.get(name);
    const done = (ok) => { const i = q.indexOf(done); if (i >= 0) q.splice(i, 1); clearTimeout(timer); res(ok); };
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

function startStreamableChild(name, warmChild, forcedSessionId) {
  const def = servers[name];
  const sessionId = forcedSessionId || randomUUID();
  const child = warmChild || spawnServer(def);
  const session = { child, name, pending: new Map(), sseRes: null, lastActivity: Date.now(), clientInfo: null };
  httpSessions.set(sessionId, session);
  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const t = line.trim();
    if (!t) return;
    let msg;
    try { msg = JSON.parse(t); } catch { log(`[${name}] (non-json stdout) ${t}`); return; }
    const id = msg.id;
    const p = id != null ? session.pending.get(id) : undefined;
    if (p) { session.pending.delete(id); clearTimeout(p.timer); p.resolve(msg); }
    else if (session.sseRes) { try { session.sseRes.write(`event: message\ndata: ${t}\n\n`); } catch { /* noop */ } }
  });
  if (!warmChild) pipeStderr(name, child);
  child.on('error', (e) => { stat(name).lastError = e.message; log(`[${name}] spawn error: ${e.message}`); });
  child.on('exit', (code) => {
    noteExit(name, child, code);
    log(`[${name}] streamable session ${sessionId.slice(0, 8)} exited (code ${code})`);
    if (session.sseRes) { try { session.sseRes.end(); } catch { /* noop */ } }
    // The same session id may already have been re-established on a fresh child by the time this
    // fires: `taskkill /F /T` takes about a second on Windows, so a reap followed by a resume
    // lands the replacement first. Only drop the mapping if it still points at this child, or a
    // late exit tears down the session that replaced it.
    if (httpSessions.get(sessionId) === session) httpSessions.delete(sessionId);
    slotFreed(name); // a capped server may have a request waiting for this slot
  });
  log(`[${name}] streamable session ${sessionId.slice(0, 8)} started (pid ${child.pid ?? '?'})`);
  return sessionId;
}

/* --------------------- keep-warm pool (sharing: "pool") --------------------- */
// For servers marked sharing:"pool", keep `minWarm` pre-spawned (un-initialized) children ready
// so a new session adopts a warm child (process already started + imports loaded) instead of a
// cold spawn. The warm child receives its FIRST initialize from the real client (safe — no
// re-initialize). shared/multiplex is deferred R&D.
const warmPool = new Map(); // name -> [child, ...]
const poolTarget = (name) => (servers[name] && servers[name].sharing === 'pool' ? (servers[name].minWarm || 1) : 0);
function spawnWarm(name) {
  const child = spawnServer(servers[name]);
  pipeStderr(name, child);
  child.on('exit', (code) => {
    noteExit(name, child, code);
    const arr = warmPool.get(name); if (arr) { const i = arr.indexOf(child); if (i >= 0) arr.splice(i, 1); }
  });
  return child;
}
function refillPool(name) {
  const target = poolTarget(name);
  if (!target) return;
  if (!warmPool.has(name)) warmPool.set(name, []);
  const arr = warmPool.get(name);
  while (arr.length < target) { arr.push(spawnWarm(name)); log(`[${name}] pre-warmed pool child (${arr.length}/${target})`); }
}
function takeWarm(name) {
  const arr = warmPool.get(name);
  if (arr && arr.length) { const c = arr.shift(); setImmediate(() => refillPool(name)); return c; }
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

function saveResumable() {
  if (!RESUME_ENABLED) return;
  try { writeFileSync(RESUME_FILE, JSON.stringify(Object.fromEntries(resumable))); } catch { /* best effort */ }
}
function rememberSession(sessionId, name, initMsg) {
  if (!RESUME_ENABLED || !initMsg) return;
  resumable.set(sessionId, { server: name, initialize: initMsg.params ?? {}, at: Date.now() });
  saveResumable();
}
function forgetSession(sessionId) {
  if (resumable.delete(sessionId)) saveResumable();
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
  const cap = servers[name].maxSessions || MAX_SESSIONS_PER_SERVER;
  if (cap > 0 && sessionCount(name) >= cap) return null;

  startStreamableChild(name, takeWarm(name), sessionId);
  const session = httpSessions.get(sessionId);
  const initId = `bridge-resume-${randomUUID()}`;
  const reply = await new Promise((resolveWait) => {
    const timer = setTimeout(() => { session.pending.delete(initId); resolveWait(null); }, INIT_TIMEOUT_MS);
    session.pending.set(initId, { resolve: resolveWait, timer });
    try {
      session.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: initId, method: 'initialize', params: rec.initialize }) + '\n');
    } catch { clearTimeout(timer); session.pending.delete(initId); resolveWait(null); }
  });
  if (!reply || reply.error) {
    killTree(session.child);
    httpSessions.delete(sessionId);
    log(`[${name}] could not resume session ${sessionId.slice(0, 8)}`);
    return null;
  }
  try { session.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n'); } catch { /* noop */ }
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
  for (const s of sessions.values()) if (!name || s.name === name) { killTree(s.child); killed++; }
  for (const s of httpSessions.values()) if (!name || s.name === name) { killTree(s.child); killed++; }
  // Warm children hold the same stale credential, so they have to go too, or a recycled server
  // is immediately replaced by a pre-spawned copy of what was just discarded.
  for (const n of (name ? [name] : Object.keys(servers))) {
    for (const c of (warmPool.get(n) || []).slice()) killTree(c);
    setTimeout(() => refillPool(n), 1000).unref();
  }
  return killed;
}

const recyclePeriods = Object.keys(servers).map(recycleMinutesFor).filter((m) => m > 0);
if (recyclePeriods.length) {
  // Check often enough to honour the shortest configured period, but never busier than needed.
  const tick = Math.max(200, Math.min(30_000, (Math.min(...recyclePeriods) * 60_000) / 2));
  setInterval(() => {
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
  }, tick).unref();
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
        .catch((e) => { stat(name).lastError = `token refresh failed: ${e.message}`; log(`[${name}] token refresh failed: ${e.message}`); });
    }
  }, tick).unref();
}

function handleStreamable(name, req, res) {
  const sid = req.headers['mcp-session-id'];

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
    if (session) { killTree(session.child); httpSessions.delete(sid); }
    // An explicit DELETE ends the session for good; it must not come back on the next request.
    if (sid) forgetSession(sid);
    res.writeHead(204).end();
    return;
  }

  if (req.method === 'POST') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      let parsed;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString() || 'null'); } catch { res.writeHead(400).end('invalid json'); return; }
      const messages = Array.isArray(parsed) ? parsed : (parsed == null ? [] : [parsed]);
      const isInit = messages.some((m) => m && m.method === 'initialize');
      let sessionId = sid;
      let session = sid ? httpSessions.get(sid) : null;
      if (!session && sid) {
        // An id this process has not seen: it may predate a restart or a recycle.
        session = await resumeSession(name, sid);
        if (session) sessionId = sid;
      }
      if (!session) {
        if (!isInit) { res.writeHead(404).end('no session (send initialize first)'); return; }
        const cap = servers[name].maxSessions || MAX_SESSIONS_PER_SERVER;
        if (cap > 0 && !(await awaitSlot(name, cap))) {
          res.writeHead(503).end(`bridge: max sessions (${cap}) reached for ${name}`);
          return;
        }
        sessionId = startStreamableChild(name, takeWarm(name));
        session = httpSessions.get(sessionId);
      }
      session.lastActivity = Date.now();
      if (isInit) {
        const im = messages.find((m) => m && m.method === 'initialize');
        const ci = im && im.params && im.params.clientInfo;
        if (ci) session.clientInfo = { name: ci.name, version: ci.version };
        rememberSession(sessionId, name, im);
      }
      const requestIds = messages.filter((m) => m && m.id != null && m.method).map((m) => m.id);
      // initialize is the request that pays for spawning the server, and a cold start can be
      // slow (a package manager fetching the server on first run), so it gets a longer budget
      // than steady-state calls.
      const budget = isInit ? INIT_TIMEOUT_MS : REQUEST_TIMEOUT_MS;
      const waits = requestIds.map((id) => new Promise((resolveWait) => {
        const timer = setTimeout(() => {
          if (session.pending.has(id)) { session.pending.delete(id); resolveWait({ jsonrpc: '2.0', id, error: { code: -32001, message: 'bridge: upstream timeout' } }); }
        }, budget);
        session.pending.set(id, { resolve: resolveWait, timer });
      }));
      try { for (const m of messages) session.child.stdin.write(JSON.stringify(m) + '\n'); }
      catch { res.writeHead(500).end('write failed'); return; }
      const headers = { 'Mcp-Session-Id': sessionId };
      if (!requestIds.length) { res.writeHead(202, headers).end(); return; }
      const results = await Promise.all(waits);
      // Stamp again on completion: the idle clock should measure time since the request finished,
      // not since it started, or a call slower than the timeout is reapable the moment it returns.
      session.lastActivity = Date.now();
      headers['Content-Type'] = 'application/json';
      res.writeHead(200, headers);
      res.end(JSON.stringify(results.length === 1 ? results[0] : results));
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
    try {
      const a = resolveAuth(def);
      if (a) headers[a.header.toLowerCase()] = await a.getValue();
    } catch (e) {
      stat(name).lastError = e.message;
      log(`[${name}] auth error: ${e.message}`);
      try { res.writeHead(502).end('auth error'); } catch { /* noop */ }
      return;
    }
    for (const [k, v] of Object.entries(def.headers ?? {})) headers[k] = v;

    const remainder = req.url.substring(('/' + name).length);
    const target = new URL(remainder ? def.url.replace(/\/$/, '') + remainder : def.url);
    const lib = target.protocol === 'https:' ? https : http;
    const upReq = lib.request(target, { method: req.method, headers }, (upRes) => {
      const outHeaders = stripHopByHop(upRes.headers);
      // A 401 challenge names where to find this resource's metadata. The upstream points at
      // its own origin, which the client cannot match to the bridge URL it is addressing, so
      // redirect it to the bridge's copy — the one place that answers with a matching `resource`.
      const wwwKey = Object.keys(outHeaders).find((k) => k.toLowerCase() === 'www-authenticate');
      if (upRes.statusCode === 401 && wwwKey) {
        outHeaders[wwwKey] = String(outHeaders[wwwKey]).replace(
          /resource_metadata="[^"]*"/i,
          `resource_metadata="http://${req.headers.host}/.well-known/oauth-protected-resource/${name}"`,
        );
      }
      res.writeHead(upRes.statusCode ?? 502, outHeaders);
      upRes.pipe(res);
    });
    upReq.on('error', (e) => {
      stat(name).lastError = e.message;
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
    if (!s) { res.writeHead(404).end('no such session'); return; }
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

function shutdown() {
  for (const s of sessions.values()) killTree(s.child, true);
  for (const s of httpSessions.values()) killTree(s.child, true);
  for (const arr of warmPool.values()) for (const c of arr) killTree(c, true);
  try { server.close(); } catch { /* noop */ }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
