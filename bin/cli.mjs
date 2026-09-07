#!/usr/bin/env node
/**
 * mcp-pacemaker — CLI (commander + @clack/prompts + picocolors). MIT.
 *
 * Commands:
 *   import   --from vscode|cursor|claude [--config <path>]   Read your existing client config -> servers.json
 *   plan     --client vscode|cursor|claude [--port N]        Dry-run: show client-config changes
 *   install  --client vscode|cursor|claude [--port N]        Wire client -> bridge, register auto-start, start bridge
 *   status                                                   Is the bridge up? what's installed?
 *   start | stop [--port N]                                  Start/stop the bridge supervisor
 *   uninstall                                                Stop bridge, remove auto-start, restore client config
 *
 * Config + state live in ~/.mcp-pacemaker/ . Your client config is backed up to *.bak before any rewrite.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn, execFileSync, execSync } from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { Command } from 'commander';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import { parse as parseToml } from 'smol-toml';
import { checkServerPaths, checkReservedName } from './config-checks.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const HOME = resolve(homedir(), '.mcp-pacemaker');
const CONFIG = resolve(HOME, 'servers.json');
const STATE = resolve(HOME, 'state.json');
const DEFAULT_PORT = 8791;

const ok = (m) => console.log(`${pc.green('✓')} ${m}`);
// warnCount lets `doctor` report warnings in its summary instead of claiming "all good".
let warnCount = 0;
const warn = (m) => { warnCount++; console.log(`${pc.yellow('!')} ${m}`); };
const err = (m) => console.log(`${pc.red('✗')} ${m}`);
const info = (m) => console.log(`${pc.cyan('·')} ${m}`);

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const writeJson = (p, o) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(o, null, 2) + '\n'); };

/* ------------------------------- host adapters ------------------------------ */
// Each MCP host (editor or CLI) is an adapter: where its config lives, the JSON key its servers
// sit under, and its config format. Editors and CLIs are just data in this registry; CLI hosts
// (Claude Code, Copilot CLI, Codex, Gemini) are added in later phases.
function vscodeConfigPath() {
  const plat = platform(), home = homedir();
  const appdata = process.env.APPDATA || join(home, 'AppData', 'Roaming');
  if (plat === 'win32') return join(appdata, 'Code', 'User', 'mcp.json');
  if (plat === 'darwin') return join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json');
  return join(home, '.config', 'Code', 'User', 'mcp.json');
}
function claudeDesktopConfigPath() {
  const plat = platform(), home = homedir();
  const appdata = process.env.APPDATA || join(home, 'AppData', 'Roaming');
  if (plat === 'win32') return join(appdata, 'Claude', 'claude_desktop_config.json');
  if (plat === 'darwin') return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  return join(home, '.config', 'Claude', 'claude_desktop_config.json');
}
function codexConfigPath() { return join(homedir(), '.codex', 'config.toml'); }
// Is a binary resolvable on PATH? (used to detect CLI hosts that keep no fixed config file)
function hasBin(name) {
  try { execSync(platform() === 'win32' ? `where ${name}` : `command -v ${name}`, { stdio: 'ignore' }); return true; }
  catch { return false; }
}

// Bridge endpoints for a server: http-proxied servers use the proxy base /<name>; stdio-backed
// servers are exposed over SSE (/<name>/sse) and Streamable HTTP (/<name>/mcp).
const proxyUrl = (name, port) => `http://127.0.0.1:${port}/${name}`;
const sseUrl = (name, port) => `http://127.0.0.1:${port}/${name}/sse`;
const mcpUrl = (name, port) => `http://127.0.0.1:${port}/${name}/mcp`;
// Per-host bridged-entry serializers. Hosts that speak Streamable HTTP use /<name>/mcp for stdio
// servers; SSE is kept only for hosts not yet verified on Streamable HTTP. SSE is also the
// transport behind the -32001 "session not found" reconnect failures, so prefer /mcp where possible.
const entryClassic = (name, def, port) =>
  def.type === 'http' ? { type: 'http', url: proxyUrl(name, port) } : { type: 'sse', url: sseUrl(name, port) };
const entryStreamable = (name, def, port) =>
  ({ type: 'http', url: def.type === 'http' ? proxyUrl(name, port) : mcpUrl(name, port) });
const entryGemini = (name, def, port) =>
  ({ httpUrl: def.type === 'http' ? proxyUrl(name, port) : mcpUrl(name, port) });

const HOSTS = [
  { id: 'vscode',      label: 'VS Code',        kind: 'editor', format: 'json', serversKey: 'servers',    path: vscodeConfigPath,                                    entry: entryStreamable },
  { id: 'cursor',      label: 'Cursor',         kind: 'editor', format: 'json', serversKey: 'mcpServers', path: () => join(homedir(), '.cursor', 'mcp.json'),         entry: entryClassic },
  { id: 'claude',      label: 'Claude Desktop', kind: 'editor', format: 'json', serversKey: 'mcpServers', path: claudeDesktopConfigPath,                             entry: entryClassic },
  { id: 'copilot-cli', label: 'Copilot CLI',    kind: 'cli',    format: 'json', serversKey: 'mcpServers', path: () => join(homedir(), '.copilot', 'mcp-config.json'), entry: entryStreamable },
  { id: 'gemini',      label: 'Gemini CLI',     kind: 'cli',    format: 'json', serversKey: 'mcpServers', path: () => join(homedir(), '.gemini', 'settings.json'),    entry: entryGemini },
  { id: 'codex',       label: 'Codex CLI',      kind: 'cli',    format: 'toml',                            path: codexConfigPath, detect: () => hasBin('codex') || existsSync(codexConfigPath()) },
  { id: 'claude-code', label: 'Claude Code',    kind: 'cli',    format: 'native', bin: 'claude',           detect: () => hasBin('claude') },
];
const hostEntry = (id, name, def, port) => (getHost(id).entry || entryClassic)(name, def, port);
const HOST_IDS = HOSTS.map((h) => h.id);
function getHost(id) {
  const h = HOSTS.find((x) => x.id === id);
  if (!h) throw new Error(`unknown host "${id}" (known: ${HOST_IDS.join(' | ')})`);
  return h;
}
// Back-compat helpers used throughout the CLI, now backed by the registry.
const clientConfigPath = (id) => getHost(id).path();
const clientServersKey = (id) => getHost(id).serversKey;
// Which known hosts have a config on this box.
function detectClients() {
  return HOSTS.filter((h) => { try { return h.detect ? h.detect() : existsSync(h.path()); } catch { return false; } }).map((h) => h.id);
}
function defaultClient(explicit) {
  return explicit || detectClients()[0] || 'vscode';
}

/* ------------------------------- install state ------------------------------ */
// state.json holds a LIST of wired hosts, each with its own port. Hosts on the same port share
// one bridge; hosts on different ports each get their own bridge (both topologies supported).
function readState() {
  if (!existsSync(STATE)) return { hosts: [] };
  let raw; try { raw = readJson(STATE); } catch { return { hosts: [] }; }
  if (Array.isArray(raw.hosts)) return raw;
  // migrate legacy single-host shape { client, path, port, installedAt, servers }
  if (raw.client) return { hosts: [{ id: raw.client, path: raw.path, port: raw.port, wiredAt: raw.installedAt, servers: raw.servers || [] }] };
  return { hosts: [] };
}
const writeState = (state) => writeJson(STATE, state);
function upsertHost(state, entry) {
  const i = state.hosts.findIndex((h) => h.id === entry.id);
  if (i >= 0) state.hosts[i] = entry; else state.hosts.push(entry);
  return state;
}
const distinctPorts = (state) => [...new Set(state.hosts.map((h) => h.port))];

/* --------------------------------- import ----------------------------------- */
// Pure import: merge a client's stdio + http servers into servers.json.
// P2: carry audience/auth/headers through so http servers authenticate with no hand-editing.
function importServers(client, srcPath) {
  const path = srcPath || clientConfigPath(client);
  if (!existsSync(path)) throw new Error(`client config not found: ${path}`);
  const src = readJson(path)[clientServersKey(client)] || {};
  const out = existsSync(CONFIG) ? readJson(CONFIG) : {};
  let imported = 0, skipped = 0, httpNoAuth = 0;
  for (const [name, def] of Object.entries(src)) {
    const url = def.url || '';
    if (/127\.0\.0\.1|localhost/.test(url)) { skipped++; continue; } // already a local bridge route
    if (def.command) {
      out[name] = { command: def.command, args: def.args || [], ...(def.env ? { env: def.env } : {}), ...(def.cwd ? { cwd: def.cwd } : {}) };
      imported++;
    } else if (url) {
      out[name] = {
        type: 'http', url,
        ...(def.headers ? { headers: def.headers } : {}),
        ...(def.audience ? { audience: def.audience } : {}),
        ...(def.auth ? { auth: def.auth } : {}),
      };
      if (!def.audience && !def.auth) httpNoAuth++;
      imported++;
    } else skipped++;
  }
  writeJson(CONFIG, out);
  return { imported, skipped, httpNoAuth, path };
}

function cmdImport(args) {
  const client = args.from || defaultClient(args.client);
  let r;
  try { r = importServers(client, args.config); } catch (e) { err(e.message); process.exit(1); }
  ok(`imported ${r.imported} server(s) from ${client} -> ${CONFIG}${r.skipped ? `  (${r.skipped} skipped)` : ''}`);
  if (r.httpNoAuth) info(`${r.httpNoAuth} http server(s) have no auth — add an "audience"/"auth" block if they need a token.`);
  else info('auth (audience/auth/headers) carried over from your client config — nothing to hand-edit.');
}

/* ----------------------------- plan / install ------------------------------- */
// An existing client entry may use a different key than our server name — VS Code's
// registry-style "io.github.Owner/name" is the common case. Recognize entries that already
// point at a bridge route for a known server so we rewrite that key in place instead of
// adding a duplicate (which would double-register the server and its tools).
const BRIDGE_URL_RE = /^https?:\/\/(?:127\.0\.0\.1|localhost):\d+\/([^/?#]+)(?:\/(?:sse|mcp))?\/?$/;
function bridgeServerName(entry) {
  const url = entry && (entry.url || entry.httpUrl);
  const m = typeof url === 'string' ? url.match(BRIDGE_URL_RE) : null;
  return m ? decodeURIComponent(m[1]) : null;
}
// Map server name -> the existing config key that already points at it under another name.
function aliasKeys(existing, servers) {
  const aliases = new Map();
  for (const [k, v] of Object.entries(existing)) {
    const target = bridgeServerName(v);
    if (target && target !== k && servers[target] && !aliases.has(target)) aliases.set(target, k);
  }
  return aliases;
}

function computeRewrite(client, port) {
  if (!existsSync(CONFIG)) { err(`no ${CONFIG} — run "mcp-pacemaker import --from ${client}" first`); process.exit(1); }
  const servers = readJson(CONFIG);
  const path = clientConfigPath(client);
  const key = clientServersKey(client);
  const cfg = existsSync(path) ? readJson(path) : { [key]: {} };
  cfg[key] = cfg[key] || {};
  const aliases = aliasKeys(cfg[key], servers);
  const changes = [];
  const keyFor = {};
  for (const [name, def] of Object.entries(servers)) {
    // An exact-name entry always wins; otherwise adopt an alias key if one already exists.
    const k = cfg[key][name] !== undefined ? name : (aliases.get(name) ?? name);
    keyFor[name] = k;
    const desired = hostEntry(client, name, def, port);
    if (JSON.stringify(cfg[key][k]) !== JSON.stringify(desired)) changes.push({ name, key: k, from: cfg[key][k], to: desired });
  }
  return { path, key, cfg, servers, changes, keyFor };
}

// --- Codex (TOML) + Claude Code (native) config writers ---
const tomlKey = (name) => (/^[A-Za-z0-9_-]+$/.test(name) ? name : JSON.stringify(name));
const codexBlock = (name, url) => `[mcp_servers.${tomlKey(name)}]\nurl = ${JSON.stringify(url)}\n`;
// Remove the [mcp_servers.<name>] tables we manage, preserving all other content + comments.
function stripManagedCodexTables(text, names) {
  const targets = new Set(names.map((n) => `mcp_servers.${n}`));
  const out = []; let skip = false;
  for (const line of text.split(/\r?\n/)) {
    const hdr = line.match(/^\s*\[\[?\s*(.+?)\s*\]\]?\s*$/);
    if (hdr) { skip = targets.has(hdr[1].replace(/["'\s]/g, '')); if (skip) continue; }
    if (!skip) out.push(line);
  }
  return out.join('\n');
}
// Merge existing config.toml (minus our tables) with fresh [mcp_servers.<name>] tables.
function buildCodexConfig(port) {
  const path = codexConfigPath();
  const servers = readJson(CONFIG);
  const names = Object.keys(servers);
  let text = existsSync(path) ? readFileSync(path, 'utf8') : '';
  text = stripManagedCodexTables(text, names).replace(/\n{3,}/g, '\n\n').trimEnd();
  const blocks = names.map((n) => codexBlock(n, servers[n].type === 'http' ? proxyUrl(n, port) : mcpUrl(n, port))).join('\n');
  let merged = (text ? text + '\n\n' : '') + blocks;
  parseToml(merged); // validate the result parses (throws on error)
  if (!merged.endsWith('\n')) merged += '\n';
  return { path, text: merged, names };
}
// Claude Code: shell out to the real `claude mcp` CLI (its ~/.claude.json is too stateful to hand-edit).
const claudeUrl = (name, def, port) => (def.type === 'http' ? proxyUrl(name, port) : mcpUrl(name, port));
function applyNativeClaude(port) {
  const servers = readJson(CONFIG);
  for (const [name, def] of Object.entries(servers)) {
    try { execSync(`claude mcp remove --scope user ${name}`, { stdio: 'ignore' }); } catch { /* not present */ }
    execSync(`claude mcp add --scope user --transport http ${name} ${claudeUrl(name, def, port)}`, { stdio: 'ignore' });
  }
  return Object.keys(servers);
}

function cmdPlan(args) {
  const client = defaultClient(args.client);
  const host = getHost(client);
  const port = parseInt(args.port || DEFAULT_PORT, 10);
  if (!existsSync(CONFIG)) { err(`no ${CONFIG} — run "mcp-pacemaker import" first`); process.exit(1); }
  const servers = readJson(CONFIG);
  if (host.format === 'toml') {
    const r = buildCodexConfig(port);
    info(`bridge port ${port} · ${r.names.length} server(s) · ${client} (${r.path})`);
    console.log(pc.dim('\n--- config.toml (managed [mcp_servers.*] tables) ---'));
    console.log(r.text.trimEnd());
    console.log(pc.dim(`\nApply with "mcp-pacemaker install --client ${client}" (writes a .bak first).`));
    return;
  }
  if (host.format === 'native') {
    info(`bridge port ${port} · ${Object.keys(servers).length} server(s) · ${client} (via ${host.bin} mcp)`);
    for (const [name, def] of Object.entries(servers)) console.log(`  ${host.bin} mcp add --scope user --transport http ${name} ${claudeUrl(name, def, port)}`);
    return;
  }
  const { path, changes } = computeRewrite(client, port);
  info(`bridge port ${port} · ${Object.keys(servers).length} server(s) · client ${client} (${path})`);
  if (!changes.length) { ok('client already wired to the bridge — no changes'); return; }
  console.log(pc.bold(`\nPlanned client-config changes (${changes.length}):`));
  for (const c of changes) {
    const label = c.key && c.key !== c.name ? `${c.name} (as ${c.key})` : c.name;
    console.log(`  ${label}: ${c.from ? JSON.stringify(c.from) : '(new)'} -> ${JSON.stringify(c.to)}`);
  }
  console.log(pc.dim(`\nApply with "mcp-pacemaker install --client ${client}" (writes a .bak first).`));
}

async function cmdInstall(args) {
  const client = defaultClient(args.client);
  const host = getHost(client);
  const port = parseInt(args.port || DEFAULT_PORT, 10);
  // P5: never wire a host to a port held by a foreign (non-pacemaker) service.
  if ((await probePort(port)) === 'foreign') { err(`port ${port} is held by a non-pacemaker service — wiring here would hijack it. Re-run with --port <free port>.`); process.exit(1); }
  if (!existsSync(CONFIG)) { err(`no ${CONFIG} — run "mcp-pacemaker import" first`); process.exit(1); }

  let path, serverNames;
  if (host.format === 'json') {
    const rw = computeRewrite(client, port);
    if (existsSync(rw.path)) { copyFileSync(rw.path, rw.path + '.bak'); info(`backed up ${rw.path} -> ${rw.path}.bak`); }
    for (const [name, def] of Object.entries(rw.servers)) rw.cfg[rw.key][rw.keyFor[name] || name] = hostEntry(client, name, def, port);
    writeJson(rw.path, rw.cfg);
    path = rw.path; serverNames = Object.keys(rw.servers);
  } else if (host.format === 'toml') {
    const r = buildCodexConfig(port);
    if (existsSync(r.path)) { copyFileSync(r.path, r.path + '.bak'); info(`backed up ${r.path} -> ${r.path}.bak`); }
    mkdirSync(dirname(r.path), { recursive: true });
    writeFileSync(r.path, r.text);
    path = r.path; serverNames = r.names;
  } else { // native
    if (!hasBin(host.bin)) { err(`"${host.bin}" not found on PATH — install ${host.label} first, or use "mcp-pacemaker emit --client ${client}".`); process.exit(1); }
    serverNames = applyNativeClaude(port);
    path = `native (${host.bin} mcp)`;
  }
  ok(`wired ${serverNames.length} server(s) in ${client} -> bridge on :${port}`);
  if (args.autostart !== false) {
    try { registerAutostart(port); ok('registered OS auto-start'); }
    catch (e) { warn(`auto-start registration skipped: ${e.message}`); }
  } else info('skipped OS auto-start (--no-autostart)');
  if (args.start !== false) await startBridge(port); else info('skipped bridge start (--no-start)');
  const state = readState();
  upsertHost(state, { id: client, path, port, wiredAt: new Date().toISOString(), servers: serverNames });
  writeState(state);
  ok('done — run "mcp-pacemaker status" to verify.');
  if (client === 'vscode') info('reload VS Code once so it picks up the rewritten mcp.json.');
}

/* --------------------------------- init (wizard) --------------------------- */
async function cmdInit(args) {
  p.intro(pc.bold('mcp-pacemaker setup'));
  const detected = detectClients();
  if (detected.length) p.log.info(`Detected host(s): ${pc.cyan(detected.map((id) => getHost(id).label).join(', '))}`);

  let port = parseInt(args.port || DEFAULT_PORT, 10);
  // P5: if the chosen port is held by a foreign (non-pacemaker) service, pick another.
  while ((await probePort(port)) === 'foreign') {
    p.log.warn(`Port ${port} is in use by a non-pacemaker service.`);
    const np = await p.text({ message: 'Choose a different bridge port:', initialValue: String(port + 1), validate: (v) => (/^\d+$/.test(v) && +v > 0 && +v < 65536 ? undefined : 'enter a valid port 1-65535') });
    if (p.isCancel(np)) { p.cancel('cancelled'); process.exit(0); }
    port = parseInt(np, 10);
  }

  // Which hosts to wire (default: all detected). --client accepts one id or a comma-separated list.
  let targets;
  if (args.client) targets = args.client.split(',').map((s) => s.trim()).filter(Boolean);
  else if (detected.length <= 1) targets = detected;
  else {
    const picked = await p.multiselect({
      message: `Wire which host(s) to the bridge on :${port}?`,
      options: detected.map((id) => ({ value: id, label: getHost(id).label, hint: getHost(id).kind })),
      initialValues: detected, required: true,
    });
    if (p.isCancel(picked) || !picked.length) { p.cancel('cancelled — nothing changed'); process.exit(0); }
    targets = picked;
  }

  // Import SOURCE: a json host with a config file (where the servers come from).
  const jsonDetected = detected.filter((id) => getHost(id).format === 'json');
  const source = args.from || jsonDetected[0] || (targets || []).find((id) => getHost(id).format === 'json') || detected[0] || 'vscode';
  if (!existsSync(CONFIG) || args.from) {
    const s = p.spinner();
    s.start(`Importing servers from ${source}`);
    let r;
    try { r = importServers(source, args.config); }
    catch (e) { s.stop(pc.red(e.message)); p.outro('Set up a client config first (VS Code / Cursor / Claude), then re-run.'); process.exit(1); }
    s.stop(`Imported ${r.imported} server(s)${r.skipped ? ` (${r.skipped} already bridged)` : ''}`);
    if (r.httpNoAuth) p.log.warn(`${r.httpNoAuth} http server(s) have no auth — add "audience"/"auth" in ~/.mcp-pacemaker/servers.json if needed.`);
  } else {
    p.log.info(`Using existing ${CONFIG}`);
  }
  if (!existsSync(CONFIG)) { p.outro('No servers to wire. Run "mcp-pacemaker import --from vscode" first.'); process.exit(1); }
  if (!targets || !targets.length) { p.outro('No hosts detected. Install an MCP host (VS Code / Cursor / Claude / a CLI) first.'); process.exit(0); }

  p.log.step(`Wiring ${targets.length} host(s) [${targets.join(', ')}] to the bridge on :${port} (a .bak is written per host).`);
  const go = args.yes ? true : await p.confirm({ message: 'Proceed?' });
  if (p.isCancel(go) || !go) { p.cancel('cancelled — nothing changed'); process.exit(0); }

  // Wire each host; autostart + start the single shared bridge once, after.
  for (const id of targets) {
    try { await cmdInstall({ client: id, port, autostart: false, start: false }); }
    catch (e) { p.log.error(`${id}: ${e.message}`); }
  }
  if (args.autostart !== false) { try { registerAutostart(port); p.log.success('registered OS auto-start'); } catch (e) { p.log.warn(`auto-start skipped: ${e.message}`); } }
  if (args.start !== false) await startBridge(port);

  const reload = [...new Set(targets.map((id) => (id === 'vscode' ? 'reload VS Code' : `restart ${getHost(id).label}`)))].join(' · ');
  p.outro(pc.green(`Done. ${reload} to pick up the bridge.\n`) + `  view it:  ${pc.cyan('mcp-pacemaker status')}  ·  ${pc.cyan('mcp-pacemaker top')}  ·  ${pc.cyan('mcp-pacemaker dashboard')}`);
}

/* -------------------------------- upgrade ----------------------------------- */
async function cmdUpgrade(args) {
  if (args.self) {
    const name = readJson(resolve(ROOT, 'package.json')).name;
    info('to update the CLI itself, run whichever matches how you installed it:');
    console.log(`  npm i -g ${name}@latest              # from npm`);
    console.log('  npm i -g github:girishkvs/mcp-pacemaker  # from GitHub');
    console.log('  git -C <your-clone> pull             # from a clone');
    return;
  }
  const state = readState();
  if (!state.hosts.length) { err('no install state — run "init" or "install" first'); process.exit(1); }
  for (const h of state.hosts) {
    info(`re-wiring ${h.id} on :${h.port} from the current servers.json`);
    await cmdInstall({ client: h.id, port: h.port, autostart: false, start: false });
  }
  for (const port of distinctPorts(state)) await startBridge(port);
  ok('upgrade complete.');
}

/* ------------------------------ update-check -------------------------------- */
function fetchNpmLatest(name) {
  return new Promise((res) => {
    const r = https.get(`https://registry.npmjs.org/${encodeURIComponent(name)}`, (resp) => {
      let d = '';
      resp.on('data', (c) => (d += c));
      resp.on('end', () => { try { res(JSON.parse(d)['dist-tags']?.latest || null); } catch { res(null); } });
    });
    r.on('error', () => res(null));
    r.setTimeout(4000, () => { r.destroy(); res(null); });
  });
}
async function cmdUpdateCheck(args) {
  const pkg = readJson(resolve(ROOT, 'package.json'));
  const latest = await fetchNpmLatest(pkg.name);
  const result = { name: pkg.name, current: pkg.version, latest, updateAvailable: !!latest && latest !== pkg.version };
  if (args.json) { console.log(JSON.stringify(result)); return; }
  if (!latest) warn(`could not reach npm for ${pkg.name} (offline, or not published yet)`);
  else if (result.updateAvailable) warn(`update available: ${pkg.version} -> ${latest}  (run "mcp-pacemaker upgrade --self")`);
  else ok(`up to date (${pkg.version})`);
}

/* ------------------------------ start / stop -------------------------------- */
function supervisorInvocation(port) {
  if (platform() === 'win32') {
    return { cmd: 'pwsh', args: ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', resolve(ROOT, 'supervisor', 'supervise.ps1'), '-Port', String(port)] };
  }
  return { cmd: '/bin/sh', args: [resolve(ROOT, 'supervisor', 'supervise.sh'), String(port)] };
}
// P5: is anything listening on the port, and if so is it ours?
function portInUse(port) {
  return new Promise((res) => {
    const sock = net.connect({ host: '127.0.0.1', port }, () => { sock.destroy(); res(true); });
    sock.on('error', () => res(false));
    sock.setTimeout(1000, () => { sock.destroy(); res(false); });
  });
}
async function probePort(port) {
  if (!(await portInUse(port))) return 'free';
  const s = await httpGet(`http://127.0.0.1:${port}/status`);
  if (s) { try { if (JSON.parse(s.body).service === 'mcp-pacemaker') return 'pacemaker'; } catch { /* not ours */ } }
  return 'foreign';
}
async function startBridge(port) {
  // P5: adopt an existing pacemaker bridge; refuse to collide with a foreign service.
  const cls = await probePort(port);
  if (cls === 'pacemaker') { ok(`bridge already running on :${port} — adopted (not starting a second).`); return; }
  if (cls === 'foreign') { err(`port ${port} is held by a non-pacemaker service — not starting. Use --port <free port>, or migrate that service.`); return; }
  const { cmd, args } = supervisorInvocation(port);
  try {
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.unref();
    ok(`started bridge supervisor (port ${port})`);
  } catch (e) { err(`failed to start supervisor: ${e.message}`); }
}
async function stopBridge(port) {
  if (port) {
    if ((await probePort(port)) !== 'pacemaker') { warn(`no pacemaker bridge on :${port}`); return; }
    try {
      if (platform() === 'win32') execFileSync('powershell', ['-NoProfile', '-Command', `Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'supervise\\.ps1.*\\b${port}\\b|mcp-bridge\\.mjs.*\\b${port}\\b' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }; Get-NetTCPConnection -LocalPort ${port} -State Listen -EA SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }`], { stdio: 'ignore' });
      else execSync(`kill $(lsof -ti tcp:${port}) 2>/dev/null || true`, { stdio: 'ignore' });
      ok(`stopped bridge on :${port}`);
    } catch { warn(`could not stop bridge on :${port}`); }
    return;
  }
  try {
    if (platform() === 'win32') {
      execFileSync('powershell', ['-NoProfile', '-Command',
        "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'mcp-bridge.mjs|supervise.ps1' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }"], { stdio: 'ignore' });
    } else {
      try { execFileSync('pkill', ['-f', 'mcp-bridge.mjs'], { stdio: 'ignore' }); } catch { /* none */ }
      try { execFileSync('pkill', ['-f', 'supervise.sh'], { stdio: 'ignore' }); } catch { /* none */ }
    }
    ok('stopped all bridges');
  } catch { warn('no running bridge found'); }
}

// Start one bridge (--port) or all distinct-port bridges recorded in state.
async function cmdStart(opts) {
  const port = opts && opts.port ? parseInt(opts.port, 10) : null;
  if (port) { await startBridge(port); return; }
  const ports = distinctPorts(readState());
  if (!ports.length) { await startBridge(DEFAULT_PORT); return; }
  for (const p2 of ports) await startBridge(p2);
}

/* -------------------------------- autostart --------------------------------- */
const AUTOSTART_ID = 'io.github.girishkvs.mcp-pacemaker';
function registerAutostart(port) {
  const plat = platform();
  const { cmd, args } = supervisorInvocation(port);
  if (plat === 'win32') {
    execFileSync('pwsh', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', resolve(ROOT, 'autostart', 'windows', 'register-task.ps1'), '-Port', String(port), '-TaskName', `McpPacemaker-${port}`], { stdio: 'ignore' });
    return;
  }
  if (plat === 'darwin') {
    const plistPath = join(homedir(), 'Library', 'LaunchAgents', `${AUTOSTART_ID}.${port}.plist`);
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${AUTOSTART_ID}.${port}</string>
  <key>ProgramArguments</key><array>${[cmd, ...args].map((a) => `<string>${a}</string>`).join('')}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict></plist>\n`;
    mkdirSync(dirname(plistPath), { recursive: true });
    writeFileSync(plistPath, plist);
    try { execFileSync('launchctl', ['unload', plistPath], { stdio: 'ignore' }); } catch { /* first time */ }
    execFileSync('launchctl', ['load', plistPath], { stdio: 'ignore' });
    return;
  }
  // linux (systemd --user)
  const unitPath = join(homedir(), '.config', 'systemd', 'user', `mcp-pacemaker-${port}.service`);
  const unit = `[Unit]
Description=mcp-pacemaker bridge supervisor
After=default.target

[Service]
Type=simple
ExecStart=${cmd} ${args.join(' ')}
Restart=on-failure

[Install]
WantedBy=default.target
`;
  mkdirSync(dirname(unitPath), { recursive: true });
  writeFileSync(unitPath, unit);
  execFileSync('systemctl', ['--user', 'daemon-reload'], { stdio: 'ignore' });
  execFileSync('systemctl', ['--user', 'enable', '--now', `mcp-pacemaker-${port}.service`], { stdio: 'ignore' });
}
function unregisterAutostart(port) {
  const plat = platform();
  const ports = port ? [port] : distinctPorts(readState());
  let removed = 0;
  for (const pt of (ports.length ? ports : [DEFAULT_PORT])) {
    try {
      if (plat === 'win32') execFileSync('schtasks', ['/Delete', '/TN', `McpPacemaker-${pt}`, '/F'], { stdio: 'ignore' });
      else if (plat === 'darwin') { const pth = join(homedir(), 'Library', 'LaunchAgents', `${AUTOSTART_ID}.${pt}.plist`); execFileSync('launchctl', ['unload', pth], { stdio: 'ignore' }); }
      else execFileSync('systemctl', ['--user', 'disable', '--now', `mcp-pacemaker-${pt}.service`], { stdio: 'ignore' });
      removed++;
    } catch { /* not present */ }
  }
  try { if (plat === 'win32') execFileSync('schtasks', ['/Delete', '/TN', 'McpPacemaker', '/F'], { stdio: 'ignore' }); } catch { /* legacy none */ }
  if (removed) ok(`removed OS auto-start (${removed})`); else warn('no auto-start entry found');
}

/* --------------------------------- status ----------------------------------- */
function httpGet(url) {
  return new Promise((res) => {
    const r = http.get(url, (resp) => { let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, body: d })); });
    r.on('error', () => res(null));
    r.setTimeout(2000, () => { r.destroy(); res(null); });
  });
}
async function cmdStatus() {
  const state = readState();
  const ports = state.hosts.length ? distinctPorts(state) : [DEFAULT_PORT];
  for (const port of ports) {
    const s = await httpGet(`http://127.0.0.1:${port}/status`);
    if (s && s.status === 200) {
      let j = null; try { j = JSON.parse(s.body); } catch { /* noop */ }
      if (j && j.service === 'mcp-pacemaker') {
        ok(`bridge UP on :${port} — ${j.servers.length} server(s), ${j.sessions} active session(s)`);
        const api = await httpGet(`http://127.0.0.1:${port}/api/status`);
        if (api && api.status === 200) {
          try {
            const snap = JSON.parse(api.body);
            const list = snap.servers;
            if (snap.restart && snap.restart.staleClients > 0) {
              warn(`  bridge restarted ${Math.round(snap.restart.sinceSec / 60)}m ago — ${snap.restart.staleClients} client(s) have not reconnected; they may need an MCP reload`);
            }
            const failing = list.filter((sv) => sv.health && sv.health.state === 'failing');
            for (const sv of failing) err(`    ${sv.name}: failing — ${sv.health.consecutiveFailures} in a row: ${sv.lastError}`);
            for (const sv of list) { if (sv.sessions || (sv.clients && sv.clients.length)) info(`    ${sv.name}: ${sv.sessions} session(s)${sv.clients && sv.clients.length ? `  agents=[${sv.clients.join(', ')}]` : ''}`); }
          } catch { /* noop */ }
        }
      } else warn(`:${port} responds but is NOT an mcp-pacemaker bridge (foreign service)`);
    } else err(`bridge DOWN on :${port}  (start with "mcp-pacemaker start")`);
    for (const h of state.hosts.filter((x) => x.port === port)) info(`  ${h.id} · ${h.servers.length} server(s) · ${h.path}`);
  }
  if (!state.hosts.length) warn('no install state — run "mcp-pacemaker install"');
}

/* --------------------------------- reload ----------------------------------- */
function httpPost(url, nonce) {
  return new Promise((res) => {
    const u = new URL(url);
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: { 'x-mcp-nonce': nonce } },
      (resp) => { let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, body: d })); });
    r.on('error', () => res(null));
    r.setTimeout(5000, () => { r.destroy(); res(null); });
    r.end();
  });
}

async function cmdReload(opts) {
  const port = opts.port ? parseInt(opts.port, 10) : (readState().hosts.length ? distinctPorts(readState())[0] : DEFAULT_PORT);
  const noncePath = join(dirname(CONFIG), 'admin.nonce');
  let nonce;
  try { nonce = readFileSync(noncePath, 'utf8').trim(); }
  catch { err(`no admin nonce at ${noncePath} — is the bridge running?`); process.exit(1); }

  const r = await httpPost(`http://127.0.0.1:${port}/admin/reload`, nonce);
  if (!r) { err(`bridge DOWN on :${port}  (start with "mcp-pacemaker start")`); process.exit(1); }
  let j = null; try { j = JSON.parse(r.body); } catch { /* noop */ }
  if (r.status !== 200 || !j || !j.ok) { err(`reload rejected: ${(j && j.error) || r.body || r.status} — the bridge kept its previous config`); process.exit(1); }
  if (j.unchanged) { ok(`${CONFIG} re-read on :${port} — no changes`); return; }
  ok(`reloaded ${CONFIG} on :${port}`);
  if (j.added.length) info(`  added:   ${j.added.join(', ')}`);
  if (j.removed.length) info(`  removed: ${j.removed.join(', ')}`);
  if (j.changed.length) info(`  changed: ${j.changed.join(', ')}`);
  if (!j.added.length && !j.removed.length && !j.changed.length) info('  no server definitions changed');
  else info(`  ${j.restarted} session(s) restarted; untouched servers kept theirs`);
}

/* --------------------------------- doctor ----------------------------------- */
async function cmdDoctor() {
  let fails = 0;
  const major = parseInt(process.versions.node.split('.')[0], 10);
  if (major >= 20) ok(`Node.js ${process.versions.node}`); else { err(`Node.js ${process.versions.node} (need >= 20)`); fails++; }

  let servers = {};
  if (!existsSync(CONFIG)) warn(`no ${CONFIG} — run "import" then "install"`);
  else {
    try { servers = readJson(CONFIG); ok(`config valid: ${Object.keys(servers).length} server(s)`); }
    catch (e) { err(`config invalid JSON: ${e.message}`); fails++; }
    for (const [n, d] of Object.entries(servers)) {
      const reserved = checkReservedName(n);
      if (reserved) { err(`  ${n}: ${reserved.detail}`); fails++; continue; }
      if (!d.command && !d.url) { err(`  ${n}: missing "command" or "url"`); fails++; continue; }
      if (d.type === 'http' && !d.auth && !d.audience && !d.headers) { warn(`  ${n}: http server with no auth/headers`); continue; }
      const pathCheck = checkServerPaths(n, d, HOME);
      if (pathCheck?.status === 'bad') { err(`  ${n}: ${pathCheck.detail}`); fails++; }
      else if (pathCheck) warn(`  ${n}: ${pathCheck.detail}`);
    }
  }

  const state = readState();
  const ports = state.hosts.length ? distinctPorts(state) : [DEFAULT_PORT];
  for (const port of ports) {
    const s = await httpGet(`http://127.0.0.1:${port}/status`);
    if (s && s.status === 200) {
      let svc = null; try { svc = JSON.parse(s.body).service; } catch { /* noop */ }
      if (svc === 'mcp-pacemaker') {
        ok(`bridge reachable on :${port} (mcp-pacemaker)`);
        const api = await httpGet(`http://127.0.0.1:${port}/api/status`);
        if (api && api.status === 200) {
          try {
            const snap = JSON.parse(api.body);
            const agents = [...new Set(snap.servers.flatMap((sv) => sv.clients || []))];
            if (agents.length) info(`    connected agents: ${agents.join(', ')}`);
            // Cold start is invisible to the person paying for it: they experience "this tool is
            // slow", not "spawning costs 20s". Naming the number and the exact config that would
            // fix it is the whole point of measuring — but enabling it is theirs to decide.
            for (const sv of snap.servers) {
              if (!sv.advice) continue;
              warn(`  ${sv.name}: ${sv.advice.reason}${sv.peakConcurrency ? `, peak ${sv.peakConcurrency} concurrent` : ''}`);
              info(`    consider: "sharing": "pool", "minWarm": ${sv.advice.suggest.minWarm}  (in ${CONFIG})`);
            }
          } catch { /* noop */ }
        }
      }
      else warn(`:${port} responds but is NOT an mcp-pacemaker bridge (foreign service)`);
    } else warn(`bridge not reachable on :${port} (start with "mcp-pacemaker start")`);
  }
  for (const h of state.hosts) {
    const host = getHost(h.id);
    if (host.format === 'native') { ok(`${h.id} wired via ${host.bin} mcp (${h.servers.length} server(s) -> :${h.port})`); continue; }
    if (!h.path || !existsSync(h.path)) { warn(`${h.id}: config not found (${h.path})`); continue; }
    let wired = 0;
    if (host.format === 'toml') {
      try { const t = parseToml(readFileSync(h.path, 'utf8')); wired = Object.values(t.mcp_servers || {}).filter((v) => /127\.0\.0\.1/.test(v.url || '')).length; } catch { /* parse error */ }
    } else {
      const cfg = readJson(h.path);
      wired = Object.values(cfg[clientServersKey(h.id)] || {}).filter((v) => /127\.0\.0\.1/.test(v.url || v.httpUrl || '')).length;
    }
    if (wired > 0) ok(`${h.id} wired (${wired} server(s) -> :${h.port})`); else warn(`${h.id} not wired to bridge`);
  }
  if (!state.hosts.length) warn('no install state — run "install"');

  if (fails) console.log(pc.red(`\n${fails} problem(s) found${warnCount ? `, ${warnCount} warning(s)` : ''}.`));
  else if (warnCount) console.log(pc.yellow(`\n${warnCount} warning(s) — no hard failures.`));
  else console.log(pc.green('\nall good.'));
  if (fails) process.exit(1);
}

/* ---------------------------------- emit ------------------------------------ */
function cmdEmit(args) {
  const client = defaultClient(args.client);
  const host = getHost(client);
  const port = parseInt(args.port || DEFAULT_PORT, 10);
  if (!existsSync(CONFIG)) { err(`no ${CONFIG} — run "import" first`); process.exit(1); }
  const servers = readJson(CONFIG);
  if (host.format === 'toml') { console.log(buildCodexConfig(port).text); return; }
  if (host.format === 'native') {
    for (const [name, def] of Object.entries(servers)) console.log(`${host.bin} mcp add --scope user --transport http ${name} ${claudeUrl(name, def, port)}`);
    return;
  }
  const out = { [clientServersKey(client)]: {} };
  for (const [name, def] of Object.entries(servers)) out[clientServersKey(client)][name] = hostEntry(client, name, def, port);
  console.log(JSON.stringify(out, null, 2));
}

/* ------------------------------- uninstall ---------------------------------- */
async function cmdUninstall() {
  await stopBridge();
  unregisterAutostart();
  const state = readState();
  for (const h of state.hosts) {
    if (!h.path || h.path.startsWith('native')) continue;
    const bak = h.path + '.bak';
    if (existsSync(bak)) { copyFileSync(bak, h.path); ok(`restored ${h.id} config (${h.path}) from backup`); }
    else warn(`no backup at ${bak} — left ${h.id} config as-is`);
  }
  info('kept ~/.mcp-pacemaker/servers.json (delete it manually if you want a clean slate).');
}

/* -------------------------------- dashboard --------------------------------- */
function cmdDashboard() {
  const state = readState();
  const port = state.hosts[0]?.port || DEFAULT_PORT;
  const url = `http://127.0.0.1:${port}/ui`;
  info(`opening ${url}`);
  try {
    const plat = platform();
    if (plat === 'win32') spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
    else if (plat === 'darwin') spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    else spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
  } catch (e) { warn(`could not open browser: ${e.message}. Visit ${url} manually.`); }
}

/* ---------------------------------- main (commander) ------------------------ */
const pkgVersion = (() => { try { return readJson(resolve(ROOT, 'package.json')).version; } catch { return '0.0.0'; } })();
const program = new Command();
program
  .name('mcp-pacemaker')
  .description('Keep your MCP servers alive across editor restarts, reboots, and token expiry.')
  .version(pkgVersion);

program.command('init')
  .description('Interactive setup: detect all MCP hosts (editors + CLIs), import, wire, autostart, start')
  .option('--client <client>', 'wire only this host, or a comma-separated list (default: all detected)')
  .option('--from <host>', 'source host to import servers.json from')
  .option('--port <n>', 'bridge port', String(DEFAULT_PORT))
  .option('--config <path>', 'source client config to import from')
  .option('-y, --yes', 'skip the confirmation prompt (non-interactive)')
  .option('--no-autostart', 'do not register OS auto-start')
  .option('--no-start', 'do not start the bridge')
  .action(cmdInit);

program.command('import')
  .description('Build ~/.mcp-pacemaker/servers.json from an existing host config')
  .option('--from <client>', 'source host: vscode|cursor|claude|copilot-cli|gemini')
  .option('--config <path>', 'source client config path')
  .action(cmdImport);

program.command('plan')
  .description('Dry-run: show what install would change in a host config')
  .option('--client <client>', 'host id (vscode|cursor|claude|copilot-cli|gemini|codex|claude-code)')
  .option('--port <n>', 'bridge port', String(DEFAULT_PORT))
  .action(cmdPlan);

program.command('install')
  .description('Back up + wire a host -> bridge, register auto-start, start the bridge')
  .option('--client <client>', 'host id (vscode|cursor|claude|copilot-cli|gemini|codex|claude-code)')
  .option('--port <n>', 'bridge port', String(DEFAULT_PORT))
  .option('--no-autostart', 'do not register OS auto-start')
  .option('--no-start', 'do not start the bridge')
  .action(cmdInstall);

program.command('status').description('Is the bridge up? what is installed?').action(cmdStatus);
program.command('reload')
  .description('Re-read servers.json into the running bridge (no restart, untouched servers keep their sessions)')
  .option('--port <n>', 'bridge port')
  .action(cmdReload);
program.command('doctor').description('Diagnose config, bridge reachability, client wiring').action(cmdDoctor);
program.command('dashboard').description('Open the web dashboard in your browser').action(cmdDashboard);
program.command('top')
  .description('Live terminal dashboard (Ink TUI)')
  .option('--port <n>', 'bridge port')
  .action(async (opts) => { const { runTop } = await import('./top.mjs'); runTop(opts.port ? parseInt(opts.port, 10) : undefined); });

program.command('emit')
  .description('Print host-config entries pointing at the bridge (no write)')
  .option('--client <client>', 'host id (vscode|cursor|claude|copilot-cli|gemini|codex|claude-code)')
  .option('--port <n>', 'bridge port', String(DEFAULT_PORT))
  .action(cmdEmit);

program.command('upgrade')
  .description('Re-wire client from servers.json; --self shows how to update the CLI')
  .option('--self', 'show how to update the CLI itself')
  .action(cmdUpgrade);

program.command('update-check')
  .description('Check npm for a newer version')
  .option('--json', 'machine-readable output')
  .action(cmdUpdateCheck);

program.command('start')
  .description('Start bridge(s): --port for one, else all wired bridges from state')
  .option('--port <n>', 'specific bridge port')
  .action(cmdStart);

program.command('stop')
  .description('Stop bridge(s): --port for one, else all')
  .option('--port <n>', 'specific bridge port')
  .action((opts) => stopBridge(opts.port ? parseInt(opts.port, 10) : undefined));
program.command('uninstall').description('Stop bridge, remove auto-start, restore client config').action(cmdUninstall);

// Bare `mcp-pacemaker`: show status if installed, else run the setup wizard.
program.action(() => (existsSync(STATE) ? cmdStatus() : cmdInit({})));

program.parseAsync(process.argv).catch((e) => { err(e.message); process.exit(1); });
