#!/usr/bin/env node
/**
 * mcp-pacemaker top — live terminal dashboard (Ink). Same data as the web /ui.
 * Reads the bridge port from ~/.mcp-pacemaker/state.json (or --port) and the admin
 * nonce from ~/.mcp-pacemaker/admin.nonce for the Recycle keybind. No JSX (uses createElement).
 */
import { createElement as h, useState, useEffect } from 'react';
import { render, Box, Text, useApp, useInput } from 'ink';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { homedir } from 'node:os';

const HOME = resolve(homedir(), '.mcp-pacemaker');

export function fetchSnapshot(port) {
  return new Promise((res) => {
    const r = http.get({ host: '127.0.0.1', port, path: '/api/status', timeout: 2000 }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => { try { res(JSON.parse(d)); } catch { res(null); } });
    });
    r.on('error', () => res(null));
    r.on('timeout', () => { r.destroy(); res(null); });
  });
}

export function recycleServer(port, name, nonce) {
  return new Promise((res) => {
    const r = http.request({ host: '127.0.0.1', port, path: `/admin/recycle/${encodeURIComponent(name)}`, method: 'POST', headers: { 'x-mcp-nonce': nonce }, timeout: 3000 }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => { let body = null; try { body = JSON.parse(d || 'null'); } catch { /* noop */ } res({ status: resp.statusCode, body }); });
    });
    r.on('error', () => res(null));
    r.on('timeout', () => { r.destroy(); res(null); });
    r.end();
  });
}

const readNonce = () => { try { return readFileSync(resolve(HOME, 'admin.nonce'), 'utf8').trim(); } catch { return ''; } };
// Pure: pick the bridge port from a parsed state object (list shape wins, legacy {port} fallback).
export function portFromState(state) {
  if (state && Array.isArray(state.hosts)) return state.hosts[0]?.port || 8791;
  return (state && state.port) || 8791;
}
function resolvePort(port) {
  if (port) return port;
  try { return portFromState(JSON.parse(readFileSync(resolve(HOME, 'state.json'), 'utf8'))); } catch { return 8791; }
}

const pad = (s, n) => { s = String(s ?? ''); return s.length >= n ? s.slice(0, n - 1) + ' ' : s.padEnd(n); };
const fmtTok = (sec) => (sec == null ? '-' : sec <= 0 ? 'exp' : `${Math.round(sec / 60)}m`);

function App({ port }) {
  const { exit } = useApp();
  const [snap, setSnap] = useState(null);
  const [sel, setSel] = useState(0);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    let alive = true;
    const tick = async () => { const s = await fetchSnapshot(port); if (alive) setSnap(s); };
    tick();
    const t = setInterval(tick, 1500);
    return () => { alive = false; clearInterval(t); };
  }, [port]);

  const servers = snap?.servers ?? [];

  useInput((input, key) => {
    if (input === 'q' || (key.ctrl && input === 'c')) return exit();
    if (key.upArrow) setSel((i) => Math.max(0, i - 1));
    else if (key.downArrow) setSel((i) => Math.min(Math.max(0, servers.length - 1), i + 1));
    else if (input === 'r') {
      const s = servers[sel];
      if (!s) return;
      if (s.type === 'http') { setMsg('http servers have no child to recycle'); return; }
      setMsg(`recycling ${s.name}…`);
      recycleServer(port, s.name, readNonce()).then((r) =>
        setMsg(r && r.status === 200 ? `recycled ${s.name} (${r.body?.recycled ?? 0})` : `recycle failed (${r?.status ?? 'no nonce/bridge'})`),
      );
    }
  });

  return h(
    Box,
    { flexDirection: 'column', padding: 1 },
    h(
      Box,
      { justifyContent: 'space-between' },
      h(Text, { bold: true, color: 'cyan' }, '🫀 mcp-pacemaker top'),
      h(Text, { color: snap ? 'green' : 'red' }, snap ? `● :${snap.port} · up ${snap.uptimeSec}s · v${snap.version}` : '● connecting…'),
    ),
    h(Text, { dimColor: true }, pad('SERVER', 18) + pad('TYPE', 7) + pad('SESS', 6) + pad('WARM', 6) + pad('REQ', 7) + pad('PID', 10) + pad('TOKEN', 8) + 'ERROR / CLIENTS'),
    servers.length === 0
      ? h(Text, { dimColor: true }, snap ? 'no servers configured' : 'connecting…')
      : servers.map((s, i) =>
          h(
            Text,
            { key: s.name, inverse: i === sel, color: s.lastError ? 'red' : undefined },
            pad(s.name, 18) + pad(s.type, 7) + pad(s.sessions, 6) + pad(s.sharing === 'pool' ? `${s.warm}/${s.minWarm ?? 1}` : '-', 6) + pad(s.requests, 7) + pad(s.pids.join(',') || '-', 10) + pad(fmtTok(s.tokenExpiresIn), 8) + (s.lastError ? String(s.lastError).slice(0, 24) : (s.clients && s.clients.length ? '\u21c4 ' + s.clients.join(',') : '')),
          ),
        ),
    h(Text, { dimColor: true }, `↑↓ select · r recycle · q quit   ${msg}`),
  );
}

export function runTop(port) {
  render(h(App, { port: resolvePort(port) }));
}
