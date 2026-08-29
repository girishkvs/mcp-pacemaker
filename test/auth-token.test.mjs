// Regression tests for command-based auth, covering two failures seen in production on the
// bridge this project replaces:
//
//   1. An auth command can exit 0 and print nothing. Caching that empty value served an empty
//      credential for the whole TTL, so every upstream request 401'd until it expired.
//   2. On startup every server asks for its token at once. Without de-duplication each one
//      spawns its own `az`, and those concurrent calls are what make az return nothing.
import { test } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

// Ports are assigned per test file to avoid collisions under the parallel suite:
// 8801-8803 bridge-controls, 8804-8805 kill-tree, 8806 keepalive, 8807 cross-host,
// 8808-8809 tui, 8810-8811 and 8820-8823 here, 8830 config-checks.
const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(__dirname, '..', 'bin', 'mcp-bridge.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const req = (port, method, path, { headers = {}, body } = {}) =>
  new Promise((res, rej) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (resp) => {
      let d = ''; resp.on('data', (c) => (d += c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: d }));
    });
    r.on('error', rej); if (body) r.write(body); r.end();
  });

// Upstream that records the Authorization header of every request it receives.
async function startUpstream(seen) {
  const srv = http.createServer((rq, rs) => {
    seen.push(rq.headers.authorization ?? null);
    rs.writeHead(200, { 'content-type': 'application/json' });
    rs.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, port: srv.address().port };
}

async function bootBridge(port, config, env) {
  const tmp = mkdtempSync(join(tmpdir(), 'mcpka-auth-'));
  const cfg = join(tmp, 'servers.json');
  writeFileSync(cfg, JSON.stringify(config));
  const child = spawn(process.execPath, [BRIDGE, '--port', String(port), '--config', cfg],
    { stdio: 'ignore', env: { ...process.env, ...env } });
  for (let i = 0; i < 60; i++) {
    try { const s = await req(port, 'GET', '/status'); if (s.status === 200) return { child, tmp }; } catch { /* wait */ }
    await sleep(100);
  }
  child.kill();
  throw new Error(`bridge on ${port} did not start`);
}

// An auth command that records each invocation in `tally`, then prints `output`
// ("-" means print nothing, reproducing an auth tool that exits 0 with no token).
// Starts with a bare command, like the real `az ...` configs: a command whose first character
// is a quote hits cmd.exe's quote-stripping rule and fails to launch.
const AUTH_FIXTURE = resolve(__dirname, 'fixtures', 'tally-auth-command.mjs');
const authCommand = (tally, output) =>
  `node "${AUTH_FIXTURE}" "${tally}" "${output}"`;

const rpc = { 'content-type': 'application/json' };
const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });

test('an empty auth command result is never cached and never sent as a credential', async (t) => {
  const seen = [];
  const up = await startUpstream(seen);
  const tally = join(mkdtempSync(join(tmpdir(), 'mcpka-tally-')), 'calls');
  const port = 8810;
  const { child } = await bootBridge(port, {
    up: { type: 'http', url: `http://127.0.0.1:${up.port}/`, auth: { type: 'command', command: authCommand(tally, '-') } },
  });
  t.after(() => { child.kill(); up.srv.close(); });

  const r = await req(port, 'POST', '/up', { headers: rpc, body });
  assert.notEqual(r.status, 200, 'request must fail rather than proceed without a credential');
  assert.deepEqual(seen, [], 'upstream must not receive a request carrying an empty credential');

  // A second attempt must retry the command rather than serve a cached empty value.
  await req(port, 'POST', '/up', { headers: rpc, body });
  const calls = existsSync(tally) ? readFileSync(tally, 'utf8').length : 0;
  assert.ok(calls >= 2, `empty result must not be cached (auth command ran ${calls} time(s))`);
});

test('a cached credential is renewed before it expires, without waiting for a request', async (t) => {
  const seen = [];
  const up = await startUpstream(seen);
  const tally = join(mkdtempSync(join(tmpdir(), 'mcpka-tally-')), 'calls');
  const port = 8820;
  const { child } = await bootBridge(port, {
    up: {
      type: 'http', url: `http://127.0.0.1:${up.port}/`,
      // Expires ~6s after minting; refresh once within 5s of expiry, so renewal is due ~1s in.
      auth: { type: 'command', command: authCommand(tally, 'tok-123'), refreshMinutes: 0.1 },
    },
  }, { MCP_TOKEN_REFRESH_LEAD_MS: '5000' });
  t.after(() => { child.kill(); up.srv.close(); });

  await req(port, 'POST', '/up', { headers: rpc, body });
  assert.equal(readFileSync(tally, 'utf8').length, 1, 'minted once for the first request');

  // No further traffic: the bridge must renew on its own.
  for (let i = 0; i < 40 && readFileSync(tally, 'utf8').length < 2; i++) await sleep(500);

  assert.ok(readFileSync(tally, 'utf8').length >= 2,
    'the credential should be renewed proactively, not on the next request');
});

// A client authenticating against the bridge derives its OAuth discovery URL from the bridge's
// own origin, so the bridge must answer /.well-known/... for a proxied server. Without this the
// client fails at "could not discover authorization server metadata" and never reaches a login.
//
// RFC 9728 also requires the client to check the document's `resource` field against the URL it
// is addressing. Relaying the upstream's own identifier there fails that check, so the bridge
// rewrites it to its own URL for the server. `authorization_servers` is left alone, because that
// is what determines the audience of the token the client ends up with.
test('OAuth discovery for a proxied server is served from the bridge origin', async (t) => {
  const seen = [];
  const metadata = { resource: 'https://upstream.example', authorization_servers: ['https://login.example/v2.0'] };
  const srv = http.createServer((rq, rs) => {
    seen.push(rq.url);
    if (rq.url.startsWith('/.well-known/oauth-protected-resource')) {
      rs.writeHead(200, { 'content-type': 'application/json' });
      rs.end(JSON.stringify(metadata));
      return;
    }
    // Everything else demands a token, the way a protected MCP endpoint does.
    rs.writeHead(401, { 'www-authenticate': 'Bearer resource_metadata="https://upstream.example/.well-known/oauth-protected-resource/"' });
    rs.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const upPort = srv.address().port;

  const port = 8821;
  const { child } = await bootBridge(port, {
    guarded: { type: 'http', url: `http://127.0.0.1:${upPort}/`, auth: { type: 'none' } },
  });
  t.after(() => { child.kill(); srv.close(); });

  const disco = await req(port, 'GET', '/.well-known/oauth-protected-resource/guarded');
  assert.equal(disco.status, 200, 'the bridge must answer discovery for a proxied server');
  const doc = JSON.parse(disco.body);
  assert.equal(doc.resource, `http://127.0.0.1:${port}/guarded`,
    'resource must name the bridge URL the client is addressing, or the client rejects the document');
  assert.deepEqual(doc.authorization_servers, metadata.authorization_servers,
    'the authorization server is relayed untouched, so the token keeps the audience the upstream expects');

  // The challenge must reach the client too, so it knows authentication is required at all,
  // and it must point at the bridge's copy of the metadata rather than the upstream's.
  const denied = await req(port, 'POST', '/guarded', { headers: rpc, body });
  assert.equal(denied.status, 401, 'the upstream challenge is relayed');
  assert.match(String(denied.headers['www-authenticate']),
    new RegExp(`resource_metadata="http://127\\.0\\.0\\.1:${port}/\\.well-known/oauth-protected-resource/guarded"`),
    'the challenge must redirect the client to the bridge metadata, the only copy with a matching resource');

  // And once the client has a token, the bridge forwards it rather than swallowing it.
  await req(port, 'POST', '/guarded', { headers: { ...rpc, authorization: 'Bearer client-token' }, body });
  assert.ok(seen.length >= 3, 'requests reached the upstream');
});

// Hop-by-hop headers are connection-scoped and must not cross a proxy (RFC 9110 section 7.6.1).
// The upstream below names `x-upstream-hop` in its own `Connection` header, which makes that
// header hop-by-hop for this message, and sends `trailer`, which is hop-by-hop always. A proxy
// that copies upstream response headers verbatim leaks both to the client.
//
// This is deliberately not asserted as body corruption. Node sets `chunkedEncoding` from a
// manually supplied `transfer-encoding`, so it does not double-encode, and a body-only assertion
// therefore passes with the stripping removed and proves nothing. The observable, reproducible
// effect of the fix is which headers reach the client, so that is what is asserted here. The
// streamed SSE body is checked alongside only to show stripping does not disturb the reply.
test('hop-by-hop response headers are not relayed to the client', async (t) => {
  const srv = http.createServer((rq, rs) => {
    rs.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive, x-upstream-hop',
      'x-upstream-hop': 'leaked',
      trailer: 'x-checksum',
      'x-passthrough': 'kept',
    });
    rs.write('event: message\n');
    rs.write(`data: ${JSON.stringify({ jsonrpc: '2.0', id: 1, result: { serverInfo: { name: 'streamed' } } })}\n\n`);
    rs.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const upPort = srv.address().port;

  const port = 8823;
  const { child } = await bootBridge(port, {
    streamed: { type: 'http', url: `http://127.0.0.1:${upPort}/`, auth: { type: 'none' } },
  });
  t.after(() => { child.kill(); srv.close(); });

  const r = await req(port, 'POST', '/streamed', { headers: rpc, body });
  assert.equal(r.status, 200);
  assert.equal(r.headers['x-upstream-hop'], undefined, 'a header named in the upstream Connection header must not reach the client');
  assert.equal(r.headers.trailer, undefined, 'trailer is hop-by-hop and must not be relayed');
  assert.equal(r.headers['x-passthrough'], 'kept', 'ordinary end-to-end headers are still relayed');
  const payload = JSON.parse((r.body.match(/data: (.*)/) || [])[1]);
  assert.equal(payload.result.serverInfo.name, 'streamed', 'the streamed reply arrives complete and parseable');
});

test('concurrent first-use mints the token once, not once per caller', async (t) => {
  const seen = [];
  const up = await startUpstream(seen);
  const tally = join(mkdtempSync(join(tmpdir(), 'mcpka-tally-')), 'calls');
  const port = 8811;
  const auth = { type: 'command', command: authCommand(tally, 'tok-123') };
  const { child } = await bootBridge(port, {
    a: { type: 'http', url: `http://127.0.0.1:${up.port}/`, auth },
    b: { type: 'http', url: `http://127.0.0.1:${up.port}/`, auth },
    c: { type: 'http', url: `http://127.0.0.1:${up.port}/`, auth },
  });
  t.after(() => { child.kill(); up.srv.close(); });

  await Promise.all(['a', 'b', 'c'].map((n) => req(port, 'POST', `/${n}`, { headers: rpc, body })));

  const calls = readFileSync(tally, 'utf8').length;
  assert.equal(calls, 1, `auth command should run once for three concurrent callers (ran ${calls})`);
  assert.deepEqual(seen, ['Bearer tok-123', 'Bearer tok-123', 'Bearer tok-123']);
});
