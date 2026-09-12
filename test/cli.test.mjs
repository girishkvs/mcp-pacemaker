// Host-adapter + TOML tests. Black-box: run `cli.mjs emit --client <host>` against a temp HOME
// with a known servers.json and assert the wired-entry shape each host gets. No bridge, no network.
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, '..', 'bin', 'cli.mjs');
const PORT = '9123';

function emit(client) {
  const home = mkdtempSync(join(tmpdir(), 'mcpka-home-'));
  mkdirSync(join(home, '.mcp-pacemaker'), { recursive: true });
  writeFileSync(join(home, '.mcp-pacemaker', 'servers.json'), JSON.stringify({
    s1: { command: 'node', args: ['x.mjs'] },            // stdio server
    h1: { type: 'http', url: 'https://api.example.com/mcp' }, // http server
  }));
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  return execFileSync(process.execPath, [CLI, 'emit', '--client', client, '--port', PORT], { env, encoding: 'utf8' });
}

test('vscode: stdio -> streamable http (/mcp), http -> proxy, under "servers"', () => {
  const out = JSON.parse(emit('vscode'));
  assert.deepEqual(out.servers.s1, { type: 'http', url: `http://127.0.0.1:${PORT}/s1/mcp` });
  assert.deepEqual(out.servers.h1, { type: 'http', url: `http://127.0.0.1:${PORT}/h1` });
});

test('cursor: stdio -> sse (classic), http -> proxy', () => {
  const out = JSON.parse(emit('cursor'));
  assert.deepEqual(out.mcpServers.s1, { type: 'sse', url: `http://127.0.0.1:${PORT}/s1/sse` });
  assert.deepEqual(out.mcpServers.h1, { type: 'http', url: `http://127.0.0.1:${PORT}/h1` });
});

test('copilot-cli: stdio -> streamable http (/mcp), under "mcpServers"', () => {
  const out = JSON.parse(emit('copilot-cli'));
  assert.deepEqual(out.mcpServers.s1, { type: 'http', url: `http://127.0.0.1:${PORT}/s1/mcp` });
  assert.deepEqual(out.mcpServers.h1, { type: 'http', url: `http://127.0.0.1:${PORT}/h1` });
});

test('gemini: httpUrl key, under "mcpServers"', () => {
  const out = JSON.parse(emit('gemini'));
  assert.deepEqual(out.mcpServers.s1, { httpUrl: `http://127.0.0.1:${PORT}/s1/mcp` });
  assert.deepEqual(out.mcpServers.h1, { httpUrl: `http://127.0.0.1:${PORT}/h1` });
});

test('codex: valid TOML [mcp_servers.*] tables with streamable http url', () => {
  const out = emit('codex');
  assert.match(out, /\[mcp_servers\.s1\]/);
  assert.match(out, new RegExp(`url = "http://127\\.0\\.0\\.1:${PORT}/s1/mcp"`));
  assert.match(out, /\[mcp_servers\.h1\]/);
  assert.match(out, new RegExp(`url = "http://127\\.0\\.0\\.1:${PORT}/h1"`));
});

for (const { name, input, expected } of [
  { name: 'unclosed array', input: 'a=[1 #' },
  { name: 'unclosed inline table', input: 'a={ b=1 #' },
  { name: 'valid array', input: 'a=[1] #', expected: { a: [1] } },
  { name: 'valid inline table', input: 'a={ b=1 } #', expected: { a: { b: 1 } } },
]) {
  test(`codex parser: ${name} with an EOF comment does not hang`, () => {
    const script = "import { parse } from 'smol-toml'; process.stdout.write(JSON.stringify(parse(process.argv[1])));";
    // Keep a regressed parser from hanging the test runner (CVE-2026-85730).
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script, input], {
      cwd: resolve(__dirname, '..'), encoding: 'utf8', timeout: 5000,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    if (expected) {
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), expected);
    } else {
      assert.equal(result.status, 1);
      assert.match(result.stderr, /TomlError/);
    }
  });
}

test('claude-code: native `claude mcp add` commands', () => {
  const out = emit('claude-code');
  assert.match(out, new RegExp(`claude mcp add --scope user --transport http s1 http://127\\.0\\.0\\.1:${PORT}/s1/mcp`));
  assert.match(out, new RegExp(`claude mcp add --scope user --transport http h1 http://127\\.0\\.0\\.1:${PORT}/h1`));
});

// A host may already list a bridged server under a different key (VS Code's registry-style
// "io.github.Owner/name" is the common case). Rewiring must update that key in place rather
// than adding a second entry, which would double-register the server and its tools.
test('plan: reconciles an aliased key instead of adding a duplicate', () => {
  const home = mkdtempSync(join(tmpdir(), 'mcpka-home-'));
  mkdirSync(join(home, '.mcp-pacemaker'), { recursive: true });
  mkdirSync(join(home, '.copilot'), { recursive: true });
  writeFileSync(join(home, '.mcp-pacemaker', 'servers.json'), JSON.stringify({
    s1: { command: 'node', args: ['x.mjs'] },
  }));
  writeFileSync(join(home, '.copilot', 'mcp-config.json'), JSON.stringify({
    mcpServers: { 's1-mcp': { type: 'sse', url: 'http://127.0.0.1:8791/s1/sse' } },
  }));
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  const out = execFileSync(process.execPath, [CLI, 'plan', '--client', 'copilot-cli', '--port', PORT], { env, encoding: 'utf8' });

  assert.doesNotMatch(out, /\(new\)/, 'aliased server must not be reported as a new entry');
  assert.match(out, /s1 \(as s1-mcp\)/, 'plan should show the alias key it will rewrite');
  assert.match(out, new RegExp(`http://127\\.0\\.0\\.1:${PORT}/s1/mcp`));
});
