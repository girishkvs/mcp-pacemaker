import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { observeWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';

export class CachedEdgeFixture {
  async run({ sourceRoot, expectedRed = false } = {}) {
    const directory = mkdtempSync(join(tmpdir(), 'mcp-cached-edge-owned-'));
    const builder = fileURLToPath(new URL('../fixtures/windows-legacy/build-cached-edge.ps1', import.meta.url));
    const helper = fileURLToPath(new URL('../../bin/windows-lifetime/ProcessLifetimeHelper.exe', import.meta.url));
    const args = ['-NoProfile', '-NonInteractive', '-File', builder, '-OutputDirectory', directory];
    if (sourceRoot) args.push('-SourceRoot', sourceRoot);
    const build = spawnSync('pwsh.exe', args, { encoding: 'utf8', windowsHide: true, timeout: 30000 });
    const evidence = { sourceRoot, expectedRed, directory, build: { code: build.status, stdout: build.stdout, stderr: build.stderr } };
    let observer;
    let exit;
    try {
      assert.equal(build.status, 0, build.stderr);
      const binary = join(directory, 'cached-edge.exe');
      evidence.variantSha256 = createHash('sha256').update(readFileSync(binary)).digest('hex');
      const child = spawn(binary, [helper, ...(expectedRed ? ['old-red'] : [])],
        { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      let buffer = '', stderr = '';
      let arm;
      let protocolError;
      child.stdin.on('error', () => {});
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', text => {
        buffer += text;
        let end;
        while ((end = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, end).trim();
          buffer = buffer.slice(end + 1);
          if (!line) continue;
          try {
            const message = JSON.parse(line);
            if (message.type === 'capsule') {
              evidence.lifetime = message.lifetime;
              evidence.modelIdentity = message.modelIdentity;
              assert.equal(message.modelIdentity.pid, child.pid);
              arm = observeWindowsProcessLifetime(message.lifetime).then(value => {
                observer = value;
                child.stdin.write('GO\n');
              }).catch(error => { protocolError = error.message; child.stdin.end(); });
            } else evidence.result = message;
          } catch (error) { protocolError = error.message; child.stdin.end(); }
        }
      });
      child.stderr.on('data', bytes => { stderr += bytes; });
      const deadline = setTimeout(() => child.kill(), 30000);
      try { exit = await new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal }))); }
      finally { clearTimeout(deadline); }
      if (arm) await arm;
      evidence.exit = exit;
      evidence.stderr = stderr;
      evidence.protocolError = protocolError;
      if (observer) evidence.capsule = await observer.done;
      assert.equal(protocolError, undefined);
      assert.equal(exit.code, 0, `${stderr}\n${JSON.stringify(evidence.result)}`);
      assert.equal(exit.signal, null);
      assert.deepEqual(evidence.capsule, { verified: true, ownerExited: true, activeProcesses: 0 });
      assert.ok(evidence.result.cleanup.every(item => item.heldHandleSignaled));
      assert.equal(evidence.result.expectedRed, expectedRed);
      return evidence;
    } finally {
      const output = process.env.MCP_LEGACY_TEST_EVIDENCE;
      evidence.variantSources = readdirSync(directory).filter(name => name.endsWith('.cs')).map(name => ({
        file: name, sha256: createHash('sha256').update(readFileSync(join(directory, name))).digest('hex'),
      }));
      if (evidence.capsule?.activeProcesses === 0 || !evidence.modelIdentity)
        rmSync(directory, { recursive: true, force: true });
      evidence.removed = !existsSync(directory);
      if (output) {
        mkdirSync(output, { recursive: true });
        const name = `cached-edge-${basename(directory)}.json`;
        writeFileSync(join(output, name), JSON.stringify(evidence, null, 2), { flag: 'wx' });
      }
    }
  }
}
