import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { localHash } from './local-regression.mjs';
import { STAGE_SCENARIOS, STAGE_CHILD_TIMEOUT, proofFiles, stageChildArgs, stageProofExit,
  validateStageProof } from './stage-proof-contract.mjs';
import { validateStageLoader } from './stage-loader.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

export function stageProofEnvironment(env, home, node) {
  const result = { PATH: dirname(node), HOME: home, USERPROFILE: home, TMP: home,
    TEMP: home, TMPDIR: home, APPDATA: home, LOCALAPPDATA: home, CI: 'true', NO_COLOR: '1' };
  for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']) {
    if (env[key]) result[key] = env[key];
  }
  return result;
}

export function runStageProof({ cli, home, root = ROOT, node = process.execPath,
  nodeVersion = process.version, env = process.env, execute = spawnSync }) {
  assert.equal(nodeVersion, 'v24.21.0', 'Actual npm12 proof requires publisher Node24.21.0');
  root = realpathSync.native(root);
  cli = realpathSync.native(cli);
  node = realpathSync.native(node);
  assert.equal(existsSync(home), false, 'Offline stage proof requires a new owned home');
  mkdirSync(home, { mode: 0o700 });
  home = realpathSync.native(home);
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  assert.ok(['1.3.1', '2.0.1'].includes(version));
  const npmRoot = resolve(dirname(cli), '..');
  const pins = JSON.parse(readFileSync(join(root, 'tools/npm-publication/stage-sdk-pins.json')));
  for (const [path, hash] of Object.entries(pins)) {
    assert.equal(localHash(readFileSync(join(npmRoot, path))), hash, 'Retained npm source changed before proof');
  }
  validateStageLoader(cli);
  const report = { schemaVersion: 4, kind: 'pinned-npm12-offline-stage-proof',
    status: 'failed', syntheticOnly: true, node: nodeVersion, npm: '12.0.2', version,
    releaseReady: false, authenticated: false, realSigning: false, realRegistry: false,
    files: proofFiles(root), invocation: { root, cli, node, home }, cases: [] };
  try {
    for (const mode of STAGE_SCENARIOS) {
      const childHome = join(home, mode);
      mkdirSync(childHome, { mode: 0o700 });
      const args = stageChildArgs({ join }, mode, root, cli, childHome);
      const start = Date.now();
      const result = execute(node, args, {
        cwd: root, env: stageProofEnvironment(env, childHome, node), shell: false,
        windowsHide: true, timeout: STAGE_CHILD_TIMEOUT, killSignal: 'SIGKILL',
        encoding: 'utf8', maxBuffer: 1024 * 1024,
      });
      const command = { executable: node, args, cwd: root, timeoutMs: STAGE_CHILD_TIMEOUT,
        elapsedMs: Date.now() - start, exitCode: result.status, signal: result.signal,
        error: result.error?.code ?? null, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
      report.cases.push({ mode, command, sha256: localHash(JSON.stringify(command)) });
      assert.equal(command.error, null);
      assert.equal(command.signal, null);
      assert.equal(command.exitCode, stageProofExit(mode), 'Offline proof child returned an unexpected exit; no retry');
    }
    report.status = 'passed';
    validateStageProof(report, { root, version, invocation: report.invocation });
    return report;
  } catch (error) {
    report.status = 'failed';
    throw Object.assign(new Error('Offline stage proof failed; original child receipts retained'), { report, cause: error });
  }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.equal(process.argv.length, 4, 'Supply retained npm CLI and new owned fixture home');
    console.log(JSON.stringify(runStageProof({ cli: resolve(process.argv[2]), home: resolve(process.argv[3]) })));
  } catch (error) {
    if (error.report) console.log(JSON.stringify(error.report));
    console.error('Offline stage proof stopped; no real registry/signing authority.');
    process.exitCode = 1;
  }
}
