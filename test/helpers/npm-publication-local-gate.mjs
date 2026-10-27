import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync, linkSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync,
  truncateSync, writeFileSync,
} from 'node:fs';
import { join, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  LocalGate, HOSTED_BOUNDARIES, SOURCE_SUITE_TIMEOUT_MS, localEnvironment, selectedTestFiles, testArguments, testTotals,
} from '../../tools/npm-publication/local-gate.mjs';
import {
  evidenceEntryFilter, launcherArguments, validateContainer, WindowsLocalGate,
} from '../../tools/npm-publication/local-windows.mjs';
import { InputSnapshot, safeName, verifyManifest, writeManifest } from '../../tools/npm-publication/local-inputs.mjs';
import { LocalGitConfig } from '../../tools/npm-publication/local-git.mjs';
import { LocalSourceReader } from '../../tools/npm-publication/local-source.mjs';
import { bindGuestIdentity, windowsSystemEnvironment } from '../../tools/npm-publication/local-environment.mjs';
import { localCaseUser, localCases, localCommitment, LOCAL_NATIVE_PACKAGES } from '../../tools/npm-publication/local-regression.mjs';
import { LocalRunLock, LocalRunState, localRunPlan } from '../../tools/npm-publication/local-run-state.mjs';
import { evidenceInventory } from '../../tools/npm-publication/local-evidence.mjs';
import { verifyLocalHeader } from '../../tools/npm-publication/verify-local.mjs';
import { LEFTOVER_CONTAINER, ResumeFixture } from './local-resume-fixture.mjs';
import { CONTROLLER_SKIP } from './legacy-checkout.mjs';

function totals(overrides = {}) {
  return Object.entries({ tests: 3, pass: 2, fail: 0, cancelled: 0, skipped: 1, todo: 0, ...overrides })
    .map(([key, value]) => `# ${key} ${value}\n`).join('');
}

function directory(t) {
  const path = realpathSync.native(mkdtempSync(join(tmpdir(), 'publication-local-unit-')));
  t.after(() => rmSync(path, { recursive: true, force: true }));
  return path;
}

function runner(t) {
  const output = directory(t);
  const root = join(output, 'source');
  const npm = join(output, 'npm');
  mkdirSync(root);
  mkdirSync(join(npm, 'bin'), { recursive: true });
  writeFileSync(join(npm, 'package.json'), '{"name":"npm","version":"12.0.2"}');
  const npmCli = join(npm, 'bin', 'npm-cli.js');
  writeFileSync(npmCli, '');
  return new LocalGate({ root, npmCli, output: join(output, 'result') });
}

test('local gate selects complete explicit Node files without shell or name-filter substitutions', () => {
  assert.deepEqual(testArguments('node --test test/a.test.mjs test/b.test.mjs'),
    ['--test', '--test-reporter=tap', 'test/a.test.mjs', 'test/b.test.mjs']);
  assert.deepEqual(testArguments('node --test --test-concurrency=6 test/a.test.mjs test/b.test.mjs'),
    ['--test', '--test-concurrency=6', '--test-reporter=tap', 'test/a.test.mjs', 'test/b.test.mjs']);
  assert.deepEqual(selectedTestFiles(testArguments('node --test --test-concurrency=6 test/a.test.mjs')),
    ['test/a.test.mjs']);
  for (const script of [
    'node --test', 'echo passed', 'node --test --test-name-pattern=missing test/a.test.mjs',
    'node --test test/a.test.mjs && exit 0', 'node --test test/a.test.mjs test/a.test.mjs',
    'node --test test/a.test.mjs;exit', 'node --test ../test/a.test.mjs',
    'node --test test/../a.test.mjs', 'node --test --test-concurrency=6',
    'node --test --test-concurrency=0 test/a.test.mjs',
    'node --test --test-concurrency=100 test/a.test.mjs',
    'node --test --concurrency=6 test/a.test.mjs',
  ]) assert.throws(() => testArguments(script));
});

test('local gate rejects empty, failed, cancelled and incomplete totals while preserving visible platform skips', () => {
  assert.deepEqual(testTotals(totals()), { tests: 3, pass: 2, fail: 0, cancelled: 0, skipped: 1, todo: 0 });
  for (const output of [
    '', totals({ tests: 0, pass: 0, skipped: 0 }), totals({ fail: 1 }), totals({ cancelled: 1 }),
    totals({ todo: 1 }), totals({ tests: 4 }), `${totals()}${totals()}`, totals().replace('# pass 2\n', ''),
  ]) assert.throws(() => testTotals(output));
});

test('local environment excludes owner credentials, hosted identity, proxies, injection and live-bridge settings', t => {
  const parent = { ...process.env, NPM_TOKEN: 'never-issued', GITHUB_TOKEN: 'never-issued',
    NODE_OPTIONS: '--bad', HTTPS_PROXY: 'https://invalid.invalid', GITHUB_ACTIONS: 'true',
    RUNNER_ENVIRONMENT: 'github-hosted', MCP_BRIDGE_PORT: '8792',
    MCP_POOLING_TRACE_ARTIFACT_DIR: 'unowned', DOCKER_HOST: 'tcp://invalid.invalid',
    PSModuleAnalysisCachePath: 'unowned-cache' };
  const env = localEnvironment(parent, join(directory(t), 'home'));
  for (const key of ['NPM_TOKEN', 'GITHUB_TOKEN', 'NODE_OPTIONS', 'HTTPS_PROXY', 'GITHUB_ACTIONS',
    'RUNNER_ENVIRONMENT', 'MCP_BRIDGE_PORT', 'MCP_POOLING_TRACE_ARTIFACT_DIR', 'DOCKER_HOST']) {
    assert.equal(env[key], undefined, key);
  }
  assert.equal(env.npm_config_offline, 'true');
  assert.equal(env.npm_config_ignore_scripts, 'true');
  assert.equal(env.PSModuleAnalysisCachePath, join(env.HOME, 'powershell-module-cache'));
  assert.equal(readFileSync(env.npm_config_userconfig, 'utf8'), '');
  assert.equal(readFileSync(env.npm_config_globalconfig, 'utf8'), '');
});

test('both guest sanitizers preserve token-bound guest identity without taking host or parent npm paths', t => {
  const token = { name: 'OWNED-GUEST\\FixtureUser', sid: 'S-1-5-21-1-2-3-1000' };
  const parent = { USERDOMAIN: 'OWNED-GUEST', USERNAME: 'FixtureUser', NPM_TOKEN: 'never-issued',
    npm_execpath: 'untrusted-parent-cli', NODE_OPTIONS: '--untrusted' };
  const system = windowsSystemEnvironment(parent);
  assert.deepEqual(system, { USERDOMAIN: 'OWNED-GUEST', USERNAME: 'FixtureUser' });
  assert.deepEqual(bindGuestIdentity(system, token), token);
  const env = localEnvironment(system, join(directory(t), 'home'));
  assert.equal(env.USERDOMAIN, 'OWNED-GUEST');
  assert.equal(env.USERNAME, 'FixtureUser');
  assert.equal(env.npm_execpath, undefined);
  assert.deepEqual(bindGuestIdentity({}, token), token);
  assert.throws(() => bindGuestIdentity({ USERDOMAIN: 'HOST' }, token), /differs from its token/);
  assert.throws(() => bindGuestIdentity({ USERNAME: 'HostUser' }, token), /differs from its token/);
  const gate = runner(t);
  assert.equal(gate.env.npm_execpath, gate.npmCli);
});

test('a deliberate real child failure remains failure and has a hash-bound receipt', t => {
  const gate = runner(t);
  assert.throws(() => gate.command('deliberate failure', process.execPath, ['-e', 'process.exit(7)']),
    /failed/);
  const step = gate.steps[0];
  const bytes = readFileSync(join(gate.output, step.file));
  assert.equal(step.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(JSON.parse(bytes).exitCode, 7);
  assert.equal(step.exitCode, 7);
});

test('binary native Git output survives the real command and evidence boundary exactly', t => {
  const gate = runner(t);
  const bytes = gate.command('binary control', process.execPath,
    ['-e', 'process.stdout.write(Buffer.from([0,255,128,13,10]))'], gate.root, true);
  assert.deepEqual(bytes, Buffer.from([0, 255, 128, 13, 10]));
  const record = JSON.parse(readFileSync(join(gate.output, gate.steps[0].file)));
  assert.equal(record.encoding, 'base64');
  assert.deepEqual(Buffer.from(record.stdout, 'base64'), bytes);
});

test('a real child timeout cannot become a successful gate command', t => {
  const gate = runner(t);
  assert.throws(() => gate.command('timeout control', process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'], gate.root, false, 500), /timeout/);
  const record = JSON.parse(readFileSync(join(gate.output, gate.steps[0].file)));
  assert.equal(record.error, 'ETIMEDOUT');
  assert.equal(record.exitCode, null);
});

test('source-suite harness budget is explicit while ordinary commands and timeout controls stay bounded', t => {
  const gate = runner(t);
  gate.command('ordinary command budget', process.execPath, ['-e', 'process.exit(0)']);
  gate.command('source budget receipt', process.execPath, ['-e', 'process.exit(0)'],
    gate.root, false, SOURCE_SUITE_TIMEOUT_MS);
  const records = gate.steps.map(step => JSON.parse(readFileSync(join(gate.output, step.file))));
  assert.equal(records[0].timeoutMs, 15 * 60_000);
  assert.equal(records[1].timeoutMs, 60 * 60_000);
  assert.throws(() => gate.command('over-budget command', process.execPath, ['-e', 'process.exit(0)'],
    gate.root, false, SOURCE_SUITE_TIMEOUT_MS + 1), /Invalid command deadline/);
  assert.equal(gate.steps.length, 2);
  const outer = Object.create(WindowsLocalGate.prototype);
  assert.ok(outer.caseTimeout('gate') > SOURCE_SUITE_TIMEOUT_MS,
    'The outer case must outlast the complete source suite it contains');
  assert.equal(outer.caseTimeout('gate'), SOURCE_SUITE_TIMEOUT_MS + 30 * 60_000);
  assert.equal(outer.caseTimeout('audit'), 5 * 60_000);
  assert.equal(outer.caseTimeout('fail'), 20 * 60_000);
  for (const mode of ['timeout', 'timeout-early-exit']) assert.equal(outer.caseTimeout(mode), 15_000);
  assert.throws(() => outer.caseTimeout('unknown'), /Unsupported local case mode/);
});

test('qualification keeps all six source cases and requires an audit companion for each current runtime', () => {
  const cases = localCases(['1.3.1', '2.1.0']);
  assert.equal(cases.length, 12);
  assert.equal(cases.filter(item => item.mode === 'gate').length, 6);
  assert.equal(cases.filter(item => item.mode === 'audit').length, 3);
  for (const item of cases) {
    const ordinary = item.mode === 'gate' && item.version === '2.1.0';
    assert.equal(localCaseUser(item.mode, item.version), ordinary ? 'ContainerUser' : '');
  }
  assert.throws(() => localCaseUser('audit', '1.3.1'));
});

test('the local Windows launcher rejects uncontained, wrong-owner or credential-bearing containers', () => {
  const binding = { id: 'a'.repeat(64), owner: 'unique-owner', image: `sha256:${'b'.repeat(64)}` };
  const value = {
    Id: binding.id, Image: binding.image, Mounts: [],
    Config: { Labels: { 'pacemaker.local-gate': binding.owner }, Env: [] },
    HostConfig: { Isolation: 'hyperv', NetworkMode: 'none', CpuCount: 4, Memory: 4 * 1024 ** 3,
      Binds: null, PortBindings: {}, RestartPolicy: { Name: 'no' }, Privileged: false, Devices: [],
      StorageOpt: { size: '4GB' }, IOMaximumBandwidth: 32 * 1024 ** 2 },
  };
  validateContainer(value, binding);
  const ordinary = structuredClone(value);
  ordinary.Config.User = 'ContainerUser';
  validateContainer(ordinary, { ...binding, user: 'ContainerUser' });
  assert.throws(() => validateContainer(value, { ...binding, user: 'ContainerUser' }));
  assert.throws(() => validateContainer(ordinary, binding));
  for (const mutate of [
    v => { v.Config.Labels['pacemaker.local-gate'] = 'someone-else'; },
    v => { v.Image = 'wrong'; },
    v => { v.HostConfig.Isolation = 'process'; },
    v => { v.HostConfig.NetworkMode = 'nat'; },
    v => { v.HostConfig.CpuCount = 16; },
    v => { v.Mounts = [{ Source: 'host' }]; },
    v => { v.Config.Env = ['HTTPS_PROXY=https://invalid.invalid']; },
    v => { v.HostConfig.PortBindings = { '8792/tcp': [{}] }; },
    v => { v.HostConfig.RestartPolicy.Name = 'always'; },
    v => { v.HostConfig.StorageOpt = {}; },
    v => { v.HostConfig.IOMaximumBandwidth = 0; },
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    assert.throws(() => validateContainer(changed, binding));
  }
});

test('local input snapshots reject unsafe paths, content changes, and unexpected copied files', t => {
  for (const name of ['../secret', 'a/../b', 'C:/secret', 'a\\b', 'a:stream', 'con.txt', 'a.', 'a//b']) {
    assert.throws(() => safeName(name), undefined, name);
  }
  const home = directory(t);
  const root = join(home, 'source');
  mkdirSync(root);
  writeFileSync(join(root, 'a.mjs'), 'original');
  const snapshot = new InputSnapshot(root);
  snapshot.add('a.mjs');
  const copy = join(home, 'copy');
  snapshot.copy(copy);
  const { manifest } = writeManifest(copy, {});
  verifyManifest(copy, manifest);
  writeFileSync(join(copy, 'unexpected'), 'extra');
  assert.throws(() => verifyManifest(copy, manifest), /Unexpected/);
  writeFileSync(join(root, 'a.mjs'), 'modified');
  assert.throws(() => snapshot.verify(), /Input/);
});

test('monotonic fractional deadlines are converted to valid bounded child timeouts', t => {
  const gate = Object.create(WindowsLocalGate.prototype);
  gate.output = directory(t);
  mkdirSync(join(gate.output, 'commands'));
  gate.env = { ...process.env };
  gate.deadline = performance.now() + 5000.5;
  gate.commandIndex = 0;
  gate.cleaning = false;
  assert.equal(gate.command(process.execPath, ['-e', 'process.exit(0)']).status, 0);
  const receipt = JSON.parse(readFileSync(join(gate.output, 'commands', '1.json')));
  assert.equal(Number.isInteger(receipt.timeout), true);
  assert.ok(receipt.timeout > 0 &&
    receipt.timeout <= 5000);
});

test('final gate binding rejects new source paths and changed HEAD without accepting old file hashes', () => {
  const gate = Object.create(WindowsLocalGate.prototype);
  gate.sourceBindings = [{ root: 'fixture', head: 'a'.repeat(40), names: ['old.mjs'] }];
  gate.snapshots = [{ verify: () => assert.fail('Source-set rejection must happen first') }];
  gate.git = () => `${'a'.repeat(40)}\n`;
  gate.sourceNames = () => ['new-runtime.mjs', 'old.mjs'];
  assert.throws(() => gate.verifyInputs(), /Source inventory changed/);
  gate.git = () => `${'b'.repeat(40)}\n`;
  assert.throws(() => gate.verifyInputs(), /Source HEAD changed/);
});

test('retained directory re-enumeration rejects newly added package or tool files', t => {
  const root = directory(t);
  mkdirSync(join(root, 'retained'));
  writeFileSync(join(root, 'retained/original'), 'same bytes');
  const snapshot = new InputSnapshot(root);
  snapshot.add('retained');
  snapshot.verify();
  writeFileSync(join(root, 'retained/unreviewed'), 'added');
  assert.throws(() => snapshot.verify(), /Input inventory or content changed/);
});

test('actual tool input wiring rejects top-level npm, pwsh and native additions, including empty directories', t => {
  for (const tool of ['npm', 'pwsh', 'native']) {
    for (const kind of ['file', 'directory']) {
      const home = directory(t);
      const root = join(home, 'source');
      mkdirSync(join(root, 'ui/node_modules'), { recursive: true });
      mkdirSync(join(root, 'node_modules'));
      writeFileSync(join(root, 'package.json'), '{"version":"2.0.1"}');
      const gate = Object.create(WindowsLocalGate.prototype);
      gate.output = join(home, 'output');
      mkdirSync(gate.output);
      gate.snapshots = [];
      gate.sourceBindings = [];
      for (const name of ['npm', 'pwsh', 'git', 'native']) {
        gate[`${name}Root`] = join(home, name);
        mkdirSync(gate[`${name}Root`]);
      }
      for (const path of ['cmd', 'mingw64/bin', 'mingw64/libexec/git-core', 'usr/bin', 'usr/share']) {
        mkdirSync(join(gate.gitRoot, path), { recursive: true });
      }
      for (const name of ['npm', 'pwsh']) writeFileSync(join(gate[`${name}Root`], 'tool.js'), 'retained');
      gate.sourceNames = () => ['package.json'];
      gate.git = (cwd, args) => {
        assert.equal(cwd, root);
        if (args[0] === 'bundle') {
          writeFileSync(args[2], 'Unit fixture only, not a Git bundle');
          return '';
        }
        if (args[0] === 'rev-parse') {
          assert.ok(args[1] === 'HEAD' ||
            args[1] === 'HEAD^{tree}');
          return (args[1] === 'HEAD' ? 'a' : 'b').repeat(40);
        }
        if (args[0] === 'status') {
          assert.deepEqual(args, ['status', '--porcelain=v1', '--untracked-files=all']);
          return '?? package.json\n';
        }
        if (args[0] === 'ls-tree') {
          assert.deepEqual(args, ['ls-tree', '-rz', '--full-tree', 'HEAD']);
          return `100644 blob ${'c'.repeat(40)}\tpackage.json\0`;
        }
        assert.deepEqual(args, ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--deduplicate']);
        return 'package.json\0';
      };
      gate.inputs(root);
      gate.verifyInputs();
      const added = join(gate[`${tool}Root`], 'new-top-level');
      if (kind === 'file') writeFileSync(added, 'unbound input');
      else mkdirSync(added);
      assert.throws(() => gate.verifyInputs(), /Input inventory or content changed/, `${tool}/${kind}`);
    }
  }
});

test('local native archives match the unchanged CI restore pins', () => {
  const script = readFileSync(new URL('../../tools/windows-ci/restore-toolchain.ps1', import.meta.url), 'utf8');
  for (const [name, hash] of Object.entries(LOCAL_NATIVE_PACKAGES)) {
    assert.ok(script.includes(`Name = '${name}'`));
    assert.ok(script.includes(`Sha256 = '${hash}'`));
  }
  const gate = Object.create(WindowsLocalGate.prototype);
  assert.throws(() => gate.run(), /--native-packages/);
});

test('native archive admission bounds files and rejects links before hashing', t => {
  const root = directory(t);
  const names = Object.keys(LOCAL_NATIVE_PACKAGES);
  const gate = Object.create(WindowsLocalGate.prototype);
  for (const name of names) writeFileSync(join(root, name), '');
  truncateSync(join(root, names[0]), 129 * 1024 ** 2);
  assert.throws(() => gate.nativeInputs(root), /Oversized/);
  rmSync(join(root, names[0]));
  const target = join(directory(t), 'archive-directory');
  mkdirSync(target);
  symlinkSync(target, join(root, names[0]), process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => gate.nativeInputs(root), /Linked/);
  // Windows junctions report as directories, so the link itself needs the recursive form to
  // unlink on every supported Node version. Removal never follows the link to its target.
  rmSync(join(root, names[0]), { recursive: true });
  mkdirSync(join(root, names[0]));
  assert.throws(() => gate.nativeInputs(root), /regular files/);
  rmSync(join(root, names[0]), { recursive: true });
  writeFileSync(join(root, names[0]), 'wrong archive');
  assert.throws(() => gate.nativeInputs(root), /hash differs/);
});

test('actual source identity binds a clean Git tree and declared checkout bytes before rejecting edits', t => {
  const root = directory(t);
  writeFileSync(join(root, 'package.json'), '{"version":"2.0.1"}\n');
  writeFileSync(join(root, '.gitattributes'), '*.ps1 text eol=crlf\n');
  const script = "Write-Output 'owned'\r\n";
  writeFileSync(join(root, 'tool.ps1'), script);
  const reader = new LocalSourceReader(root);
  reader.git(['init', '--quiet']);
  reader.git(['add', '--', '.gitattributes', 'package.json', 'tool.ps1']);
  reader.git(['-c', 'user.name=Local fixture', '-c', 'user.email=fixture@invalid.invalid',
    '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Owned local source identity fixture']);
  const identity = reader.capture();
  assert.equal(identity.clean, true);
  assert.equal(identity.head, reader.git(['rev-parse', 'HEAD']).trim());
  assert.equal(identity.tree, reader.git(['rev-parse', 'HEAD^{tree}']).trim());
  assert.deepEqual(identity.entries.map(entry => entry.path), ['.gitattributes', 'package.json', 'tool.ps1']);
  assert.equal(reader.git(['show', 'HEAD:tool.ps1']), "Write-Output 'owned'\n");
  assert.equal(identity.files.find(file => file.path === 'tool.ps1').sha256,
    createHash('sha256').update(script).digest('hex'));
  writeFileSync(join(root, 'new-source.mjs'), 'Added source');
  assert.throws(() => reader.capture(), /clean final source HEADs/);
  rmSync(join(root, 'new-source.mjs'));
  writeFileSync(join(root, 'tool.ps1'), "Write-Output 'changed'\r\n");
  assert.throws(() => reader.capture(), /clean final source HEADs/);
});

test('directory snapshots preserve and bind empty directory membership and type', t => {
  for (const mutation of ['addition', 'removal', 'type']) {
    const home = directory(t);
    const root = join(home, 'source');
    mkdirSync(join(root, 'retained/empty'), { recursive: true });
    const snapshot = new InputSnapshot(root);
    snapshot.add('retained');
    const copied = join(home, 'copy');
    snapshot.copy(copied);
    assert.equal(existsSync(join(copied, 'retained/empty')), true);
    if (mutation === 'addition') mkdirSync(join(root, 'retained/added'));
    else {
      rmSync(join(root, 'retained/empty'), { recursive: true });
      if (mutation === 'type') writeFileSync(join(root, 'retained/empty'), '');
    }
    assert.throws(() => snapshot.verify(), /Input inventory or content changed/, mutation);
  }
});

test('both Git wrappers reject canonical inline and conditional executable configuration before repository operations', t => {
  for (const text of [
    '[CoRe] worktree = C:/not-the-candidate\n',
    '[core] fsmonitor = this-command-must-never-run\n',
    '[includeIf "gitdir:*"] path = C:/missing-config\n',
    '[filter "fixture"] clean = this-command-must-never-run\n',
  ]) {
    for (const kind of ['inner', 'outer']) {
      const gate = runner(t);
      mkdirSync(join(gate.root, '.git'));
      writeFileSync(join(gate.root, '.git/config'), text);
      let operations = 0;
      let parses = 0;
      const execute = (file, args, cwd) => {
        if (!args.includes('config')) {
          operations++;
          return '';
        }
        parses++;
        const result = spawnSync(file, args, {
          cwd, env: gate.env, encoding: 'utf8', shell: false, windowsHide: true,
          timeout: 5000, maxBuffer: 1024 * 1024,
        });
        assert.equal(result.error, undefined);
        assert.equal(result.status, 0, result.stderr);
        return result.stdout;
      };
      if (kind === 'inner') {
        gate.command = (label, file, args, cwd) => execute(file, args, cwd);
        assert.throws(() => gate.git(['ls-files']), /Inherited executable Git configuration/);
      } else {
        const outer = Object.create(WindowsLocalGate.prototype);
        outer.config = gate.gitEmpty;
        outer.command = (file, args) => ({ stdout: execute(file, args, gate.gitEmpty) });
        assert.throws(() => outer.git(gate.root, ['ls-files']), /Inherited executable Git configuration/);
      }
      assert.equal(operations, 0, `${kind}: rejection must precede repository operations`);
      assert.equal(parses, 1, `${kind}: use Git's config parser`);
    }
  }
});

test('Git key parsing never follows includes and rejects parser failure or changing input', t => {
  const gate = runner(t);
  const config = join(gate.root, '.git/config');
  mkdirSync(join(gate.root, '.git'));
  const included = join(gate.gitEmpty, 'malformed-config');
  writeFileSync(included, '[invalid syntax');
  const allowed = '[core]\nrepositoryformatversion=0\nbare=false\n';
  let parses = 0;
  const parse = args => {
    parses++;
    assert.ok(args.includes('--no-includes'));
    const result = spawnSync('git', args, {
      cwd: gate.gitEmpty, env: gate.env, encoding: 'utf8', windowsHide: true, shell: false,
      timeout: 5000, maxBuffer: 1024 * 1024,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  writeFileSync(config, `[includeIf "gitdir:*"] path = "${included.replaceAll('\\', '/')}"\n`);
  assert.throws(() => new LocalGitConfig(gate.root, gate.gitEmpty, parse), /Inherited executable Git/);
  assert.equal(parses, 1, 'The malformed included file was not parsed');
  writeFileSync(config, allowed);
  const stopped = new Error('Original config parser failure');
  assert.throws(() => new LocalGitConfig(gate.root, gate.gitEmpty, () => { throw stopped; }),
    error => error === stopped);
  assert.throws(() => new LocalGitConfig(gate.root, gate.gitEmpty, args => {
    const output = parse(args);
    writeFileSync(config, '[core] worktree = C:/changed\n');
    return output;
  }), /Git configuration changed/);
  writeFileSync(config, allowed);
  const binding = new LocalGitConfig(gate.root, gate.gitEmpty, parse);
  assert.deepEqual(binding.options(), ['-c', `safe.directory=${gate.root}`,
    '-c', `core.worktree=${gate.root}`, '-c', 'extensions.worktreeConfig=false']);
  writeFileSync(config, '[core] fsmonitor = changed\n');
  assert.throws(() => binding.verify(), /Git configuration changed/);
  writeFileSync(config, '[invalid syntax');
  const failedBefore = parses;
  assert.throws(() => new LocalGitConfig(gate.root, gate.gitEmpty, parse), /bad config|invalid/i);
  assert.equal(parses, failedBefore + 1);
});

test('both wrappers accept ordinary real repositories and bind operations to the intended worktree', t => {
  const gate = runner(t);
  gate.git(['init', '--quiet']);
  writeFileSync(join(gate.root, 'fixture.txt'), 'Owned local fixture, never published');
  gate.git(['add', 'fixture.txt']);
  gate.git(['commit', '--quiet', '-m', 'Owned local gate test fixture']);
  assert.equal(gate.git(['ls-files']), 'fixture.txt');
  const outer = Object.create(WindowsLocalGate.prototype);
  outer.output = join(gate.work, 'outer');
  mkdirSync(join(outer.output, 'commands'), { recursive: true });
  outer.config = gate.gitEmpty;
  outer.env = gate.env;
  outer.deadline = performance.now() + 30_000;
  outer.commandIndex = 0;
  outer.cleaning = false;
  assert.equal(outer.git(gate.root, ['ls-files']).trim(), 'fixture.txt');
  const receipt = JSON.parse(readFileSync(join(outer.output, 'commands', '2.json')));
  assert.ok(receipt.args.includes(`core.worktree=${gate.root}`));
  const clone = join(gate.work, 'clone');
  gate.git(['clone', '--quiet', '--no-hardlinks', '--no-checkout', gate.root, clone]);
  gate.git(['checkout', '--force', 'HEAD', '--', '.'], clone);
  assert.equal(readFileSync(join(clone, 'fixture.txt'), 'utf8'), 'Owned local fixture, never published');
  assert.equal(gate.git(['ls-files'], clone), 'fixture.txt');
});

test('controller binding rejects changed original and frozen entry bytes or extra frozen files', t => {
  for (const mutation of ['original', 'frozen', 'extra']) {
    const home = directory(t);
    const root = join(home, 'source');
    const source = join(root, 'tools/npm-publication');
    mkdirSync(source, { recursive: true });
    for (const name of ['local-windows-entry.mjs', 'local-inputs.mjs', 'local-environment.mjs']) {
      writeFileSync(join(source, name), 'reviewed controller');
    }
    const gate = Object.create(WindowsLocalGate.prototype);
    gate.output = join(home, 'output');
    mkdirSync(gate.output);
    gate.snapshots = [];
    gate.sourceBindings = [];
    gate.freezeController(root);
    gate.verifyInputs();
    const destination = mutation === 'original' ? source : join(gate.controller, 'tools/npm-publication');
    writeFileSync(join(destination, mutation === 'extra' ? 'extra.mjs' : 'local-windows-entry.mjs'), 'changed');
    assert.throws(() => gate.verifyInputs(), /Input inventory or content changed/, mutation);
  }
});

test('evidence export rejects links, traversal, duplicate paths and excessive declared data before extraction', () => {
  const valid = evidenceEntryFilter();
  assert.equal(valid('output/', { type: 'Directory', size: 0 }), true);
  assert.equal(valid('output/runtime.json', { type: 'File', size: 512 }), true);
  for (const [name, type, size] of [
    ['output/../outside', 'File', 1], ['output/alias', 'SymbolicLink', 0],
    ['output/hard', 'Link', 0], ['output/C:stream', 'File', 1],
    ['output/huge', 'File', 33 * 1024 ** 2], ['output/bad-size', 'File', -1],
  ]) assert.throws(() => evidenceEntryFilter()(name, { type, size }));
  assert.throws(() => valid('output/RUNTIME.json', { type: 'File', size: 1 }), /Duplicate/);
  const overflow = evidenceEntryFilter();
  for (let index = 0; index < 4; index++) overflow(`output/${index}`, { type: 'File', size: 32 * 1024 ** 2 });
  assert.throws(() => overflow('output/extra', { type: 'File', size: 1 }), /bounds/);
});

test('local gate cannot quietly fetch or push missing Git prerequisites', t => {
  const gate = runner(t);
  for (const verb of ['fetch', 'push']) assert.throws(() => gate.git([verb, 'origin']), /forbids/);
  assert.equal(gate.steps.length, 0);
});

test('successful local controls do not remove genuine hosted and publication boundaries', () => {
  assert.ok(HOSTED_BOUNDARIES.some(item => item.includes('Fresh registry')));
  assert.ok(HOSTED_BOUNDARIES.some(item => item.includes('OIDC')));
  assert.ok(HOSTED_BOUNDARIES.some(item => item.includes('Actual staged provenance')));
});

const FULL_SCOPE = 'both-release-lines-local-only';
const PLAN = localRunPlan(FULL_SCOPE, ['1.3.1', '2.1.0']);
const notInput = step => !step.startsWith('inputs-');

test('a normal local run records one complete invocation and still verifies', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  const report = f.gate().run();
  assert.equal(report.status, 'passed');
  assert.deepEqual(f.ran, PLAN.filter(notInput));
  assert.equal(report.invocations.length, 1);
  const [invocation] = report.invocations;
  assert.deepEqual([invocation.index, invocation.status, invocation.reused, invocation.ran, invocation.setAside,
    invocation.removedContainers], [1, 'passed', [], PLAN, null, []]);
  assert.equal(invocation.startedAt, report.startedAt);
  assert.equal(invocation.completedAt, report.completedAt);
  assert.deepEqual(f.json('run-state.json').binding.platform, { docker: { version: f.server.Version,
    apiVersion: f.server.ApiVersion, os: f.server.Os, kernelVersion: f.server.KernelVersion }, windows: f.windows });
  verifyLocalHeader(report);
  assert.deepEqual(f.json('evidence-manifest.json'), evidenceInventory(f.output));
  new LocalRunState(f.output).verify(report, f.inputs());
  assert.equal(existsSync(f.attempts), false, 'A normal run sets nothing aside');
});

test('a resumed run reruns only the failed case onwards and preserves the failed attempt aside', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  const failed = PLAN.indexOf('v2.1.0-node20.20.2');
  f.failRun(PLAN[failed]);
  const before = f.json('run-state.json');
  const bound = before.checkpoints.at(-1).commands;
  const report = f.gate(true).run();
  assert.equal(report.status, 'passed');
  assert.equal(report.runId, before.runId);
  assert.equal(report.startedAt, before.startedAt);
  assert.deepEqual(f.ran, PLAN.slice(failed));
  assert.deepEqual(report.invocations.map(item => item.status), ['failed', 'passed']);
  assert.deepEqual(report.invocations[0].ran, PLAN.slice(0, failed + 1));
  assert.deepEqual(report.invocations[1].reused, PLAN.slice(0, failed));
  assert.deepEqual(report.invocations[1].ran, PLAN.slice(failed));
  const aside = join(f.attempts, 'before-invocation-2');
  const receipts = readdirSync(join(aside, 'commands')).map(name => Number.parseInt(name, 10)).sort((a, b) => a - b);
  assert.equal(receipts[0], bound + 1, 'Only receipts after the last checkpoint are set aside');
  assert.deepEqual(report.invocations[1].setAside, { directory: 'before-invocation-2',
    members: ['result.json', PLAN[failed], `${PLAN[failed]}-storage-admission.json`], commands: [bound + 1, receipts.at(-1)] });
  assert.equal(JSON.parse(readFileSync(join(aside, 'result.json'))).status, 'failed');
  assert.equal(JSON.parse(readFileSync(join(aside, PLAN[failed], 'result.json'))).status, 'failed');
  assert.deepEqual(f.json('run-state.json').checkpoints.slice(0, failed), before.checkpoints,
    'Checkpoints of the reused steps are carried forward unchanged');
  const runState = new LocalRunState(f.output);
  assert.deepEqual(report.cases.map(item => item.name), PLAN.filter(step => runState.isCase(step)));
  for (const item of report.cases) assert.equal(item.status, 'passed');
  verifyLocalHeader(report);
  assert.deepEqual(f.json('evidence-manifest.json'), evidenceInventory(f.output));
  runState.verify(report, f.inputs());
});

test('a killed run resumes from its last checkpoint and removes the container it left running', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  const first = f.gate();
  first.createState(FULL_SCOPE);
  first.caseStep('failure-control', 'fail');
  first.caseStep('timeout-control', 'timeout');
  f.interrupt(first, PLAN[2]);
  assert.equal(existsSync(join(f.output, 'result.json')), false);
  f.ran.length = 0;
  const report = f.gate(true).run();
  assert.equal(report.status, 'passed');
  assert.deepEqual(f.ran, PLAN.slice(2).filter(notInput));
  const [killed, resumed] = report.invocations;
  assert.deepEqual([killed.status, killed.completedAt, killed.ran], ['interrupted', null, PLAN.slice(0, 3)]);
  assert.deepEqual(resumed.reused, PLAN.slice(0, 2));
  assert.deepEqual(resumed.removedContainers, [LEFTOVER_CONTAINER]);
  assert.equal(f.containers.size, 0, 'The leftover owned container was removed');
  assert.deepEqual(resumed.setAside.members, [PLAN[2], `${PLAN[2]}-storage-admission.json`]);
  const receipts = join(f.attempts, 'before-invocation-2', 'commands');
  assert.ok(readdirSync(receipts).some(name => readFileSync(join(receipts, name)).length === 0),
    'The receipt cut off by the kill is preserved aside, not left in the journal');
  assert.equal(existsSync(join(f.output, 'run-state.json.tmp')), false, 'The cut-off state write was replaced');
  verifyLocalHeader(report);
  assert.deepEqual(f.json('evidence-manifest.json'), evidenceInventory(f.output));
  new LocalRunState(f.output).verify(report, f.inputs());
});

test('a leftover container that keeps a process after kill is not removed and fails the resume', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  const first = f.gate();
  first.createState(FULL_SCOPE);
  first.caseStep('failure-control', 'fail');
  f.interrupt(first, 'timeout-control');
  f.containers.get(LEFTOVER_CONTAINER).stuck = true;
  assert.throws(() => f.gate(true).run(), /The owned container still has a process after kill/);
  assert.equal(f.containers.has(LEFTOVER_CONTAINER), true, 'A container that still has a process is left in place');
});

test('resume refuses a changed controller, platform, source, tool, runtime or image and leaves the run untouched', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  f.failRun('v1.3.1-node20.20.2');
  const statePath = join(f.output, 'run-state.json');
  const before = f.tree();
  const add = path => {
    writeFileSync(path, 'SYNTHETIC unbound addition');
    return () => rmSync(path);
  };
  const changes = [
    [/the controller binding differs/, () => {
      // A live controller edit cannot be staged inside the repository under test, so the run records another one.
      const value = f.json('run-state.json');
      value.binding.controller.files[0].sha256 = '0'.repeat(64);
      value.binding.controller.sha256 = localCommitment(value.binding.controller.files);
      value.bindingSha256 = localCommitment(value.binding);
      for (const invocation of value.invocations) invocation.bindingSha256 = value.bindingSha256;
      return f.replace(statePath, JSON.stringify(value));
    }],
    [/the platform binding differs/, () => {
      f.server.Version = '24.0.7';
      return () => { f.server.Version = '20.10.15+azure'; };
    }],
    [/the platform binding differs/, () => {
      f.windows.ubr++;
      return () => { f.windows.ubr--; };
    }],
    [/the sources binding differs/, () => {
      f.heads.set(f.roots[0], 'f'.repeat(40));
      return () => f.heads.set(f.roots[0], 'a'.repeat(40));
    }],
    [/the sources binding differs/, () => f.replace(join(f.roots[1], 'node_modules', 'retained.js'), 'changed peer dependency')],
    [/the tools binding differs/, () => add(join(f.tools.pwsh, 'added.dll'))],
    [/the tools binding differs/, () => f.replace(join(f.tools.npm, 'tool.bin'), 'changed npm')],
    [/the tools binding differs/, () => f.replace(join(f.tools.native, 'tool.bin'), 'changed native archive')],
    [/the tools binding differs/, () => f.replace(join(f.tools.git, 'cmd', 'git.exe'), 'changed git')],
    [/the nodes binding differs/, () => f.replace(join(f.tools.node, 'node-v22.23.2-win-x64', 'node.exe'), 'changed runtime')],
  ];
  for (const [pattern, change] of changes) {
    const undo = change();
    assert.throws(() => f.gate(true), pattern);
    undo();
    assert.deepEqual(f.tree(), before, `${pattern} refusal changed the run`);
  }
  assert.throws(() => f.gate(true, { image: `sha256:${'0'.repeat(64)}` }), /the image binding differs/);
  assert.deepEqual(f.tree(), before);
  assert.equal(f.gate(true).run().status, 'passed', 'The unchanged run still resumes');
});

test('resume refuses tampered reused evidence or an unexplained run member and leaves the run untouched', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  f.failRun('v1.3.1-node20.20.2');
  const tampering = [
    [/Reused evidence changed after it passed: failure-control/, join('failure-control', 'guest', 'runtime.json')],
    [/Reused evidence changed after it passed: audit-v2\.1\.0-node20\.20\.2/, 'audit-v2.1.0-node20.20.2-storage-admission.json'],
    [/Reused evidence changed after it passed: session-lane/, 'session-lane.json'],
    [/Reused evidence changed after it passed: inputs-2\.1\.0/, join('inputs-2.1.0', 'manifest.json')],
    [/Reused evidence changed after it passed: inputs-1\.3\.1/, join('inputs-1.3.1', 'source', 'package.json')],
    [/Command receipts changed after they were checkpointed/, join('commands', '2.json')],
    [/The frozen runtime differs/, join('runtime', 'node-v20.20.2-win-x64', 'node.exe')],
    [/The frozen controller differs/, join('controller', 'tools', 'npm-publication', 'local-inputs.mjs')],
    [/Checkpoints do not follow the run plan/, 'run-state.json', bytes => {
      const value = JSON.parse(bytes);
      value.checkpoints.reverse();
      return JSON.stringify(value);
    }],
  ];
  for (const [pattern, member, change = bytes => Buffer.concat([bytes, Buffer.from(' ')])] of tampering) {
    const path = join(f.output, member);
    const undo = f.replace(path, change(readFileSync(path)));
    const before = f.tree();
    assert.throws(() => f.gate(true), pattern, member);
    assert.deepEqual(f.tree(), before, `${member}: a refused resume changed the run`);
    undo();
  }
  for (const [pattern, member] of [
    [/Unexpected run member; refusing to resume: notes\.txt/, 'notes.txt'],
    [/Unexpected private Docker configuration/, join('docker-config', 'config.json')],
  ]) {
    writeFileSync(join(f.output, member), '{}');
    const before = f.tree();
    assert.throws(() => f.gate(true), pattern);
    assert.deepEqual(f.tree(), before);
    rmSync(join(f.output, member));
  }
  renameSync(join(f.output, 'timeout-control'), join(f.home, 'timeout-control'));
  assert.throws(() => f.gate(true), /Reused evidence is missing: timeout-control/);
  renameSync(join(f.home, 'timeout-control'), join(f.output, 'timeout-control'));
  assert.equal(existsSync(f.attempts), false);
  assert.equal(f.gate(true).run().status, 'passed', 'The restored run still resumes');
});

test('resume refuses a passed run, a controls-only run, a run without durable state and a stepped-back clock', { skip: CONTROLLER_SKIP }, t => {
  const passed = new ResumeFixture(t);
  passed.gate().run();
  assert.throws(() => passed.gate(true), /This run already passed; there is nothing to resume/);
  const controls = new ResumeFixture(t);
  controls.failures.add('timeout-control');
  assert.throws(() => controls.gate().run({ controlsOnly: true }), { message: 'SYNTHETIC failure: timeout-control' });
  assert.throws(() => controls.gate(true), /Only a full qualification run can be resumed/);
  const unbound = new ResumeFixture(t);
  unbound.failRun('failure-control');
  rmSync(join(unbound.output, 'run-state.json'));
  assert.throws(() => unbound.gate(true), /no run-state\.json/);
  const clock = new ResumeFixture(t);
  clock.failRun('timeout-control');
  const state = clock.json('run-state.json');
  state.invocations[0].completedAt = new Date(Date.now() + 3_600_000).toISOString();
  writeFileSync(join(clock.output, 'run-state.json'), JSON.stringify(state));
  const before = clock.tree();
  assert.throws(() => clock.gate(true), /Invocations overlap or are out of order/);
  assert.deepEqual(clock.tree(), before, 'A clock that stepped back is refused before anything is recorded');
});

test('a run proves its inventory before it passes, and a pass cut off before its inventory resumes', { skip: CONTROLLER_SKIP }, t => {
  const stray = new ResumeFixture(t);
  stray.hooks.set(PLAN.at(-1), gate => writeFileSync(join(gate.output, 'notes.txt'), 'SYNTHETIC stray member'));
  assert.throws(() => stray.gate().run(), /Missing or unexpected local run members/);
  assert.equal(stray.json('result.json').status, 'failed');
  assert.equal(stray.json('run-state.json').invocations[0].status, 'failed');
  assert.equal(existsSync(join(stray.output, 'evidence-manifest.json')), false);
  rmSync(join(stray.output, 'notes.txt'));
  stray.hooks.clear();
  stray.ran.length = 0;
  assert.equal(stray.gate(true).run().status, 'passed');
  assert.deepEqual(stray.ran, [], 'Nothing reruns once the stray member is gone');
  const cut = new ResumeFixture(t);
  cut.gate().run();
  // The process died after recording the pass and before writing the inventory.
  rmSync(join(cut.output, 'evidence-manifest.json'));
  cut.ran.length = 0;
  const report = cut.gate(true).run();
  assert.equal(report.status, 'passed');
  assert.deepEqual(cut.ran, []);
  assert.deepEqual(report.invocations.map(item => item.status), ['failed', 'passed']);
  assert.equal(report.invocations[0].error, 'The run passed but its evidence inventory was not written');
  assert.deepEqual(report.invocations[1].setAside.members, ['result.json']);
  assert.deepEqual(cut.json('evidence-manifest.json'), evidenceInventory(cut.output));
  new LocalRunState(cut.output).verify(report, cut.inputs());
});

test('only an absent or partly written inventory reopens a passed run; anything else refuses', { skip: CONTROLLER_SKIP }, t => {
  for (const partial of [bytes => bytes.subarray(0, bytes.length >> 1), () => Buffer.alloc(0)]) {
    const f = new ResumeFixture(t);
    f.gate().run();
    // The process died part way through writing the inventory.
    const path = join(f.output, 'evidence-manifest.json');
    writeFileSync(path, partial(readFileSync(path)));
    f.ran.length = 0;
    const report = f.gate(true).run();
    assert.equal(report.status, 'passed');
    assert.deepEqual(f.ran, []);
    assert.equal(report.invocations[0].error, 'The run passed but its evidence inventory was not written');
    assert.deepEqual(report.invocations[1].setAside.members, ['evidence-manifest.json', 'result.json']);
    new LocalRunState(f.output).verify(report, f.inputs());
  }
  const f = new ResumeFixture(t);
  f.gate().run();
  const before = f.tree();
  const link = (target, name) => {
    linkSync(target, join(f.home, name));
    return () => rmSync(join(f.home, name));
  };
  for (const [pattern, change] of [
    [/The evidence changed after the run passed/, () => {
      const path = join(f.output, 'result.json');
      return f.replace(path, Buffer.concat([readFileSync(path), Buffer.from(' ')]));
    }],
    [/Missing, linked, empty or oversized local evidence/, () => link(join(f.output, 'evidence-manifest.json'), 'manifest')],
    [/Hardlinked evidence is not independent/, () => link(join(f.output, 'failure-control', 'guest', 'runtime.json'), 'runtime')],
  ]) {
    const undo = change();
    const changed = f.tree();
    assert.throws(() => f.gate(true), pattern);
    assert.deepEqual(f.tree(), changed, `${pattern}: a refused resume changed the run`);
    undo();
  }
  assert.deepEqual(f.tree(), before);
  assert.throws(() => f.gate(true), /This run already passed; there is nothing to resume/);
});

test('a run state that cannot be recorded still writes the report and never hides the original error', { skip: CONTROLLER_SKIP }, t => {
  for (const [failed, message] of [[false, 'SYNTHETIC state write failure'], [true, 'SYNTHETIC failure: failure-control']]) {
    const f = new ResumeFixture(t);
    if (failed) f.failures.add('failure-control');
    const gate = f.gate();
    const create = gate.createState.bind(gate);
    gate.createState = scope => {
      create(scope);
      gate.state.finish = () => {
        throw new Error('SYNTHETIC state write failure');
      };
    };
    assert.throws(() => gate.run(), { message });
    const report = f.json('result.json');
    assert.equal(report.status, 'failed');
    assert.match(report.error, /The run state was not recorded: SYNTHETIC state write failure$/);
    if (failed) assert.match(report.error, /^SYNTHETIC failure: failure-control; /);
    assert.equal(existsSync(join(f.output, 'evidence-manifest.json')), false);
  }
});

test('a resume killed while setting evidence aside leaves a contiguous journal and resumes again', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  f.hooks.set('timeout-control', gate => {
    for (let index = 0; index < 3; index++) gate.docker(['logs', 'SYNTHETIC']);
  });
  f.failRun('timeout-control');
  const bound = f.json('run-state.json').checkpoints.at(-1).commands;
  const total = readdirSync(join(f.output, 'commands')).length;
  const move = LocalRunState.prototype.move;
  let moved = 0;
  LocalRunState.prototype.move = function (source, target) {
    if (source.includes(`${sep}commands${sep}`) &&
        ++moved > 2) throw new Error('SYNTHETIC kill while setting evidence aside');
    return move.call(this, source, target);
  };
  try {
    assert.throws(() => f.gate(true), /SYNTHETIC kill while setting evidence aside/);
  } finally {
    LocalRunState.prototype.move = move;
  }
  const left = readdirSync(join(f.output, 'commands')).map(name => Number.parseInt(name, 10)).sort((a, b) => a - b);
  assert.deepEqual(left, Array.from({ length: total - 2 }, (_, index) => index + 1),
    'Receipts move from the highest down, so the journal left behind is a contiguous prefix');
  const report = f.gate(true).run();
  assert.equal(report.status, 'passed');
  assert.deepEqual(report.invocations.map(item => item.status), ['failed', 'interrupted', 'passed']);
  assert.deepEqual(report.invocations[1].setAside.commands, [bound + 1, total]);
  assert.deepEqual(report.invocations[2].setAside, { directory: 'before-invocation-3', members: [],
    commands: [bound + 1, total - 2] });
  assert.equal(readdirSync(join(f.attempts, 'before-invocation-2', 'commands')).length, 2);
  verifyLocalHeader(report);
  assert.deepEqual(f.json('evidence-manifest.json'), evidenceInventory(f.output));
  new LocalRunState(f.output).verify(report, f.inputs());
});

test('a resume recovers from a failed input step, a failed or unverified session lane and a failed final check', { skip: CONTROLLER_SKIP }, t => {
  const inputs = new ResumeFixture(t);
  inputs.failRun('inputs-1.3.1');
  const fromInputs = inputs.gate(true).run();
  assert.deepEqual(fromInputs.invocations[1].ran, PLAN.slice(PLAN.indexOf('inputs-1.3.1')));
  assert.deepEqual(fromInputs.invocations[1].setAside.members, ['inputs-1.3.1', 'result.json']);
  new LocalRunState(inputs.output).verify(fromInputs, inputs.inputs());
  const plain = new ResumeFixture(t);
  plain.failRun('session-lane');
  const fromPlain = plain.gate(true).run();
  assert.deepEqual(fromPlain.invocations[1].ran, PLAN.slice(PLAN.indexOf('session-lane')));
  assert.deepEqual(fromPlain.invocations[1].setAside.members, ['result.json']);
  new LocalRunState(plain.output).verify(fromPlain, plain.inputs());
  const lane = new ResumeFixture(t);
  const restore = [];
  lane.hooks.set('session-lane', () => {
    restore.push(lane.replace(join(lane.roots[0], 'node_modules', 'retained.js'), 'edited while the lane ran'));
  });
  assert.throws(() => lane.gate().run(), /Input inventory or content changed/);
  restore.pop()();
  lane.hooks.clear();
  const fromLane = lane.gate(true).run();
  assert.deepEqual(fromLane.invocations[1].ran, PLAN.slice(PLAN.indexOf('session-lane')));
  assert.ok(fromLane.invocations[1].setAside.members.includes('session-lane.json'),
    'A receipt whose tree changed is set aside, not reused');
  new LocalRunState(lane.output).verify(fromLane, lane.inputs());
  const final = new ResumeFixture(t);
  final.hooks.set(PLAN.at(-1), () => {
    restore.push(final.replace(join(final.tools.pwsh, 'tool.bin'), 'edited after the last case'));
  });
  assert.throws(() => final.gate().run(), /Input inventory or content changed/);
  assert.equal(final.json('run-state.json').checkpoints.length, PLAN.length);
  restore.pop()();
  final.hooks.clear();
  final.ran.length = 0;
  const fromFinal = final.gate(true).run();
  assert.equal(fromFinal.status, 'passed');
  assert.deepEqual(final.ran, [], 'Every step is reused');
  assert.deepEqual([fromFinal.invocations[1].reused, fromFinal.invocations[1].ran], [PLAN, []]);
  new LocalRunState(final.output).verify(fromFinal, final.inputs());
});

test('the launcher resolves one run path and keeps strict argument positions', t => {
  const run = join(directory(t), 'run1');
  const values = ['--npm-cli', join(run, 'npm-cli.js'), '--peer-root', join(run, 'peer'), '--resume', `${run}${sep}`,
    '--node-root', join(run, 'nodes'), '--pwsh-root', join(run, 'pwsh')];
  const parsed = launcherArguments(values);
  assert.equal(parsed.options.output, run, 'A trailing separator names the same run');
  assert.deepEqual([parsed.controlsOnly, parsed.options.resume], [false, true]);
  assert.equal(launcherArguments([...values.slice(0, 4), '--output', `${run}${sep}`, ...values.slice(6)]).options.output, run);
  assert.throws(() => launcherArguments([...values, '--controls-only']), /Only a full qualification run can be resumed/);
  assert.throws(() => launcherArguments([...values.slice(4, 6), ...values.slice(0, 4), ...values.slice(6)]),
    { message: /^Usage: local-windows\.mjs/ });
  assert.throws(() => launcherArguments([...values.slice(0, 5), 'relative-run', ...values.slice(6)]),
    /Absolute paths required/);
  const script = fileURLToPath(new URL('../../tools/npm-publication/local-windows.mjs', import.meta.url));
  const launched = spawnSync(process.execPath, [script, ...values, '--controls-only'],
    { encoding: 'utf8', windowsHide: true, timeout: 60_000 });
  assert.equal(launched.status, 1);
  assert.match(launched.stderr, /Only a full qualification run can be resumed/);
});

test('a trailing separator on --resume names the same run and keeps the attempts directory beside it', { skip: CONTROLLER_SKIP }, t => {
  const f = new ResumeFixture(t);
  f.failRun('timeout-control');
  const { options } = launcherArguments(['--npm-cli', join(f.tools.npm, 'npm-cli.js'), '--peer-root', f.roots[1],
    '--resume', `${f.output}${sep}`, '--node-root', f.tools.node, '--pwsh-root', f.tools.pwsh]);
  assert.equal(f.gate(true, { output: options.output }).run().status, 'passed');
  assert.equal(existsSync(join(f.attempts, 'before-invocation-2', 'timeout-control')), true);
  assert.equal(existsSync(join(f.output, '.attempts')), false, 'Nothing is set aside inside the run');
});

test('the launcher refuses an unnormalized run path before touching it', { skip: process.platform !== 'win32' }, t => {
  const base = directory(t);
  assert.throws(() => new WindowsLocalGate({ output: `${join(base, 'run1')}${sep}`,
    npmCli: join(base, 'npm', 'bin', 'npm-cli.js'), peerRoot: join(base, 'peer'), nodeRoot: join(base, 'nodes'),
    pwshRoot: join(base, 'pwsh') }), /The run directory path must be normalized/);
  assert.deepEqual(readdirSync(base), []);
});

test('the platform binding reads the Docker engine and the Windows build and refuses unreadable output', t => {
  const f = new ResumeFixture(t);
  const gate = Object.create(WindowsLocalGate.prototype);
  gate.config = join(f.home, 'docker-config');
  gate.probe = (file, args) => f.probe(file, args);
  assert.deepEqual(gate.platform(), { docker: { version: '20.10.15+azure', apiVersion: '1.41', os: 'windows',
    kernelVersion: f.server.KernelVersion }, windows: { build: '26300', ubr: 9457 } });
  delete f.server.ApiVersion;
  assert.throws(() => gate.platform(), /Unreadable Docker engine version/);
  f.server.ApiVersion = '1.41';
  gate.probe = (file, args) => file === 'reg' ? '    CurrentBuildNumber    REG_SZ    26300\r\n' : f.probe(file, args);
  assert.throws(() => gate.platform(), /Unreadable Windows build/);
});

test('the read-only source probe lists exactly the files the frozen input copies', { skip: process.platform !== 'win32' }, t => {
  const base = directory(t);
  const root = join(base, 'source');
  mkdirSync(join(root, 'src'), { recursive: true });
  writeFileSync(join(root, 'package.json'), '{"version":"2.1.0"}\n');
  writeFileSync(join(root, '.gitignore'), 'ignored.log\nbuild/\n');
  writeFileSync(join(root, 'src', 'kept.mjs'), 'tracked');
  writeFileSync(join(root, 'src', 'deleted.mjs'), 'tracked, then deleted');
  const reader = new LocalSourceReader(root);
  reader.git(['init', '--quiet']);
  reader.git(['add', '--', '.']);
  reader.git(['-c', 'user.name=Local fixture', '-c', 'user.email=fixture@invalid.invalid',
    '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Owned source probe fixture']);
  rmSync(join(root, 'src', 'deleted.mjs'));
  mkdirSync(join(root, 'notes'));
  writeFileSync(join(root, 'notes', 'untracked.mjs'), 'untracked');
  writeFileSync(join(root, 'ignored.log'), 'ignored');
  mkdirSync(join(root, 'build'));
  writeFileSync(join(root, 'build', 'output.js'), 'ignored');
  const gate = Object.create(WindowsLocalGate.prototype);
  gate.output = join(base, 'run');
  mkdirSync(join(gate.output, 'commands'), { recursive: true });
  gate.config = join(base, 'docker-config');
  mkdirSync(gate.config);
  gate.env = gate.hostEnvironment();
  gate.deadline = performance.now() + 60_000;
  gate.commandIndex = 0;
  gate.cleaning = false;
  gate.gitRoot = gate.gitRootOf(gate.probe('git', ['--exec-path']));
  const journaled = gate.sourceNames(root);
  const probed = gate.readSource(root);
  assert.deepEqual(journaled, ['.gitignore', 'notes/untracked.mjs', 'package.json', 'src/kept.mjs']);
  assert.deepEqual(probed.names, journaled, 'The binding and the frozen input must select the same files');
  assert.equal(probed.head, gate.git(root, ['rev-parse', 'HEAD']).trim());
  assert.equal(probed.version, '2.1.0');
});

test('one run directory admits one live launcher at a time', { skip: process.platform !== 'win32' }, async t => {
  const output = join(directory(t), 'run');
  const first = new LocalRunLock(output);
  await first.acquire();
  await assert.rejects(new LocalRunLock(output).acquire(), /Another invocation is already using this run directory/);
  await first.release();
  const next = new LocalRunLock(output);
  await next.acquire();
  await next.release();
});

test('a killed launcher releases its run lock', { skip: process.platform !== 'win32' }, async t => {
  const output = join(directory(t), 'run');
  const module = new URL('../../tools/npm-publication/local-run-state.mjs', import.meta.url).href;
  const holder = spawn(process.execPath, ['--input-type=module', '-e', [
    `const { LocalRunLock } = await import(${JSON.stringify(module)});`,
    `await new LocalRunLock(${JSON.stringify(output)}).acquire();`,
    "console.log('locked');",
    'setInterval(() => {}, 1000);',
  ].join('\n')], { stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true });
  t.after(() => holder.kill());
  await new Promise((accept, reject) => {
    holder.stdout.on('data', chunk => {
      if (chunk.toString().includes('locked')) accept();
    });
    holder.once('exit', code => reject(new Error(`The lock holder exited early: ${code}`)));
  });
  await assert.rejects(new LocalRunLock(output).acquire(), /Another invocation is already using this run directory/);
  const exited = new Promise(accept => holder.once('exit', accept));
  holder.kill();
  await exited;
  const next = new LocalRunLock(output);
  await next.acquire();
  await next.release();
});
