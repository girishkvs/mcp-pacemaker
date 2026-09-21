import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  LocalGate, HOSTED_BOUNDARIES, SOURCE_SUITE_TIMEOUT_MS, localEnvironment, testArguments, testTotals,
} from '../../tools/npm-publication/local-gate.mjs';
import { evidenceEntryFilter, validateContainer, WindowsLocalGate } from '../../tools/npm-publication/local-windows.mjs';
import { InputSnapshot, safeName, verifyManifest, writeManifest } from '../../tools/npm-publication/local-inputs.mjs';
import { LocalGitConfig } from '../../tools/npm-publication/local-git.mjs';
import { LocalSourceReader } from '../../tools/npm-publication/local-source.mjs';
import { bindGuestIdentity, windowsSystemEnvironment } from '../../tools/npm-publication/local-environment.mjs';

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
  for (const script of [
    'node --test', 'echo passed', 'node --test --test-name-pattern=missing test/a.test.mjs',
    'node --test test/a.test.mjs && exit 0', 'node --test test/a.test.mjs test/a.test.mjs',
    'node --test test/a.test.mjs;exit', 'node --test ../test/a.test.mjs',
    'node --test test/../a.test.mjs',
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
    MCP_POOLING_TRACE_ARTIFACT_DIR: 'unowned', DOCKER_HOST: 'tcp://invalid.invalid' };
  const env = localEnvironment(parent, join(directory(t), 'home'));
  for (const key of ['NPM_TOKEN', 'GITHUB_TOKEN', 'NODE_OPTIONS', 'HTTPS_PROXY', 'GITHUB_ACTIONS',
    'RUNNER_ENVIRONMENT', 'MCP_BRIDGE_PORT', 'MCP_POOLING_TRACE_ARTIFACT_DIR', 'DOCKER_HOST']) {
    assert.equal(env[key], undefined, key);
  }
  assert.equal(env.npm_config_offline, 'true');
  assert.equal(env.npm_config_ignore_scripts, 'true');
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
  assert.equal(records[1].timeoutMs, 25 * 60_000);
  assert.throws(() => gate.command('over-budget command', process.execPath, ['-e', 'process.exit(0)'],
    gate.root, false, SOURCE_SUITE_TIMEOUT_MS + 1), /Invalid command deadline/);
  assert.equal(gate.steps.length, 2);
  const outer = Object.create(WindowsLocalGate.prototype);
  assert.equal(outer.caseTimeout('gate'), 30 * 60_000);
  assert.equal(outer.caseTimeout('fail'), 20 * 60_000);
  for (const mode of ['timeout', 'timeout-early-exit']) assert.equal(outer.caseTimeout(mode), 15_000);
  assert.throws(() => outer.caseTimeout('unknown'), /Unsupported local case mode/);
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

test('actual tool input wiring rejects top-level npm and pwsh additions, including empty directories', t => {
  for (const tool of ['npm', 'pwsh']) {
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
      for (const name of ['npm', 'pwsh', 'git']) {
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
  assert.deepEqual(binding.options(), ['-c', `core.worktree=${gate.root}`, '-c', 'extensions.worktreeConfig=false']);
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
