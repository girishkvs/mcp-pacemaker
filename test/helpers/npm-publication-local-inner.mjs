import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import net from 'node:net';
import {
  LocalGate, localEnvironment, main, retainedDependencies, testArguments, testTotals,
  SOURCE_SUITE_TIMEOUT_MS, uiTestArguments, validateContainment,
} from '../../tools/npm-publication/local-gate.mjs';
import { AUDIT_MODE, AUDIT_MODE_VARIABLE } from '../../tools/npm-publication/local-audit-report.mjs';
import { validateSdkContract } from '../../tools/npm-publication/local-sdk-check.mjs';
import { CURRENT_REF } from '../../tools/compatibility/fixtures.mjs';
import { POLICY, channelFor, digest } from '../../tools/npm-publication/policy.mjs';
import { verifyStaged } from '../../tools/npm-publication/verify-staged.mjs';
import { stageCaptureFixture } from './stage-capture-fixture.mjs';
import { stageProofFixture } from './stage-proof-fixture.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SDK = new URL('../../tools/npm-publication/local-sdk-check.mjs', import.meta.url).href;
const integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;

function write(root, path, bytes) {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), bytes);
}

function fixture(t, separateWork = false) {
  const parent = realpathSync.native(mkdtempSync(join(tmpdir(), 'publication-inner-unit-')));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const root = join(parent, 'source');
  mkdirSync(root);
  const npmCli = join(parent, 'npm/bin/npm-cli.js');
  write(parent, 'npm/package.json', JSON.stringify({ name: 'npm', version: POLICY.npm }));
  write(parent, 'npm/bin/npm-cli.js', 'throw new Error("Unit fixture must never execute npm");');
  return new LocalGate({ root, npmCli, output: join(parent, 'evidence'),
    workRoot: separateWork ? join(parent, 'work') : undefined });
}

function dependency(root) {
  const path = 'node_modules/fixture-public';
  const metadata = { version: '1.0.0', integrity, resolved: `${POLICY.registry}fixture-public/-/fixture-public-1.0.0.tgz` };
  write(root, `${path}/package.json`, JSON.stringify({ name: 'fixture-public', version: metadata.version, license: 'MIT' }));
  write(root, `${path}/LICENSE`,
    'MIT License\nCopyright Local Fixture\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files.');
  for (const file of ['package-lock.json', 'node_modules/.package-lock.json']) {
    write(root, file, JSON.stringify({ lockfileVersion: 3, packages: { [path]: metadata } }));
  }
  return { path, name: 'fixture-public', version: metadata.version, integrity };
}

class SdkFixture {
  constructor(t) {
    this.gate = fixture(t, true);
    this.runs = 0;
    this.version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
    for (const directory of ['npm-publication', 'compatibility', 'publication-scanners',
      'npm-consumer', 'third-party-notices']) {
      cpSync(join(ROOT, 'tools', directory), join(this.gate.root, 'tools', directory), { recursive: true });
    }
    for (const path of ['package.json', 'tools/npm-publication/local-sdk-check.mjs',
      'tools/npm-publication/policy.mjs', 'tools/npm-publication/local-regression.mjs',
      'tools/npm-publication/verify-staged.mjs']) {
      write(this.gate.root, path, readFileSync(join(ROOT, path)));
    }
    const npm = dirname(dirname(this.gate.npmCli));
    write(npm, 'node_modules/sigstore/package.json', '{"name":"sigstore","version":"5.0.0","main":"index.js"}');
    write(npm, 'node_modules/sigstore/index.js',
      'exports.verify = () => { throw new Error("Unit stub must never verify a signature"); };');
    if (this.version === '2.0.1') {
      // Only dispatch/shape stubs. No retained npm modules, authentication or signature generation.
      write(this.gate.root, 'tools/npm-publication/owner-sdk.mjs', `
        export const PROFILE_SOURCE_SHA256 = '1'.repeat(64);
        export function loadOwnerLibraries(cli) {
          if (cli !== ${JSON.stringify(this.gate.npmCli)}) throw new Error('Wrong CLI');
          const forbidden = () => { throw new Error('Unit stub must never perform owner operations'); };
          const registry = Object.assign(forbidden, {
            json: Object.assign(() => forbidden(), { stream: () => forbidden() }),
          });
          return { registry, publish: forbidden,
            profile: { get: forbidden, loginWeb: forbidden, webAuthOpener: forbidden },
            pacote: { manifest: forbidden } };
        }
      `);
      write(this.gate.root, 'tools/npm-publication/provenance.mjs', `
        export const PROVENANCE_SOURCE_SHA256 = '2'.repeat(64);
        export function npmProvenance(cli) {
          if (cli !== ${JSON.stringify(this.gate.npmCli)}) throw new Error('Wrong CLI');
          const forbidden = () => { throw new Error('Unit stub must never sign or verify'); };
          return { verifyBundle: forbidden, generate: forbidden,
            subject: (name, version, sha512) => ({ name: 'pkg:npm/' + name + '@' + version, digest: { sha512 } }) };
        }
      `);
    }
  }

  run() {
    const env = localEnvironment(process.env, join(this.gate.work, `smoke-home-${this.runs++}`));
    const module = pathToFileURL(join(this.gate.root, 'tools/npm-publication/local-sdk-check.mjs')).href;
    const pkg = JSON.parse(readFileSync(join(this.gate.root, 'package.json'), 'utf8'));
    const source = `
      import assert from 'node:assert/strict';
      import { blockSdkTransports, loadLaneSdk, main } from ${JSON.stringify(module)};
      if (process.version === ${JSON.stringify(`v${POLICY.node}`)}) {
        await main([${JSON.stringify(this.gate.npmCli)}]);
      } else {
        const attempts = blockSdkTransports();
        const result = await loadLaneSdk(${JSON.stringify(this.gate.npmCli)}, ${JSON.stringify(pkg.version)});
        assert.deepEqual(attempts, { network: 0, subprocess: 0 });
        console.log(JSON.stringify({ kind: 'unit-stubs-only', ...result }));
      }
    `;
    return spawnSync(process.execPath, ['--input-type=module', '-e', source], {
      env, shell: false, windowsHide: true, encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024,
    });
  }
}

test('actual lane UI manifest selects existing tests or the legitimate legacy absence', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const ui = JSON.parse(readFileSync(join(ROOT, 'ui/package.json'), 'utf8'));
  const selected = uiTestArguments(ROOT, pkg.version);
  if (Object.hasOwn(ui.scripts, 'test')) {
    assert.deepEqual(selected, testArguments(ui.scripts.test));
    assert.ok(selected.length > 2);
  } else {
    assert.equal(pkg.version, '1.3.1');
    assert.equal(existsSync(join(ROOT, 'ui/test')), false);
    assert.equal(selected, null);
  }
});

test('only legacy may omit UI tests; new scripts and nested files must all be selected', t => {
  const gate = fixture(t);
  const ui = JSON.parse(readFileSync(join(ROOT, 'ui/package.json'), 'utf8'));
  ui.version = '1.3.1';
  delete ui.scripts.test;
  write(gate.root, 'ui/package.json', JSON.stringify(ui));
  assert.equal(uiTestArguments(gate.root, ui.version), null);
  assert.throws(() => uiTestArguments(gate.root, '9.0.0'), /Unsupported UI test lane/);
  ui.version = '2.0.1';
  write(gate.root, 'ui/package.json', JSON.stringify(ui));
  assert.throws(() => uiTestArguments(gate.root, ui.version), /UI suite is required/);
  for (const version of ['1.3.1', '2.0.1']) {
    ui.version = version;
    ui.scripts.test = '';
    write(gate.root, 'ui/package.json', JSON.stringify(ui));
    assert.throws(() => uiTestArguments(gate.root, version));
    ui.scripts.test = 'node --test test/added.test.mjs';
    write(gate.root, 'ui/package.json', JSON.stringify(ui));
    if (!existsSync(join(gate.root, 'ui/test'))) {
      assert.throws(() => uiTestArguments(gate.root, version), /ENOENT/);
    }
    write(gate.root, 'ui/test/added.test.mjs', '// Selection fixture, never executed');
    assert.deepEqual(uiTestArguments(gate.root, version), testArguments(ui.scripts.test));
    write(gate.root, 'ui/test/nested/new.test.mjs', '// Selection fixture, never executed');
    assert.throws(() => uiTestArguments(gate.root, version), /complete UI suite/);
    ui.scripts.test += ' test/nested/new.test.mjs';
    write(gate.root, 'ui/package.json', JSON.stringify(ui));
    assert.deepEqual(uiTestArguments(gate.root, version), testArguments(ui.scripts.test));
    delete ui.scripts.test;
    write(gate.root, 'ui/package.json', JSON.stringify(ui));
    assert.throws(() => uiTestArguments(gate.root, version), /test script is required/);
    rmSync(join(gate.root, 'ui/test'), { recursive: true });
  }
});

test('TAP line parser preserves numeric, duplicate, separator and accounting semantics', () => {
  const expected = { tests: 3, pass: 2, fail: 0, cancelled: 0, skipped: 1, todo: 0 };
  const lines = Object.entries(expected).map(([key, value]) => `# ${key} ${value}`);
  for (const separator of ['\n', '\r\n', '\r', '\u2028', '\u2029']) {
    const output = lines.toReversed().join(separator);
    assert.equal(JSON.stringify(testTotals(output)), JSON.stringify(expected));
    assert.deepEqual(testTotals(`# pass invalid${separator}${output}`), expected);
    assert.throws(() => testTotals(`${output}${separator}# pass 2`), /ambiguous test total/);
  }
  const valid = lines.join('\n');
  assert.deepEqual(testTotals(valid.replace('# pass 2', '# pass 0002')), expected);
  for (const value of ['', '-2', '+2', '2.0', '2e0', ' 2', '2 ', '２', '9007199254740992']) {
    assert.throws(() => testTotals(valid.replace('# pass 2', `# pass ${value}`)));
  }
  for (const key of ['fail', 'cancelled', 'todo']) {
    assert.throws(() => testTotals(valid.replace(`# ${key} 0`, `# ${key} 1`)));
  }
  assert.throws(() => testTotals(valid.replace('# tests 3', '# tests 4')));
  assert.deepEqual(testTotals(`${'not a TAP total '.repeat(100_000)}\n${valid}`), expected);
});

test('fresh-child actual lane dispatch uses minimal stubs, never retained npm or absent legacy owner modules', t => {
  const sdk = new SdkFixture(t);
  if (sdk.version === '1.3.1') {
    for (const file of ['owner-sdk.mjs', 'provenance.mjs']) {
      assert.equal(existsSync(join(sdk.gate.root, 'tools/npm-publication', file)), false);
    }
  }
  const result = sdk.run();
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  const record = JSON.parse(result.stdout);
  assert.equal(record.contract, sdk.version === '1.3.1'
    ? 'legacy-staged-signature' : 'owner-sdk-and-provenance');
  if (sdk.version === '1.3.1') assert.equal(record.module, 'verify-staged.mjs');
  if (process.version === `v${POLICY.node}`) {
    assert.equal(record.version, sdk.version);
    for (const key of ['authenticated', 'published', 'provenanceVerified', 'signatureVerified', 'releaseReady']) {
      assert.equal(record[key], false);
    }
    assert.equal(record.networkAttempts, 0);
    assert.equal(record.subprocessAttempts, 0);
  }
});

test('SDK lane dispatch fails closed on unsupported lanes, absent modules, and invalid retained interfaces', t => {
  const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
  const changes = [
    sdk => write(sdk.gate.root, 'package.json', JSON.stringify({ name: POLICY.name, version: '9.0.0' })),
    ...(version === '1.3.1' ? [
      sdk => write(dirname(dirname(sdk.gate.npmCli)), 'package.json', '{"name":"npm","version":"11.0.0"}'),
      sdk => write(dirname(dirname(sdk.gate.npmCli)), 'node_modules/sigstore/package.json',
        '{"name":"sigstore","version":"4.0.0","main":"index.js"}'),
      sdk => write(dirname(dirname(sdk.gate.npmCli)), 'node_modules/sigstore/index.js', 'exports.verify = {};'),
      sdk => write(sdk.gate.root, 'tools/npm-publication/verify-staged.mjs', 'export const verifyStaged = {};'),
      sdk => rmSync(join(sdk.gate.root, 'tools/npm-publication/verify-staged.mjs')),
    ] : [
      sdk => rmSync(join(sdk.gate.root, 'tools/npm-publication/owner-sdk.mjs')),
      sdk => rmSync(join(sdk.gate.root, 'tools/npm-publication/provenance.mjs')),
      sdk => write(sdk.gate.root, 'tools/npm-publication/owner-sdk.mjs', 'export const loadOwnerLibraries = {};'),
    ]),
  ];
  for (const change of changes) {
    const sdk = new SdkFixture(t);
    change(sdk);
    const result = sdk.run();
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout, '', 'A failed SDK control must not emit success evidence');
  }
});

test('actual lane verifyStaged passes the exact signature callback contract and preserves verifier failure', async () => {
  const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
  const bytes = Buffer.from('Unit fixture only, not a signed package or hosted evidence');
  const source = { ref: `refs/tags/v${version}`, commit: 'a'.repeat(40),
    tagObject: 'b'.repeat(40), tree: 'c'.repeat(40) };
  const record = {
    name: POLICY.name, channel: channelFor(version),
    status: 'submitted-awaiting-owner-verification', stageId: ['11111111', '2222', '4333', '8444', '555555555555'].join('-'),
    version, source, artifact: digest(bytes), workflow: {
      ref: `${POLICY.repository}/${POLICY.workflow}@${source.ref}`, commit: source.commit, runId: '42', attempt: 1 },
    ownerPreflight: { expectedDistTags: { latest: '2.0.1' } },
  };
  const payload = {
    _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: `pkg:npm/${POLICY.name}@${version}`, digest: { sha512: record.artifact.sha512 } }],
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: {
          ref: source.ref, repository: `https://github.com/${POLICY.repository}`, path: POLICY.workflow,
        } },
        internalParameters: { github: { event_name: 'workflow_dispatch' } },
        resolvedDependencies: [{ uri: `git+https://github.com/${POLICY.repository}@${source.ref}`,
          digest: { gitCommit: source.commit } }],
      },
      runDetails: {
        builder: { id: 'https://github.com/actions/runner/github-hosted' },
        metadata: { invocationId: `https://github.com/${POLICY.repository}/actions/runs/42/attempts/1` },
      },
    },
  };
  const bundle = { dsseEnvelope: {
    payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(payload)).toString('base64'),
  } };
  const stopped = new Error('Unit-only verifier: no signature verification performed');
  let calls = 0;
  const input = {
    bytes, ...stageCaptureFixture(record, bundle), currentTags: record.ownerPreflight.expectedDistTags,
    view: { id: record.stageId, packageName: POLICY.name, version, tag: channelFor(version),
      shasum: createHash('sha1').update(bytes).digest('hex') },
    verifyBundle: async (actual, options) => {
      calls++;
      assert.deepEqual(actual, bundle, 'The exact captured JSON bytes must reach the signature verifier');
      assert.deepEqual(Object.keys(options).sort(),
        ['certificateIdentityURI', 'certificateIssuer', 'ctLogThreshold', 'tlogThreshold']);
      assert.equal(options.certificateIssuer, 'https://token.actions.githubusercontent.com');
      assert.equal(options.ctLogThreshold, 1);
      assert.equal(options.tlogThreshold, 1);
      const identity = new RegExp(options.certificateIdentityURI);
      const expected = `https://github.com/${POLICY.repository}/${POLICY.workflow}@${source.ref}`;
      assert.ok(identity.test(expected));
      assert.equal(identity.test(`${expected}-different`), false);
      throw stopped;
    },
  };
  await assert.rejects(verifyStaged(input), error => error === stopped);
  assert.equal(calls, 1);
  payload.subject[0].digest.sha512 = 'b'.repeat(128);
  bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(payload)).toString('base64');
  await assert.rejects(verifyStaged({ ...input, ...stageCaptureFixture(record, bundle) }));
  assert.equal(calls, 1, 'Mismatched subject must fail before the signature callback');
});

test('inner full run refuses absent containment before any child or source action, including env-only claims', async t => {
  const gate = fixture(t);
  gate.env.MCP_LOCAL_GATE_GUEST = 'parent-token-not-authority';
  gate.command = () => assert.fail('No full action may run without containment');
  gate.snapshot = () => assert.fail('No snapshot may run without containment');
  await assert.rejects(gate.run(), /isolated Windows guest|parent containment/);
  assert.deepEqual(gate.steps, []);
  assert.equal(existsSync(join(gate.output, 'result.json')), false);
});

test('default CLI cannot authorize a full run', async t => {
  const gate = fixture(t);
  const output = join(gate.output, 'default-cli');
  await assert.rejects(main(['--npm-cli', gate.npmCli, '--output', output]),
    /isolated Windows guest|parent containment/);
  assert.equal(existsSync(join(output, 'result.json')), false);
});

test('scratch roots keep homes and child temp files out of evidence; unit defaults remain available', t => {
  for (const separateWork of [false, true]) {
    const gate = fixture(t, separateWork);
    assert.equal(gate.work, separateWork ? join(dirname(gate.root), 'work') : join(gate.output, 'work'));
    const home = join(gate.work, 'home');
    for (const key of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR']) {
      assert.equal(gate.env[key], home);
    }
    assert.equal(gate.gitEmpty, join(gate.work, 'empty-git-config'));
    assert.deepEqual(readdirSync(gate.gitEmpty), []);
    assert.equal(gate.env.npm_config_cache, join(home, 'npm-cache'));
    const stdout = gate.command('Unit-only scratch paths', process.execPath, ['-e', `
      const { writeFileSync } = require('node:fs');
      const { tmpdir, homedir } = require('node:os');
      const { join } = require('node:path');
      writeFileSync(join(tmpdir(), 'unit-temp.txt'), 'disposable unit bytes');
      console.log(JSON.stringify({ temp: tmpdir(), home: homedir() }));
    `]);
    assert.deepEqual(JSON.parse(stdout), { temp: home, home });
    assert.equal(readFileSync(join(home, 'unit-temp.txt'), 'utf8'), 'disposable unit bytes');
    const step = gate.steps[0];
    assert.equal(step.file, 'command-1.json');
    assert.equal(digest(readFileSync(join(gate.output, step.file))).sha256, step.sha256);
    assert.deepEqual(readdirSync(gate.output).sort(), separateWork ? [step.file] : [step.file, 'work']);
  }
});

test('constructor rejects relative, source-local, reused or shared evidence work roots without overwrite', t => {
  const gate = fixture(t, true);
  const output = join(dirname(gate.output), 'unused-evidence');
  for (const workRoot of ['relative-work', null, gate.root, join(gate.root, 'work'), gate.work, output]) {
    assert.throws(() => new LocalGate({ root: gate.root, npmCli: gate.npmCli, output, workRoot }),
      /Absolute work root|outside the source|new work directory|must differ/);
    assert.equal(existsSync(output), false);
  }
  assert.ok(existsSync(gate.env.HOME));
});

test('inner containment requires exact guest source, evidence and private work roots plus a frozen manifest', () => {
  const binding = { kind: 'hyperv-network-none', root: 'C:\\source', output: 'C:\\output', manifestSha256: 'a'.repeat(64) };
  validateContainment(binding, 'C:\\source', 'C:\\output\\gate', 'C:\\work', 'win32');
  for (const [value, root, output, platform] of [
    [undefined, 'C:\\source', 'C:\\output\\gate', 'win32'],
    [{ ...binding, kind: 'process' }, 'C:\\source', 'C:\\output\\gate', 'win32'],
    [{ ...binding, manifestSha256: '' }, 'C:\\source', 'C:\\output\\gate', 'win32'],
    [{ ...binding, root: 'Q:\\repo' }, 'C:\\source', 'C:\\output\\gate', 'win32'],
    [binding, 'Q:\\repo', 'C:\\output\\gate', 'win32'],
    [binding, 'C:\\source', 'C:\\output', 'win32'],
    [binding, 'C:\\source', 'C:\\output\\..\\source\\gate', 'win32'],
    [binding, 'C:\\source', 'C:\\output\\other', 'win32'],
    [binding, 'C:\\source', 'D:\\elsewhere', 'win32'],
    [binding, 'C:\\source', 'C:\\output\\gate', 'linux'],
  ]) assert.throws(() => validateContainment(value, root, output, 'C:\\work', platform));
  for (const work of [undefined, '', 'work', 'C:\\source', 'C:\\output', 'C:\\output\\gate\\work',
    'C:\\work\\nested', 'C:\\work-other', 'C:\\work\\..\\output', 'D:\\work']) {
    assert.throws(() => validateContainment(binding, 'C:\\source', 'C:\\output\\gate', work, 'win32'),
      /work root|C:\\work/);
  }
});

test('publisher commands use the selected runtime without changing the source suite runtime', t => {
  const gate = fixture(t);
  const calls = [];
  gate.publisherNode = join(gate.work, 'publisher-node.exe');
  gate.command = (label, file, args) => calls.push({ file, args });
  gate.node('source', ['--test', 'test/a.test.mjs'], gate.root);
  gate.publisher('publisher', ['-p', 'process.version'], gate.root);
  assert.equal(calls[0].file, process.execPath);
  assert.equal(calls[1].file, gate.publisherNode);
});

for (const version of ['1.3.1', '2.0.1']) {
  test(`source suite child receives CI mode without hosted authority for ${version}`, t => {
    const gate = fixture(t);
    gate.env.CI = 'inherited-marker';
    const script = `process.stdout.write(JSON.stringify({
      ci: process.env.CI,
      audit: process.env[${JSON.stringify(AUDIT_MODE_VARIABLE)}],
      github: process.env.GITHUB_ACTIONS,
      token: process.env.GITHUB_TOKEN,
      npmToken: process.env.NPM_TOKEN,
      temporary: require('node:os').tmpdir(),
      physicalTemporary: require('node:fs').realpathSync.native(require('node:os').tmpdir())
    }));`;
    const output = gate.sourceSuite(gate.root, version, ['-e', script]);
    assert.deepEqual(JSON.parse(output), {
      ci: 'true', ...(version === '2.0.1' ? { audit: AUDIT_MODE } : {}),
      temporary: join(gate.work, 'source-test-temp-alias'),
      physicalTemporary: realpathSync.native(join(gate.work, 'source-test-temp')),
    });
    assert.equal(gate.env.CI, 'inherited-marker');
    assert.equal(gate.env[AUDIT_MODE_VARIABLE], undefined);
    assert.equal(gate.env.TEMP, gate.env.HOME);
    const receipt = JSON.parse(readFileSync(join(gate.output, gate.steps[0].file)));
    assert.equal(receipt.label, 'Complete source suite');
    assert.equal(receipt.executable, process.execPath);
    assert.deepEqual(receipt.args, ['-e', script]);
    assert.equal(receipt.cwd, gate.root);
    assert.equal(receipt.timeoutMs, SOURCE_SUITE_TIMEOUT_MS);
    assert.equal(receipt.exitCode, 0);
  });
}

test('SDK receives a new home rather than reusing the source suite home', t => {
  const gate = fixture(t, true);
  writeFileSync(join(gate.env.HOME, '.npmrc'), 'unit-only-never-issued-token');
  gate.command = (label, executable, args, cwd, binary, timeout, environment) => {
    assert.equal(executable, gate.publisherNode);
    assert.equal(cwd, gate.root);
    assert.equal(timeout, 15 * 60 * 1000);
    assert.notEqual(environment.HOME, gate.env.HOME);
    for (const key of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR']) {
      assert.equal(environment[key], join(gate.work, 'sdk-home'));
    }
    assert.deepEqual(readdirSync(environment.HOME).sort(), ['global.npmrc', 'user.npmrc']);
    assert.equal(existsSync(join(environment.HOME, '.npmrc')), false);
    assert.equal(environment.NODE_OPTIONS, undefined);
    assert.equal(environment.NPM_TOKEN, undefined);
    assert.equal(readFileSync(environment.npm_config_userconfig, 'utf8'), '');
    assert.equal(readFileSync(environment.npm_config_globalconfig, 'utf8'), '');
    return '{"status":"unit-fixture"}';
  };
  assert.deepEqual(gate.sdk(gate.root), { status: 'unit-fixture' });
  assert.deepEqual(readdirSync(gate.output), []);
});

test('stage proof gate uses the publisher runtime, fresh driver home and exact retained CLI', t => {
  const gate = fixture(t, true);
  const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
  gate.publisherNode = join(gate.work, 'pinned-publisher-node.exe');
  const invocation = { root: realpathSync.native(ROOT), cli: gate.npmCli, node: gate.publisherNode,
    home: join(gate.work, 'stage-proof-fixtures') };
  const proof = stageProofFixture(ROOT, version, invocation);
  let calls = 0;
  gate.command = (label, executable, args, cwd, binary, timeout, environment) => {
    calls++;
    assert.equal(label, 'Actual pinned npm stage capture, offline fixtures');
    assert.equal(executable, gate.publisherNode);
    assert.deepEqual(args, ['tools/npm-publication/local-stage-check.mjs', gate.npmCli, invocation.home]);
    assert.equal(cwd, invocation.root);
    assert.equal(binary, false);
    assert.equal(timeout, 15 * 60 * 1000);
    assert.equal(environment.HOME, join(gate.work, 'stage-proof-driver-home'));
    assert.notEqual(environment.HOME, gate.env.HOME);
    assert.equal(environment.NPM_TOKEN, undefined);
    assert.equal(environment.GITHUB_TOKEN, undefined);
    return JSON.stringify(proof);
  };
  assert.deepEqual(gate.stageCapture(invocation.root, version), proof);
  assert.equal(calls, 1);
  assert.deepEqual(readdirSync(gate.output), []);
});

test('real binary child receipts preserve every byte and real signal failures stay failures', t => {
  const gate = fixture(t);
  const bytes = gate.command('binary unit', process.execPath,
    ['-e', 'process.stdout.write(Buffer.from([0,255,128,13,10]))'], gate.root, true);
  assert.deepEqual(bytes, Buffer.from([0, 255, 128, 13, 10]));
  const receipt = readFileSync(join(gate.output, gate.steps[0].file));
  assert.equal(digest(receipt).sha256, gate.steps[0].sha256);
  assert.deepEqual(Buffer.from(JSON.parse(receipt).stdout, 'base64'), bytes);
  assert.throws(() => gate.command('signal unit', process.execPath,
    ['-e', 'process.kill(process.pid, "SIGTERM")']), /terminated|failed/);
  assert.notEqual(gate.steps[1].exitCode, 0);
});

test('Git refuses inherited includes, hooks, filters and remote verbs before repository operations', t => {
  const gate = fixture(t);
  gate.command = (label, executable, args, cwd) => {
    assert.equal(label, 'Parse local Git configuration');
    const result = spawnSync(executable, args, {
      cwd, env: gate.env, encoding: 'utf8', shell: false, windowsHide: true,
      timeout: 5000, maxBuffer: 1024 * 1024,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  for (const text of [
    '[include]\npath=untrusted\n', '[includeIf "gitdir:*"]\npath=untrusted\n',
    '[filter "candidate"]\nclean=untrusted\n', '[core]\nhooksPath=untrusted\n',
    '[core]\nfsmonitor=untrusted\n', '[extensions]\nworktreeConfig=true\n',
  ]) {
    write(gate.root, '.git/config', text);
    assert.throws(() => gate.git(['ls-files']), /Inherited executable Git/);
  }
  for (const verb of ['fetch', 'push', 'pull', 'remote', 'ls-remote', 'submodule']) {
    assert.throws(() => gate.git([verb, 'origin']), /forbids/);
  }
});

test('checkout stages only the physical candidate from an empty index, including ignored tracked files', t => {
  const gate = fixture(t, true);
  write(gate.root, 'kept.mjs', 'candidate bytes\r\n');
  write(gate.root, 'ignored.log', 'tracked despite ignore');
  mkdirSync(join(gate.root, 'node_modules'));
  mkdirSync(join(gate.root, 'ui/node_modules'), { recursive: true });
  const snapshot = ['kept.mjs', 'ignored.log'].map(path => ({ path }));
  const calls = [];
  let index = new Set(['kept.mjs', 'deleted.mjs']);
  gate.git = (args, cwd) => {
    calls.push(args);
    if (args[0] === 'clone') mkdirSync(args.at(-1));
    if (args[0] === 'read-tree') {
      assert.deepEqual(args, ['read-tree', '--empty']);
      index = new Set();
    }
    if (args.includes('add')) {
      assert.equal(index.size, 0, 'Baseline entries would restore deleted files');
      assert.ok(args.includes('--force'), 'Ignored but tracked candidate files must not be lost');
      for (const { path } of snapshot) {
        assert.deepEqual(readFileSync(join(cwd, path)), readFileSync(join(gate.root, path)));
        index.add(path);
      }
    }
    if (args.includes('checkout')) {
      assert.equal(index.has('deleted.mjs'), false);
      for (const path of index) cpSync(join(gate.root, path), join(cwd, path));
    }
    return '';
  };
  for (const autocrlf of ['false', 'true']) {
    const root = gate.checkout(snapshot, autocrlf);
    assert.equal(root, join(gate.work, `checkout-${autocrlf}`));
    assert.ok(existsSync(join(root, 'node_modules')));
    assert.ok(existsSync(join(root, 'ui/node_modules')));
    assert.equal(existsSync(join(root, 'deleted.mjs')), false);
  }
  assert.deepEqual(readdirSync(gate.output), []);
  assert.ok(calls.findIndex(args => args[0] === 'read-tree') < calls.findIndex(args => args.includes('add')));
  assert.ok(calls.some(args => args.includes('checkout') &&
    args.includes('core.autocrlf=true')));
  assert.deepEqual(readFileSync(join(gate.root, 'kept.mjs')), Buffer.from('candidate bytes\r\n'));
});

test('native verifier receives raw binary Git blobs through the actual adapter', async t => {
  const gate = fixture(t);
  const build = 'tools/windows-security-helper/build.ps1';
  const paths = ['bin/windows/PoolingSecurityHelper.exe', 'bin/windows/PoolingSecurityHelper.build.json',
    'bin/windows/src/AssemblyInfo.cs', 'bin/windows/src/PoolingNativeFiles.cs',
    'bin/windows/src/PoolingSecurityHelper.cs', 'bin/windows/src/PoolingSecurityReader.cs', build];
  const blobs = paths.map(path => path === build ? Buffer.from('Write-Output fixture\n') : Buffer.from([0, 255, 128, 13, 10]));
  const commit = 'c'.repeat(40);
  paths.forEach((path, index) => write(gate.root, path,
    path === build ? Buffer.from(blobs[index].toString().replaceAll('\n', '\r\n')) : blobs[index]));
  const object = index => String(index + 1).padStart(40, '0');
  gate.command = (label, executable, args, cwd, binary) => {
    assert.equal(executable, 'git');
    assert.equal(cwd, gate.root);
    let output;
    if (args.includes('rev-parse')) {
      output = args.includes('--git-path') ? join(gate.root, '.git/info/attributes') : commit;
    } else if (args.includes('ls-tree')) {
      output = paths.map((path, index) => `100644 blob ${object(index)}\t${path}\0`).join('');
    } else if (args.includes('check-attr')) {
      output = Object.entries({ text: 'set', eol: 'crlf', filter: 'unspecified',
        'working-tree-encoding': 'unspecified', ident: 'unspecified' })
        .flatMap(([key, value]) => [build, key, value]).join('\0') + '\0';
    } else if (args.includes('cat-file')) {
      if (args.includes('-e')) {
        assert.equal(args.at(-1), `${CURRENT_REF}^{commit}`);
        output = '';
      } else {
        assert.equal(binary, true, 'Native blobs must not pass through UTF-8 decoding');
        output = blobs[args.at(-1).includes(':') ? paths.length - 1 : Number(args.at(-1)) - 1];
      }
    } else assert.fail(`Unexpected local native operation: ${args}`);
    return binary ? Buffer.from(output) : output;
  };
  const result = await gate.native(gate.root, '2.0.1');
  assert.equal(result.files.find(item => item.path.endsWith('.exe')).sha256, digest(blobs[0]).sha256);
  assert.equal(result.buildScript.comparison, 'exact-declared-crlf-checkout');
  write(gate.root, paths[0], Buffer.from([0, 254, 128, 13, 10]));
  await assert.rejects(gate.native(gate.root, '2.0.1'));
});

test('retained graph uses physical packages and exact installed/root lock metadata, with no npm execution', t => {
  const gate = fixture(t);
  const expected = dependency(gate.root);
  assert.deepEqual(retainedDependencies(gate.root), [expected]);
  write(gate.root, `${expected.path}/package.json`, '{"name":"fixture-public","version":"9.0.0"}');
  assert.throws(() => retainedDependencies(gate.root), /Retained version mismatch/);
  dependency(gate.root);
  write(gate.root, 'node_modules/unrecorded/package.json', '{"name":"unrecorded","version":"1.0.0"}');
  assert.throws(() => retainedDependencies(gate.root), /Unrecorded retained dependency/);
});

test('actual capture and runtime finalizer accept retained fixture bytes without claiming fresh consumers', async t => {
  const gate = fixture(t, true);
  const source = join(gate.root, '.hidden-parent/source');
  mkdirSync(source, { recursive: true });
  dependency(source);
  // Read-only real notice artifacts; no UI build, package load, npm, Git or source suite.
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const result = await gate.retainedLicenses(source, ROOT, pkg);
  assert.equal(result.freshRegistryEvidence, false);
  assert.equal(result.installedInThisRun, false);
  assert.equal(result.releaseReady, false);
  const bytes = readFileSync(join(gate.output, result.file));
  assert.equal(digest(bytes).sha256, result.sha256);
  const record = JSON.parse(bytes);
  assert.equal(record.kind, 'retained-graph-finalizer-contract-fixture');
  assert.equal(record.packages.length, 2);
  assert.equal(record.packages.find(item => item.name === 'fixture-public').source, 'retained-license-fixture');
  assert.equal(record.licenseEvidence.packages.length, 1);
  const project = join(gate.work, 'retained-license-fixture');
  assert.ok(existsSync(join(project, 'node_modules/fixture-public/package.json')));
  assert.equal(existsSync(join(project, 'package-lock.json')), false);
  assert.equal(existsSync(join(project, 'node_modules/.package-lock.json')), false);
  assert.deepEqual(readdirSync(gate.output), [result.file]);
});

test('SDK contract controls use actual owner/provenance shapes without importing retained npm', () => {
  const registry = Object.assign(() => {}, { json: Object.assign(() => {}, { stream: () => {} }) });
  const libraries = { registry, publish: () => {}, profile: { get() {}, loginWeb() {}, webAuthOpener() {} },
    pacote: { manifest() {} } };
  const provenance = { verifyBundle() {}, generate() {},
    subject: (name, version, sha512) => ({ name: `pkg:npm/${name}@${version}`, digest: { sha512 } }) };
  validateSdkContract(libraries, provenance);
  assert.throws(() => validateSdkContract({ ...libraries, publish: { publish() {} } }, provenance));
  assert.throws(() => validateSdkContract({ ...libraries, profile: {} }, provenance));
  assert.throws(() => validateSdkContract(libraries, { ...provenance, subject: () => ({}) }));
  assert.equal(typeof net.connect, 'function');
});

test('SDK imports are inert and disposable-child controls block network and process APIs before transport', t => {
  const gate = fixture(t);
  const source = `
    import assert from 'node:assert/strict';
    import net from 'node:net';
    import dns from 'node:dns';
    import http from 'node:http';
    import https from 'node:https';
    import tls from 'node:tls';
    import http2 from 'node:http2';
    import dgram from 'node:dgram';
    import { spawn } from 'node:child_process';
    const connect = net.connect;
    const { blockSdkTransports } = await import(${JSON.stringify(SDK)});
    assert.equal(net.connect, connect);
    const counts = blockSdkTransports();
    for (const action of [
      () => net.connect(1), () => new net.Socket().connect(1),
      () => tls.connect(1), () => http.get('http://invalid.invalid'),
      () => https.get('https://invalid.invalid'), () => http2.connect('https://invalid.invalid'),
      () => dns.lookup('invalid.invalid'), () => dns.promises.resolve('invalid.invalid'),
      () => new dns.Resolver().resolve('invalid.invalid'),
      () => dgram.createSocket('udp4'), () => fetch('https://invalid.invalid'),
      () => spawn(process.execPath, ['-e', 'process.exit(0)']),
    ]) assert.throws(action, /forbidden/);
    assert.deepEqual(counts, { network: 11, subprocess: 1 });
    console.log(JSON.stringify(counts));
  `;
  const env = localEnvironment(process.env, join(gate.work, 'sdk-control-home'));
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    env, shell: false, windowsHide: true, encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { network: 11, subprocess: 1 });
});
