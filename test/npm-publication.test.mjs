import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  POLICY, REQUIRED_GATES, digest, channelFor, publicationTagName, validateApproval, validateContext, validateSource,
  validatePackage, npm12Contents, validateRegistry, validateGates, validateCi,
  validateEnvironment, validateTransfer, validateGateStatus, stageArguments, submitOnce,
} from '../tools/npm-publication/policy.mjs';
import { cleanNpmEnvironment } from '../tools/npm-publication/run.mjs';

const bytes = Buffer.from('controlled local guard fixture; not an npm artifact');
const stageId = ['11111111', '2222', '4333', '8444', '555555555555'].join('-');
const humanGates = [
  'source-private-identifiers', 'payload-private-identifiers', 'author-identity', 'historical-risk-disposition',
];
function approval(version = '1.3.1') {
  return {
    schemaVersion: 1, name: POLICY.name, version, ref: `refs/tags/v${version}`,
    tagObject: 'a'.repeat(40), commit: 'b'.repeat(40), tree: 'c'.repeat(40), ciRunId: '42', ciAttempt: 1,
    approver: POLICY.owner, approvedAt: new Date().toISOString(), scope: 'stage',
    publicPackages: [POLICY.name, 'smol-toml', '@modelcontextprotocol/sdk'],
    artifact: { ...digest(bytes), manifestSha256: 'd'.repeat(64),
      artifactDigest: `sha256:${'e'.repeat(64)}`, artifactId: '43', runId: '44', runAttempt: 1 },
    ownerPreflight: {
      owner: POLICY.owner, checkedAt: new Date().toISOString(), packageName: POLICY.name,
      privateContentReview: {
        reviewer: POLICY.owner, scope: 'source-and-tarball', disposition: 'approved',
        historyAndAuthorsReviewed: true, historicalEvidenceAccepted: true,
        commit: 'b'.repeat(40), artifact: digest(bytes), reviewedAt: new Date().toISOString(),
      },
      unresolvedSubmission: false, expectedDistTags: { latest: '2.0.1' }, pending: { status: 'none' },
      trust: { repository: POLICY.repository, workflow: 'npm-publish.yml', environment: POLICY.environment,
        allowPublish: false, allowStagePublish: true },
    },
  };
}

function context(a) {
  return {
    env: {
      RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64',
      GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
      GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: POLICY.repository,
      GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_ACTOR: POLICY.owner,
      GITHUB_TRIGGERING_ACTOR: POLICY.owner, GITHUB_RUN_ATTEMPT: '1', GITHUB_REF: a.ref,
      GITHUB_SHA: a.commit, GITHUB_WORKFLOW_SHA: a.commit,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${a.ref}`,
    },
    event: { repository: { full_name: POLICY.repository, private: false, fork: false },
      sender: { login: POLICY.owner } },
  };
}

function pkg(a) {
  return { name: POLICY.name, version: a.version, repository: {
    type: 'git', url: `git+https://github.com/${POLICY.repository}.git`,
  }, dependencies: { 'smol-toml': '^1.8.0' } };
}

function published(a) {
  return { name: POLICY.name, maintainers: [{ name: POLICY.owner }], versions: {},
    'dist-tags': structuredClone(a.ownerPreflight.expectedDistTags) };
}

function output(a) {
  return JSON.stringify({ [POLICY.name]: {
    id: `${POLICY.name}@${a.version}`, name: POLICY.name, version: a.version,
    filename: `${POLICY.name}-${a.version}.tgz`, size: bytes.length, integrity: digest(bytes).integrity,
    shasum: createHash('sha1').update(bytes).digest('hex'),
    files: [{ path: 'package.json', size: 1, mode: 0o644 }], entryCount: 1, bundled: [], stageId,
  } });
}

function submission(a = approval()) {
  const calls = [];
  const records = [];
  return { calls, records, args: {
    approval: a, bytes, tarball: '/owned/candidate.tgz', config: { user: '/owned/u', global: '/owned/g' },
    readRegistry: async () => published(a),
    execute: async args => { calls.push(args); return output(a); },
    record: async value => { records.push(value); },
  } };
}

test('Synthetic stage IDs remain runtime-only fixtures', () => {
  const source = readFileSync(new URL(import.meta.url), 'utf8');
  assert.ok(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(stageId));
  assert.equal(source.includes(stageId), false, 'Keep the synthetic stage ID out of source bytes');
});

test('T01/T20: only approved stable candidate versions map to fixed channels', () => {
  assert.equal(channelFor('1.3.1'), 'legacy');
  assert.equal(channelFor('2.0.1'), 'latest');
  for (const version of ['1.3.0', '2.0.0', '3.0.1', '2.0.1-beta.1', 'v2.0.1', '1', '1.3.1+build']) {
    assert.throws(() => channelFor(version));
  }
});

for (const version of ['1.3.1', '2.0.1']) {
  for (const namespace of ['', 'npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/']) {
    test(`publication tag ${namespace}v${version} preserves approval, workflow and environment binding`, () => {
      const a = approval(version);
      a.ref = `refs/tags/${namespace}v${version}`;
      assert.equal(publicationTagName(a.ref, version), `${namespace}v${version}`);
      assert.equal(validateApproval(a, 'stage'), channelFor(version));
      assert.equal(validateApproval({ ...a, scope: 'prepare' }, 'prepare'), channelFor(version));
      const { env, event } = context(a);
      validateContext(env, event, a);
      const otherRefs = ['', 'npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/'].filter(value => value !== namespace)
        .map(value => `refs/tags/${value}v${version}`);
      for (const other of otherRefs) {
        assert.throws(() => validateContext({ ...env, GITHUB_REF: other }, event, a));
        assert.throws(() => validateContext({
          ...env, GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${other}`,
        }, event, a));
      }
      const environment = { id: 12, name: POLICY.environment, protection_rules: [{
        type: 'required_reviewers', prevent_self_review: false,
        reviewers: [{ reviewer: { login: POLICY.owner } }],
      }], deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } };
      const policies = [{ type: 'tag', name: `${namespace}v${version}` }];
      const reviews = [{ state: 'approved', user: { login: POLICY.owner },
        environments: [{ id: 12, name: POLICY.environment }] }];
      validateEnvironment(environment, policies, reviews, a);
      for (const other of otherRefs) {
        assert.throws(() => validateEnvironment(environment,
          [{ type: 'tag', name: other.slice('refs/tags/'.length) }], reviews, a));
      }
    });
  }
}

test('publication tag approval rejects alternate refs and mismatched versions', () => {
  const a = approval('2.0.1');
  for (const ref of ['refs/heads/main', 'refs/tags/npm/v1.3.1', 'refs/tags/npm/v2.0.1-extra',
    'refs/tags/npm/v2.0.1/other', 'refs/tags/npm//v2.0.1', 'refs/tags/npm/../v2.0.1',
    'refs/tags/NPM/v2.0.1', 'refs/tags/other/v2.0.1', 'npm/v2.0.1',
    'refs/tags/npm-r2/v1.3.1', 'refs/tags/npm-r2/v2.0.1-extra', 'refs/tags/npm-r2/v2.0.1/other',
    'refs/tags/npm-r2//v2.0.1', 'refs/tags/npm-r2/../v2.0.1',
    'refs/tags/npm-r3/v1.3.1', 'refs/tags/npm-r3/v2.0.1-extra', 'refs/tags/npm-r3/v2.0.1/other',
    'refs/tags/npm-r3//v2.0.1', 'refs/tags/npm-r3/../v2.0.1',
    'refs/tags/npm-r4/v1.3.1', 'refs/tags/npm-r4/v2.0.1-extra', 'refs/tags/npm-r4/v2.0.1/other',
    'refs/tags/npm-r4//v2.0.1', 'refs/tags/npm-r4/../v2.0.1',
    'refs/tags/npm-r5/v1.3.1', 'refs/tags/npm-r5/v2.0.1-extra', 'refs/tags/npm-r5/v2.0.1/other',
    'refs/tags/npm-r5//v2.0.1', 'refs/tags/npm-r5/../v2.0.1', 'refs/tags/npm-r6/v2.0.1', null]) {
    assert.throws(() => validateApproval({ ...a, ref }, 'stage'), /exact approved/);
  }
  assert.throws(() => publicationTagName('refs/tags/npm/v3.0.1', '3.0.1'));
});

test('T02/T03: each source identity independently fails closed', () => {
  const a = approval();
  const source = { tagType: 'tag', tagObject: a.tagObject, tagCommit: a.commit,
    tagTree: a.tree, head: a.commit, tree: a.tree, status: '', workflowMatches: true };
  validateSource(source, a);
  for (const key of Object.keys(source)) {
    assert.throws(() => validateSource({ ...source, [key]: 'different' }, a), key);
  }
});

test('T03/T05/T45: hosted identity is not inferred from runner labels or checkout HEAD', () => {
  const a = approval();
  const { env, event } = context(a);
  validateContext(env, event, a);
  for (const key of Object.keys(env)) {
    assert.throws(() => validateContext({ ...env, [key]: 'untrusted' }, event, a), key);
  }
  assert.throws(() => validateContext(env, { ...event,
    repository: { ...event.repository, fork: true } }, a));
  assert.throws(() => validateContext({ ...env, GITHUB_REF: 'refs/heads/main' }, event, a));
});

test('T05/T45: self-hosted refusal happens before the injected mutation boundary', async () => {
  const a = approval();
  const { env, event } = context(a);
  const s = submission(a);
  await assert.rejects(async () => {
    validateContext({ ...env, RUNNER_ENVIRONMENT: 'self-hosted' }, event, a);
    await submitOnce(s.args);
  });
  assert.equal(s.calls.length, 0);
});

test('T06: exact scope, owner and freshness are mandatory; preparation cannot stage', () => {
  const a = approval();
  validateApproval(a, 'stage');
  for (const delta of [{ scope: 'prepare' }, { approver: 'other' }, { name: '@other/pkg' },
    { approvedAt: '2000-01-01T00:00:00Z' }, { approvedAt: '2999-01-01T00:00:00Z' },
    { artifact: { ...a.artifact, sha512: 'f'.repeat(128) } }]) {
    assert.throws(() => validateApproval({ ...a, ...delta }, 'stage'));
  }
});

test('Prepare approval requires a nonempty, unique, valid public-package disclosure list', () => {
  const a = { ...approval(), scope: 'prepare' };
  validateApproval(a, 'prepare');
  for (const publicPackages of [undefined, null, [], 'smol-toml', ['smol-toml', 'smol-toml'],
    ['PrivateName'], ['@scope'], ['@scope/'], ['https://example.invalid/pkg'], ['pkg name'], [null], [7]]) {
    assert.throws(() => validateApproval({ ...a, publicPackages }, 'prepare'));
  }
  assert.throws(() => validateApproval(a, 'stage'), /does not authorize/);
});

test('T07/T09: bootstrap is not an automated action or a fabricated stage', () => {
  assert.throws(() => validateApproval(approval(), 'bootstrap'));
  const a = approval();
  delete a.ownerPreflight.expectedDistTags.latest;
  assert.throws(() => validateApproval(a, 'stage'), /Bootstrap/);
});

test('T08/T09: unknown ownership, absent package and missing trust block before a write', async () => {
  for (const readback of [null, {}, { name: POLICY.name, maintainers: [{ name: 'someone-else' }] }]) {
    const s = submission();
    s.args.readRegistry = async () => readback;
    await assert.rejects(() => submitOnce(s.args));
    assert.equal(s.calls.length, 0);
  }
  const a = approval();
  a.ownerPreflight.trust.allowPublish = true;
  const s = submission(a);
  await assert.rejects(() => submitOnce(s.args), /trust/);
  assert.equal(s.calls.length, 0);
});

test('T10/T11/T20: exact tarball submitted once with explicit final tag and no approval commands', async () => {
  for (const version of ['1.3.1', '2.0.1']) {
    const s = submission(approval(version));
    await submitOnce(s.args);
    assert.equal(s.calls.length, 1);
    assert.deepEqual(s.calls[0].slice(0, 3), ['stage', 'publish', '/owned/candidate.tgz']);
    assert.ok(s.calls[0].includes(`--tag=${channelFor(version)}`));
    assert.ok(s.calls[0].includes('--fetch-retries=0'));
    assert.ok(s.calls[0].includes('--provenance'));
    assert.equal(s.records[0].status, 'submission-outcome-unknown');
    assert.equal(s.records[1].stageId, stageId);
    assert.equal(s.records[1].registrySignatures, 'pending-publication');
    assert.equal(s.records[1].ownerPublicationApproval, 'pending');
  }
});

test('npm publication refs preserve fixed npm channels during stage submission', async () => {
  for (const version of ['1.3.1', '2.0.1']) {
    for (const namespace of ['npm/', 'npm-r2/', 'npm-r3/', 'npm-r4/', 'npm-r5/']) {
      const a = approval(version);
      a.ref = `refs/tags/${namespace}v${version}`;
      const s = submission(a);
      await submitOnce(s.args);
      assert.equal(s.calls.length, 1);
      assert.ok(s.calls[0].includes(`--tag=${channelFor(version)}`));
      assert.ok(!s.calls[0].some(value => value.startsWith('--tag=npm')));
      assert.equal(s.records.at(-1).status, 'submitted-awaiting-owner-verification');
    }
  }
});

test('T04: tampered bytes cannot cross the injected mutation boundary', async () => {
  const s = submission();
  s.args.bytes = Buffer.from('changed');
  await assert.rejects(() => submitOnce(s.args), /mismatch/);
  assert.equal(s.calls.length, 0);
});

test('T13: owner-reconciled matching pending stage returns its ID without another write', async () => {
  const a = approval();
  a.ownerPreflight.pending = { status: 'matching', stageId, version: a.version,
    tag: 'legacy', ...digest(bytes), workflow: {
      ref: `${POLICY.repository}/${POLICY.workflow}@${a.ref}`, commit: a.commit, runId: '40', attempt: 1,
    } };
  const s = submission(a);
  await submitOnce(s.args);
  assert.equal(s.calls.length, 0);
  assert.equal(s.records[0].stageId, stageId);
  assert.equal(s.records[0].workflow.runId, '40');
  assert.equal(s.records[0].provenance, 'pending-owner-cryptographic-verification');
});

test('T14/T17: ambiguous/conflicting pending stages and unresolved outcomes never retry', async () => {
  for (const status of ['unknown', 'conflict']) {
    const a = approval();
    a.ownerPreflight.pending.status = status;
    const s = submission(a);
    await assert.rejects(() => submitOnce(s.args));
    assert.equal(s.calls.length, 0);
  }
  const a = approval();
  a.ownerPreflight.unresolvedSubmission = true;
  await assert.rejects(() => submitOnce(submission(a).args));
});

test('T15/T16: matching published payload is readback-only; conflicting payload is immutable', async () => {
  for (const integrity of [digest(bytes).integrity, 'sha512-conflict']) {
    const s = submission();
    const packument = published(s.args.approval);
    packument.versions['1.3.1'] = { dist: { integrity } };
    s.args.readRegistry = async () => packument;
    if (integrity === digest(bytes).integrity) {
      await submitOnce(s.args);
      assert.equal(s.records[0].status, 'published-matching');
      assert.equal(s.records[0].publicationAcceptance, 'pending-registry-verification');
    } else {
      await assert.rejects(() => submitOnce(s.args), /Immutable/);
    }
    assert.equal(s.calls.length, 0);
  }
});

test('T17: lost response, malformed JSON and missing stage ID preserve unknown outcome', async () => {
  for (const response of ['lost', '{}', '[]', '{"mcp-pacemaker":{}}']) {
    const s = submission();
    s.args.execute = async args => {
      s.calls.push(args);
      if (response === 'lost') throw new Error('lost response');
      return response;
    };
    await assert.rejects(() => submitOnce(s.args));
    assert.equal(s.calls.length, 1);
    assert.equal(s.records.length, 1);
    assert.equal(s.records[0].status, 'submission-outcome-unknown');
  }
});

test('T17: failed durable intent record prevents submission', async () => {
  const s = submission();
  s.args.record = async () => { throw new Error('disk failure'); };
  await assert.rejects(() => submitOnce(s.args), /disk failure/);
  assert.equal(s.calls.length, 0);
});

test('T19/T41/T43: changed/missing/wrong-major channel state fails rather than selecting a maximum', () => {
  const a = approval();
  for (const tags of [{}, { latest: '1.3.1' }, { latest: '2.0.2' }]) {
    assert.throws(() => validateRegistry({ ...published(a), 'dist-tags': tags }, a), /Channel/);
  }
});

test('T21/T25: package metadata cannot override publication flags or reintroduce unsafe dependency floor', () => {
  const a = approval();
  validatePackage(pkg(a), a);
  validatePackage({ ...pkg(a), publishConfig: { registry: POLICY.registry, access: 'public', tag: 'legacy' } }, a);
  for (const delta of [{ private: true }, { tag: 'latest' }, { packageExtensions: {} },
    { publishConfig: { tag: 'latest' } }, { publishConfig: { access: 'restricted' } },
    { publishConfig: { registry: 'https://example.invalid/' } },
    { publishConfig: { provenance: false } }, { publishConfig: { '//registry.npmjs.org/:_authToken': 'synthetic' } },
    { scripts: { prepare: 'something' } }, { dependencies: { 'smol-toml': '^1.7.0' } }]) {
    assert.throws(() => validatePackage({ ...pkg(a), ...delta }, a));
  }
  assert.throws(() => stageArguments('/repo', 'legacy', {}));
  assert.throws(() => stageArguments('/candidate.tgz', '1', {}));
});

test('npm12 official name-keyed pack/stage schema is distinct from npm11 array output', () => {
  const a = approval();
  assert.equal(npm12Contents(output(a), a, bytes, true).stageId, stageId);
  assert.throws(() => npm12Contents(`[${output(a)}]`, a, bytes));
  const noId = JSON.parse(output(a));
  delete noId[POLICY.name].stageId;
  assert.throws(() => npm12Contents(JSON.stringify(noId), a, bytes, true));
});

test('T22-T28/T42: missing, generic-pending or unbound gates fail without changing designated owner-pending states', () => {
  const a = approval();
  const report = { schemaVersion: 1, commit: a.commit, artifact: digest(bytes),
    gates: Object.fromEntries(REQUIRED_GATES.map(name => [name, {
      ...(humanGates.includes(name) ? { status: 'pending-owner-review', ownerReview: 'pending' } : { status: 'passed' }),
      evidence: [{ description: 'controlled unit-test evidence', sha256: '1'.repeat(64) }],
    }])) };
  validateGates(report, a, digest(bytes));
  for (const name of REQUIRED_GATES) {
    const missing = structuredClone(report);
    missing.gates[name].status = 'pending';
    assert.throws(() => validateGates(missing, a, digest(bytes)), new RegExp(name));
    delete missing.gates[name];
    assert.throws(() => validateGates(missing, a, digest(bytes)), new RegExp(name));
  }
  assert.throws(() => validateGates({ ...report, commit: 'd'.repeat(40) }, a, digest(bytes)));
  const incomplete = structuredClone(report);
  incomplete.gates['native-release-identity'].evidence = [];
  assert.throws(() => validateGates(incomplete, a, digest(bytes)));
});

test('Only four human gates accept owner-pending; native execution/identity and T32 still require automated passes', () => {
  assert.ok(!REQUIRED_GATES.includes('native-rebuild'));
  for (const name of ['native-release-identity', 'native-windows-execution', 'service-replacement']) {
    assert.ok(REQUIRED_GATES.includes(name));
  }
  for (const name of REQUIRED_GATES) {
    validateGateStatus(name, { status: 'passed' });
    assert.throws(() => validateGateStatus(name, undefined), new RegExp(name));
    for (const status of ['pending-owner-review', 'not-run', 'pending', 'skipped', 'failed']) {
      const gate = { status, ownerReview: 'pending' };
      const allowed = humanGates.includes(name) &&
        (status === 'pending-owner-review' ||
          name.endsWith('-private-identifiers') &&
          status === 'not-run');
      if (allowed) {
        validateGateStatus(name, gate);
        for (const ownerReview of [undefined, 'approved', false]) {
          assert.throws(() => validateGateStatus(name, { ...gate, ownerReview }), new RegExp(name));
        }
      } else {
        assert.throws(() => validateGateStatus(name, gate), new RegExp(name));
      }
    }
  }
});

test('T42: exact CI attempt and complete successful required matrix are mandatory', () => {
  const a = approval();
  const run = { id: 42, run_attempt: 1, head_sha: a.commit, head_repository: { full_name: POLICY.repository },
    repository: { full_name: POLICY.repository }, path: '.github/workflows/ci.yml',
    event: 'push', status: 'completed', conclusion: 'success' };
  const names = ['Lockfiles resolve to the public registry', 'ui'];
  for (const os of ['ubuntu-latest', 'windows-latest', 'macos-latest']) {
    for (const node of [20, 22, 24]) names.push(`test (${os}, ${node})`);
  }
  const jobs = names.map(name => ({ name, head_sha: a.commit, status: 'completed', conclusion: 'success' }));
  validateCi(run, jobs, a);
  assert.throws(() => validateCi({ ...run, head_sha: 'd'.repeat(40) }, jobs, a));
  assert.throws(() => validateCi({ ...run, event: 'pull_request' }, jobs, a));
  assert.throws(() => validateCi(run, jobs.slice(1), a));
  assert.throws(() => validateCi(run, jobs.map(job => ({ ...job, conclusion: 'skipped' })), a));
});

test('T05/T06: a named but unprotected environment or bypass without owner review is insufficient', () => {
  const a = approval();
  const environment = { id: 7, name: POLICY.environment, protection_rules: [
    { type: 'required_reviewers', prevent_self_review: false, reviewers: [{ reviewer: { login: POLICY.owner } }] },
  ], deployment_branch_policy: { custom_branch_policies: true, protected_branches: false } };
  const policies = [{ type: 'tag', name: 'v1.3.1' }];
  const reviews = [{ state: 'approved', user: { login: POLICY.owner },
    environments: [{ name: POLICY.environment, id: 7 }] }];
  validateEnvironment(environment, policies, reviews, a);
  assert.throws(() => validateEnvironment({ ...environment, protection_rules: [] }, policies, reviews, a));
  assert.throws(() => validateEnvironment(environment, [{ type: 'branch', name: 'v1.3.1' }], reviews, a));
  assert.throws(() => validateEnvironment(environment, policies, [], a));
});

test('T05/T11: no inherited npm token/config or Node injection and no GitHub read token in npm child', () => {
  const env = cleanNpmEnvironment({ PATH: '/bin', GITHUB_TOKEN: 'synthetic', OTHER_SECRET: 'synthetic' }, '/owned');
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.OTHER_SECRET, undefined);
  for (const key of ['NODE_AUTH_TOKEN', 'NPM_TOKEN', 'NPM_ID_TOKEN', 'SIGSTORE_ID_TOKEN',
    'NODE_OPTIONS', 'npm_config_registry', 'NPM_CONFIG_USERCONFIG']) {
    assert.throws(() => cleanNpmEnvironment({ PATH: '/bin', [key]: 'synthetic' }, '/owned'));
  }
});

test('T22: private-pattern scanning cannot substitute for fresh owner source-and-tarball review', async () => {
  const variants = [
    review => { delete review.reviewer; },
    review => { review.reviewer = 'another-owner'; },
    review => { review.scope = 'pattern-scan'; },
    review => { review.disposition = 'pending'; },
    review => { review.commit = 'f'.repeat(40); },
    review => { review.artifact.sha256 = 'f'.repeat(64); },
    review => { review.artifact.sha512 = 'f'.repeat(128); },
    review => { review.artifact.integrity = digest(Buffer.from('different')).integrity; },
    review => { review.reviewedAt = '2000-01-01T00:00:00.000Z'; },
  ];
  for (const mutate of variants) {
    const a = approval();
    mutate(a.ownerPreflight.privateContentReview);
    const s = submission(a);
    await assert.rejects(() => submitOnce(s.args));
    assert.equal(s.calls.length, 0);
  }
  const a = approval();
  delete a.ownerPreflight.privateContentReview;
  const s = submission(a);
  await assert.rejects(() => submitOnce(s.args), /Separate owner/);
  assert.equal(s.calls.length, 0);
  assert.equal(validateApproval({ ...a, scope: 'prepare' }, 'prepare'), 'legacy');
});

for (const flag of ['historyAndAuthorsReviewed', 'historicalEvidenceAccepted']) {
  test(`Owner content review requires literal ${flag}=true before the injected submission boundary`, async () => {
    for (const value of [undefined, false, null, 'true']) {
      const a = approval();
      if (value === undefined) delete a.ownerPreflight.privateContentReview[flag];
      else a.ownerPreflight.privateContentReview[flag] = value;
      const s = submission(a);
      await assert.rejects(() => submitOnce(s.args));
      assert.equal(s.calls.length, 0);
      assert.equal(s.records.length, 0);
    }
  });
}

test('Scanner tool pins pass only to preparation; unrelated configuration and stage-child leakage are excluded', () => {
  const tools = {
    MCP_GITLEAKS_BIN: join(tmpdir(), 'gitleaks'), MCP_GITLEAKS_SHA256: 'a'.repeat(64),
    MCP_TRUFFLEHOG_BIN: join(tmpdir(), 'trufflehog'), MCP_TRUFFLEHOG_SHA256: 'b'.repeat(64),
    MCP_GO_BIN: join(tmpdir(), 'go'),
    MCP_GIT_BIN: join(tmpdir(), 'git'),
    MCP_GITLEAKS_CONFIG: join(tmpdir(), 'gitleaks.toml'),
  };
  const source = cleanNpmEnvironment({ PATH: '/bin', ...tools, MCP_UNRELATED: 'not-forwarded' }, '/owned');
  for (const [name, value] of Object.entries(tools)) assert.equal(source[name], value);
  assert.equal(source.MCP_UNRELATED, undefined);
  assert.throws(() => cleanNpmEnvironment({ MCP_GIT_BIN: 'relative' }, '/owned'), /MCP_GIT_BIN.*absolute/);
  assert.throws(() => cleanNpmEnvironment({
    ...tools, MCP_GITLEAKS_CONFIG: undefined,
  }, '/owned'), /MCP_GITLEAKS_CONFIG is required/);
  assert.throws(() => cleanNpmEnvironment({ MCP_GITLEAKS_CONFIG: 'relative' }, '/owned'), /absolute/);
  assert.throws(() => cleanNpmEnvironment({ MCP_GITLEAKS_BIN: tools.MCP_GITLEAKS_BIN }, '/owned'), /must pin/);
  assert.throws(() => cleanNpmEnvironment({
    MCP_GITLEAKS_BIN: 'relative', MCP_GITLEAKS_SHA256: 'a'.repeat(64),
  }, '/owned'), /absolute/);
  const a = approval();
  const env = { ...context(a).env, ...tools,
    GITHUB_REPOSITORY_ID: '1', GITHUB_REPOSITORY_OWNER_ID: '2', GITHUB_RUN_ID: '3',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'synthetic-request-url',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-controlled-fixture-not-a-token',
  };
  const stage = cleanNpmEnvironment(env, '/owned', true);
  for (const name of Object.keys(tools)) assert.equal(stage[name], undefined);
});

test('T04/T06: transfer is bound to approved artifact ID/archive digest/source/prepare run', () => {
  const a = approval();
  const run = { id: 44, head_sha: a.commit, repository: { full_name: POLICY.repository },
    head_repository: { full_name: POLICY.repository }, path: POLICY.workflow,
    event: 'workflow_dispatch', run_attempt: 1, status: 'completed', conclusion: 'success' };
  const names = ['source', 'prepare', ...['linux', 'win32', 'darwin'].flatMap(platform =>
    ['11.6.1', POLICY.npm].map(npm => `consumer (${platform}, ${npm})`))];
  const jobs = [...names.map(name => ({ name, conclusion: 'success', status: 'completed', head_sha: a.commit })),
    { name: 'stage', conclusion: 'skipped' }];
  const artifact = { id: 43, expired: false, name: 'npm-candidate-44-1',
    digest: a.artifact.artifactDigest, workflow_run: { id: 44, head_sha: a.commit } };
  validateTransfer(run, jobs, artifact, a);
  for (const name of names) {
    assert.throws(() => validateTransfer(run, jobs.filter(job => job.name !== name), artifact, a),
      /Missing or ambiguous/, `${name}: missing`);
    const job = jobs.find(item => item.name === name);
    assert.throws(() => validateTransfer(run, [...jobs, job], artifact, a),
      /Missing or ambiguous/, `${name}: duplicate`);
    for (const delta of [{ status: 'in_progress' }, { status: 'skipped' },
      { conclusion: 'skipped' }, { conclusion: 'failure' }, { head_sha: 'f'.repeat(40) }]) {
      assert.throws(() => validateTransfer(run, jobs.map(item => item.name === name ? { ...item, ...delta } : item),
        artifact, a), `${name}: ${JSON.stringify(delta)}`);
    }
  }
  for (const delta of [{ id: 99 }, { expired: true }, { digest: `sha256:${'f'.repeat(64)}` },
    { workflow_run: { id: 99, head_sha: a.commit } }]) {
    assert.throws(() => validateTransfer(run, jobs, { ...artifact, ...delta }, a));
  }
  assert.throws(() => validateTransfer({ ...run, head_sha: 'f'.repeat(40) }, jobs, artifact, a));
  for (const conclusion of ['success', 'failure', null]) {
    assert.throws(() => validateTransfer(run, jobs.map(job => job.name === 'stage' ? { ...job, conclusion } : job),
      artifact, a), /prepare-only/);
  }
});

test('T18: workflow is manual-only, package-wide serialized, stage-only OIDC and pinned actions', () => {
  const workflow = readFileSync(new URL('../.github/workflows/npm-publish.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  assert.match(workflow, /workflow_dispatch:/);
  assert.doesNotMatch(workflow, /^\s+(?:push|release|pull_request|schedule|workflow_run):/m);
  assert.match(workflow, /default: prepare/);
  assert.match(workflow, /group: npm-publication-mcp-pacemaker\n\s+cancel-in-progress: false/);
  assert.equal((workflow.match(/id-token: write/g) ?? []).length, 1);
  assert.doesNotMatch(workflow.split('\n  stage:')[0], /id-token/);
  assert.match(workflow, /environment: npm-publish/);
  assert.match(workflow, /ACTUAL_RUNNER_ENVIRONMENT: \$\{\{ runner.environment }}/);
  assert.doesNotMatch(workflow, /^ {6}\S[^\n]*\$\{\{\s*runner\./m,
    'GitHub job-env context excludes runner; runner-derived env belongs on steps');
  for (const match of workflow.matchAll(/uses: (.+)/g)) {
    assert.match(match[1], /^actions\/[\w-]+@[a-f0-9]{40}(?: # .+)?$/);
  }
  assert.doesNotMatch(workflow, /(?:npm@latest|npm login|npm publish|npm stage approve|NODE_AUTH_TOKEN|secrets\.)/);
  assert.doesNotMatch(workflow, /^\s+GITHUB_(?:SHA|REF|WORKFLOW_REF|WORKFLOW_SHA):/m);
});
