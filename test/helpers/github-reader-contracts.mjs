import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { compileFunction } from 'node:vm';
import { createRequire } from 'node:module';
import * as matrix from '../../tools/npm-publication/matrix.mjs';
import { POLICY } from '../../tools/npm-publication/policy.mjs';
import { readAuthenticatedStageCapture } from '../../tools/npm-publication/stage-capture-hosted.mjs';
import { validateCollectionJobs } from '../../tools/npm-publication/secret-admission.mjs';
import { syntheticLocalApproval } from './local-regression-fixture.mjs';
import { stageCaptureFixture } from './stage-capture-fixture.mjs';

const { fixture } = createRequire(import.meta.url)('../../tools/npm-publication/offline-stage/fixture.cjs');
const captured = JSON.parse(readFileSync(new URL('../fixtures/github-collection-jobs.json', import.meta.url)));
const runSource = readFileSync(new URL('../../tools/npm-publication/run.mjs', import.meta.url), 'utf8');
const version = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url))).version;
const api = `https://api.github.com/repos/${POLICY.repository}/`;
const token = 'synthetic-reader-contract-fixture';
const missing = Symbol('missing-total');

// Only HTTP envelopes are modeled. Readers and downstream validators execute unchanged.
class Service {
  constructor() {
    this.routes = new Map();
    this.calls = [];
  }

  json(path, body, status = 200) {
    this.routes.set(api + path, { body, status });
    return this;
  }

  pages(path, key, batches, totals) {
    batches.forEach((items, index) => this.json(`${path}?per_page=100&page=${index + 1}`, {
      [key]: items, ...(totals[index] === missing ? {} : { total_count: totals[index] }),
    }));
    return this;
  }

  async fetch(url, options) {
    const route = this.routes.get(String(url));
    assert.ok(route, `Unexpected modeled HTTP request: ${url}`);
    assert.equal(options.method, undefined);
    assert.equal(options.body, undefined);
    assert.ok(options.signal instanceof AbortSignal);
    assert.ok(['manual', 'error'].includes(options.redirect));
    if (String(url).startsWith(api)) {
      assert.equal(options.headers.authorization, `Bearer ${token}`);
    } else {
      assert.equal(options.headers, undefined);
    }
    this.calls.push(String(url));
    if (route.location) return new Response(null, { status: 302, headers: { location: route.location } });
    return new Response(route.bytes ?? JSON.stringify(route.body), { status: route.status ?? 200 });
  }

  readers() {
    return matrix.githubReaders({ GITHUB_TOKEN: token }, { fetcher: this.fetch.bind(this) });
  }

  privateJobs() {
    const start = runSource.indexOf('async function github(');
    const tail = runSource.slice(start).search(/\n(?:export )?async function sourceAndCi/);
    assert.ok(start >= 0 && tail > 0);
    // Source-function seam only: this does not execute main/sourceAndCi or its Git preflight.
    const load = compileFunction(`${runSource.slice(start, start + tail)}\nreturn jobs;`,
      ['assert', 'fetch', 'process', 'POLICY', 'AbortSignal', 'readGithubPages']);
    return load(assert, this.fetch.bind(this), { env: { GITHUB_TOKEN: token } },
      POLICY, AbortSignal, matrix.readGithubPages);
  }
}

const invalidTotals = [
  ['missing', missing], ['null', null], ['string', '2'], ['negative', -1],
  ['fractional', 0.5], ['unsafe', Number.MAX_SAFE_INTEGER + 1], ['true', true], ['false', false],
];
for (const kind of ['jobs', 'artifacts', 'private-jobs']) {
  const key = kind === 'artifacts' ? 'artifacts' : 'jobs';
  const path = key === 'jobs' ? 'actions/runs/12/attempts/1/jobs' : 'actions/runs/12/artifacts';
  const one = [{ id: 1 }];
  const two = [{ id: 1 }, { id: 2 }];
  const invoke = service => kind === 'private-jobs'
    ? service.privateJobs()('12', 1)
    : key === 'jobs' ? service.readers().readJobs('12', 1) : service.readers().readArtifacts('12');
  const cases = [
    { name: 'empty zero', batches: [[]], totals: [0], calls: 1, expected: [] },
    { name: 'complete two pages', batches: [one, [{ id: 2 }]], totals: [2, 2], calls: 2, expected: two },
    { name: 'exact twentieth page', batches: Array.from({ length: 20 }, (_, index) => [{ id: index }]),
      totals: Array(20).fill(20), calls: 20, expected: Array.from({ length: 20 }, (_, id) => ({ id })) },
    { name: 'hard twenty-page bound', batches: Array(20).fill(one), totals: Array(20).fill(21),
      calls: 20, error: /Unexpected.*count/ },
    { name: 'empty first page', batches: [[]], totals: [1], calls: 1, error: /Incomplete/ },
    { name: 'empty continuation', batches: [one, []], totals: [2, 2], calls: 2, error: /Incomplete/ },
    { name: 'invalid first items', batches: [{}], totals: [1], calls: 1, error: /assert|Array|iterable/i },
    { name: 'invalid later items', batches: [one, {}], totals: [2, 2], calls: 2, error: /assert|Array|iterable/i },
    { name: 'first HTTP failure', batches: [one], totals: [1], statusPage: 1, calls: 1, error: /GitHub read failed/ },
    { name: 'later HTTP failure', batches: [one, one], totals: [2, 2], statusPage: 2, calls: 2, error: /GitHub read failed/ },
    { name: 'upward drift', batches: [one, two], totals: [2, 3], calls: 2, error: /total_count changed/ },
    { name: 'downward drift', batches: [one, one], totals: [3, 2], calls: 2, error: /total_count changed/ },
    { name: 'first overshoot', batches: [two, []], totals: [1, 2], calls: 1, error: /exceeds.*total_count/ },
    { name: 'later overshoot', batches: [one, two, []], totals: [2, 2, 3], calls: 2, error: /exceeds.*total_count/ },
    ...invalidTotals.flatMap(([label, total]) => [
      { name: `invalid first total ${label}`, batches: [one, one], totals: [total, 2],
        calls: 1, error: /Invalid GitHub total_count/ },
      { name: `invalid later total ${label}`, batches: [one, one, []], totals: [2, total, 2],
        calls: 2, error: /Invalid GitHub total_count/ },
    ]),
  ];
  for (const scenario of cases) {
    test(`L3 ${kind}: ${scenario.name}`, async () => {
      const service = new Service().pages(path, key, scenario.batches, scenario.totals);
      if (scenario.statusPage) service.routes.get(`${api}${path}?per_page=100&page=${scenario.statusPage}`).status = 503;
      if (scenario.error) await assert.rejects(invoke(service), scenario.error);
      else assert.deepEqual([...await invoke(service)], scenario.expected);
      assert.equal(service.calls.length, scenario.calls);
    });
  }
}

test('L3 private jobs source wiring shares the pagination invariant without claiming main execution', () => {
  assert.equal(typeof matrix.readGithubPages, 'function');
  assert.match(runSource, /import\s*\{[^}]*\breadGithubPages\b[^}]*\}\s*from '\.\/matrix\.mjs'/);
  const body = runSource.slice(runSource.indexOf('async function jobs('));
  assert.match(body, /return readGithubPages\(/);
  assert.match(body, /attempts\/\$\{attempt\}\/jobs\?per_page=100&page=\$\{page\}/);
});

class SelectorService extends Service {
  constructor() {
    super();
    this.approval = syntheticLocalApproval({
      schemaVersion: 1, scope: 'prepare', approver: POLICY.owner, name: POLICY.name, version,
      ref: `refs/tags/v${version}`, tagObject: 'a'.repeat(40), commit: 'b'.repeat(40), tree: 'c'.repeat(40),
    });
    this.env = {
      ACTUAL_RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_ENVIRONMENT: 'github-hosted',
      RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64', RUNNER_NAME: 'synthetic-reader-only',
      GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_API_URL: 'https://api.github.com',
      GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REPOSITORY: POLICY.repository,
      GITHUB_REPOSITORY_OWNER: POLICY.owner, GITHUB_ACTOR: POLICY.owner, GITHUB_TRIGGERING_ACTOR: POLICY.owner,
      GITHUB_RUN_ATTEMPT: '1', GITHUB_RUN_ID: '700', GITHUB_REPOSITORY_ID: '701',
      GITHUB_REF: this.approval.ref, GITHUB_SHA: this.approval.commit, GITHUB_WORKFLOW_SHA: this.approval.commit,
      GITHUB_WORKFLOW_REF: `${POLICY.repository}/${POLICY.workflow}@${this.approval.ref}`,
    };
    this.artifacts = matrix.MATRIX.map((lane, index) => ({
      id: 800 + index, name: `npm-consumer-700-1-${lane.platform}-${lane.npm}`,
      expired: false, digest: `sha256:${'d'.repeat(64)}`,
      workflow_run: { id: 700, head_sha: this.approval.commit, repository_id: 701, head_repository_id: 701 },
    }));
    this.jobs = matrix.MATRIX.map((lane, index) => ({
      id: 900 + index, name: lane.jobName, run_id: 700, run_attempt: 1,
      head_sha: this.approval.commit, status: 'completed', conclusion: 'success',
      runner_id: 1000 + index, runner_name: `synthetic-${index}`, labels: [lane.image],
      steps: ['Require supported hosted runner', 'Verify source transfer and run real consumers',
        'Upload one consumer report'].map(name => ({ name, status: 'completed', conclusion: 'success' })),
    }));
  }

  select(target, fullDuplicate = false, countDrop = false) {
    const artifacts = [...this.artifacts];
    const jobs = [...this.jobs];
    if (fullDuplicate) (target === 'artifacts' ? artifacts : jobs).push(
      target === 'artifacts' ? artifacts[0] : jobs[0]);
    this.pages('actions/runs/700/artifacts', 'artifacts', [artifacts.slice(0, 3), artifacts.slice(3)],
      [countDrop && target === 'artifacts' ? 7 : artifacts.length, artifacts.length]);
    this.pages('actions/runs/700/attempts/1/jobs', 'jobs', [jobs.slice(0, 3), jobs.slice(3)],
      [countDrop && target === 'jobs' ? 7 : jobs.length, jobs.length]);
    for (const item of this.artifacts) this.json(`actions/artifacts/${item.id}`, item);
    return matrix.selectMatrixArtifacts({ approval: this.approval, env: this.env, ...this.readers() });
  }
}
test('L3 selector accepts complete two-page metadata and jobs through actual readers', async () => {
  const service = new SelectorService();
  const selected = await service.select();
  assert.deepEqual(selected.map(item => item.metadata.id), [800, 801, 802, 803, 804, 805]);
  assert.equal(service.calls.length, 10);
});
for (const target of ['artifacts', 'jobs']) {
  test(`L3 selector rejects complete visible duplicate ${target}`, async () => {
    await assert.rejects(new SelectorService().select(target, true), /exactly six|Missing\/duplicate current-run job/);
  });
  test(`L3 selector rejects count drop hiding duplicate ${target}`, async () => {
    await assert.rejects(new SelectorService().select(target, false, true), /total_count changed/);
  });
}

class CaptureService extends Service {
  constructor() {
    super();
    const base = fixture(version);
    this.capture = stageCaptureFixture(base.record, base.bundle);
    this.value = this.capture.fixtureOnly;
    this.value.jobs[0].run_attempt = 1;
    this.jobs = [...this.value.jobs, { ...this.value.jobs[0], name: 'source', conclusion: 'skipped' }];
  }

  read({ totalDrop = false, duplicate = false } = {}) {
    const jobs = duplicate ? [...this.jobs, this.jobs[0]] : this.jobs;
    this.json('actions/runs/123/attempts/1', this.value.run);
    this.pages('actions/runs/123/attempts/1/jobs', 'jobs', [jobs.slice(0, 1), jobs.slice(1)],
      [totalDrop ? 3 : jobs.length, jobs.length]);
    this.json('actions/artifacts/456', this.value.metadata);
    const storage = 'https://reader-contract.invalid/capture.zip';
    this.routes.set(`${api}actions/artifacts/456/zip`, { location: storage });
    this.routes.set(storage, { bytes: this.value.archive });
    return readAuthenticatedStageCapture({ ...this.capture, readers: this.readers() });
  }
}
test('L3 capture accepts numeric attempt one through actual two-page reader and archive validation', async () => {
  const service = new CaptureService();
  const actual = await service.read();
  assert.equal(actual.runAttempt, 1);
  assert.equal(actual.artifactDigest, service.value.metadata.digest);
  assert.equal(service.calls.length, 6);
});
for (const [label, attempt] of [['two', 2], ['missing', missing], ['string', '1'], ['true', true],
  ['false', false], ['zero', 0], ['null', null], ['negative', -1]]) {
  test(`L3 capture rejects stage job attempt ${label} before metadata or archive reads`, async () => {
    const service = new CaptureService();
    if (attempt === missing) delete service.jobs[0].run_attempt;
    else service.jobs[0].run_attempt = attempt;
    await assert.rejects(service.read(), /stage job attempt/);
    assert.equal(service.calls.length, 3);
  });
}
test('L3 capture rejects a complete duplicate stage job', async () => {
  await assert.rejects(new CaptureService().read({ duplicate: true }), /Missing or ambiguous actual stage run job/);
});
test('L3 capture rejects count drop hiding a duplicate stage job', async () => {
  await assert.rejects(new CaptureService().read({ totalDrop: true }), /total_count changed/);
});

for (const form of ['complete', 'count-drop', 'full-duplicate', 'repeated-page', 'missing-job']) {
  test(`L3 original collection jobs: ${form} through the actual reader and validator`, async () => {
    const original = JSON.stringify(captured);
    const jobs = captured.jobs;
    const batches = form === 'full-duplicate' ? [[...jobs, jobs[0]]]
      : form === 'repeated-page' ? [jobs.slice(0, 3), jobs.slice(0, 3)]
        : [jobs.slice(0, 2), form === 'missing-job' ? jobs.slice(2, 4) : jobs.slice(2)];
    const count = form === 'full-duplicate' || form === 'repeated-page' ? 6
      : form === 'missing-job' ? 4 : 5;
    const totals = batches.map((_, index) => form === 'count-drop' && index === 0 ? 6 : count);
    const path = `actions/runs/${captured.report.workflow.runId}/attempts/1/jobs`;
    const service = new Service().pages(path, 'jobs', batches, totals);
    const invoke = async () => {
      const result = await service.readers().readJobs(captured.report.workflow.runId, 1);
      validateCollectionJobs(result, captured.approval, captured.report);
      return result;
    };
    if (form === 'complete') assert.deepEqual(await invoke(), jobs);
    else await assert.rejects(invoke(), form === 'count-drop' ? /total_count changed/ : /Incomplete original collection topology/);
    assert.equal(JSON.stringify(captured), original, 'Preserved original job objects must not be altered');
  });
}
