import assert from 'node:assert/strict';
import { test } from 'node:test';
import { UserRuntimeContext } from '../bin/runtime-context.mjs';

class ContextFixture {
  constructor(platform = 'linux') {
    this.ids = { uid: 1000, euid: 1000, gid: 1000, egid: 1000 };
    this.changes = 0;
    this.status = [
      'Uid:\t1000\t1000\t1000\t1000',
      'Gid:\t1000\t1000\t1000\t1000',
      ...['CapInh', 'CapPrm', 'CapEff', 'CapAmb'].map(name => `${name}:\t0000000000000000`),
    ].join('\n');
    this.host = {
      platform,
      getuid: () => this.ids.uid, geteuid: () => this.ids.euid,
      getgid: () => this.ids.gid, getegid: () => this.ids.egid,
      setuid: () => { this.changes++; }, seteuid: () => { this.changes++; },
      setgid: () => { this.changes++; }, setegid: () => { this.changes++; },
    };
    this.context = new UserRuntimeContext({ host: this.host, linuxStatus: () => this.status });
  }

  async refused(code = 'USER_RUNTIME_PRIVILEGED') {
    await assert.rejects(this.context.require(), { code });
    assert.equal(this.changes, 0);
  }
}

for (const platform of ['linux', 'darwin']) {
  test(`${platform} accepts a stable ordinary identity without changing it`, async () => {
    const fixture = new ContextFixture(platform);
    const result = await fixture.context.require();
    assert.equal(result.platform, platform);
    assert.equal(result.ordinary, true);
    assert.deepEqual(result.identity, fixture.ids);
    assert.equal(result.atomicFutureProtection, false);
    assert.equal(fixture.changes, 0);
  });

  for (const [field, value] of [['uid', 0], ['euid', 0], ['euid', 1001], ['egid', 1001]]) {
    test(`${platform} refuses ${field}=${value} without switching identity`, async () => {
      const fixture = new ContextFixture(platform);
      fixture.ids[field] = value;
      await fixture.refused();
    });
  }
}

for (const field of ['CapInh', 'CapPrm', 'CapEff', 'CapAmb']) {
  test(`Linux refuses nonzero ${field}`, async () => {
    const fixture = new ContextFixture();
    fixture.status = fixture.status.replace(`${field}:\t0000000000000000`, `${field}:\t0000000000000001`);
    await fixture.refused();
  });
}

for (const replacement of ['Uid:\t1000\t1000\t0\t1000', 'Uid:\t1000\t1000\t1000\t0']) {
  test(`Linux refuses saved/filesystem identity mismatch: ${replacement}`, async () => {
    const fixture = new ContextFixture();
    fixture.status = fixture.status.replace('Uid:\t1000\t1000\t1000\t1000', replacement);
    await fixture.refused();
  });
}

for (const [name, change] of [
  ['missing capability', text => text.replace('CapEff:\t0000000000000000', '')],
  ['duplicate capability', text => `${text}\nCapEff:\t0000000000000000`],
  ['invalid capability', text => text.replace('CapEff:\t0000000000000000', 'CapEff:\tunverified')],
  ['oversized observation', () => 'x'.repeat(16385)],
]) {
  test(`Linux refuses ${name}`, async () => {
    const fixture = new ContextFixture();
    fixture.status = change(fixture.status);
    await fixture.refused('USER_RUNTIME_CONTEXT_UNVERIFIED');
  });
}

test('Linux reports observation failure rather than assuming an ordinary context', async () => {
  const fixture = new ContextFixture();
  fixture.context.linuxStatus = () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); };
  await fixture.refused('USER_RUNTIME_CONTEXT_UNVERIFIED');
});

test('identity drift during observation refuses execution', async () => {
  const fixture = new ContextFixture();
  fixture.context.linuxStatus = () => {
    const status = fixture.status;
    fixture.ids = { uid: 1001, euid: 1001, gid: 1001, egid: 1001 };
    return status;
  };
  await fixture.refused('USER_RUNTIME_CONTEXT_UNVERIFIED');
});

test('missing identity APIs and unsupported platforms fail explicitly', async () => {
  const missing = new ContextFixture('darwin');
  delete missing.host.geteuid;
  await missing.refused('USER_RUNTIME_CONTEXT_UNVERIFIED');
  await new ContextFixture('unsupported').refused('USER_RUNTIME_CONTEXT_UNVERIFIED');
});

test('Windows delegates to the unchanged native enforcement and preserves its refusal', async () => {
  const failure = new Error('native ordinary-context refusal');
  const context = new UserRuntimeContext({
    host: { platform: 'win32' },
    windowsCheck: async () => { throw failure; },
  });
  await assert.rejects(context.require(), error => error === failure);
  context.windowsCheck = async () => undefined;
  await assert.rejects(context.require(), { code: 'USER_RUNTIME_CONTEXT_UNVERIFIED' });
  const proof = { ordinaryEligible: true, proofScope: 'cli-effective-context-snapshot' };
  context.windowsCheck = async () => proof;
  assert.equal((await context.require()).native, proof);
});
