import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PoolingConfigWriter } from '../bin/pooling-writer.mjs';

test('accepted valid no-op queue fits the existing 10-second request budget', async (t) => {
  const directory = fs.mkdtempSync(join(tmpdir(), 'queue-budget-'));
  const path = join(directory, 'servers.json');
  const original = '{"alpha":{"command":"node"}}\n';
  fs.writeFileSync(path, original, { mode: 0o600 });
  const revision = createHash('sha256').update(original).digest('hex');
  const writer = new PoolingConfigWriter(path);
  const acceptedMs = [];
  let timerTicks = 0;
  const timer = setInterval(() => { timerTicks++; }, 10);
  t.after(async () => {
    clearInterval(timer);
    await writer.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const started = performance.now();
  const requests = Array.from({ length: 17 }, async () => {
    const result = await writer.apply({ name: 'alpha', mode: 'isolated', revision });
    acceptedMs.push(Math.round(performance.now() - started));
    return result;
  });
  const results = await Promise.allSettled(requests);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 16);
  assert.equal(results.filter((result) => result.reason?.code === 'WRITER_BUSY').length, 1);
  assert.equal(fs.readFileSync(path, 'utf8'), original);
  assert.deepEqual(fs.readdirSync(directory), ['servers.json']);
  assert.ok(timerTicks > 0);
  t.diagnostic(`QUEUE_BUDGET ${JSON.stringify({ acceptedMs, timerTicks, limitMs: 10000 })}`);
  assert.ok(Math.max(...acceptedMs) < 10000,
    'Accepted, valid requests must fit the existing client budget including queue wait');
});
