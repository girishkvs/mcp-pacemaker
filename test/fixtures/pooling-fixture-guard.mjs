import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join } from 'node:path';
import { DeadlineFixture } from '../helpers/pooling-deadline-fixture.mjs';
import { PoolingConfigWriter } from '../../bin/pooling-writer.mjs';

const mode = process.argv[2];
assert.ok(['completion', 'teardown'].includes(mode));
const method = mode === 'completion' ? 'apply' : 'close';
PoolingConfigWriter.prototype[method] = function () {
  return new Promise(() => {});
};
const keepAlive = setInterval(() => {}, 1000);
try {
  await test(`stalled ${mode} after checkpoint`, { timeout: 2000 }, async (t) => {
    const fixture = new DeadlineFixture(t, 'commit-completed', { guardMs: 100 });
    fs.writeFileSync(join(fixture.directory, 'entered'), fixture.stage);
    await fixture.entered(Promise.resolve());
    if (mode === 'completion') await fixture.writer.apply(fixture.request());
  });
} finally {
  clearInterval(keepAlive);
}
