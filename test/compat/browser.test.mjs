import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { ROOT, loadFixtures } from '../../tools/compatibility/fixtures.mjs';
import { CompatibilityBridge, assertImmediate, assertPending, assertSnapshot } from './bridge.mjs';
import { CompatibilityPage } from './browser.mjs';

const fixtures = loadFixtures();
const require = createRequire(join(ROOT, 'ui', 'package.json'));
const { chromium } = require('playwright');
let browser;
before(async () => {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.MCP_COMPAT_BROWSER_CHANNEL ? { channel: process.env.MCP_COMPAT_BROWSER_CHANNEL } : {}),
  });
});
after(async () => { if (browser) await browser.close(); });

async function withPage(t, bridge, assetsRoot, action) {
  const ui = new CompatibilityPage(bridge, browser);
  let failed = false;
  try {
    await ui.open(assetsRoot);
    if (assetsRoot) t.diagnostic(`TEST-ONLY built asset serving; real API backend. SHA-256: ${JSON.stringify(ui.assetHashes)}`);
    await action(ui);
    assert.deepEqual(ui.errors, []);
  } catch (error) {
    failed = true;
    t.diagnostic(`Browser page errors: ${JSON.stringify(ui.errors)}`);
    try { t.diagnostic(await ui.page.locator('body').innerText({ timeout: 2000 })); }
    catch (diagnosticError) { t.diagnostic(`Page dump failed: ${diagnosticError.message}`); }
    throw error;
  } finally {
    try { await ui.close(t); }
    catch (error) {
      if (!failed) throw error;
      t.diagnostic(`Browser cleanup also failed: ${error.stack}`);
    }
  }
}

test('2.0.0 built dashboard -> real 1.3.0: legacy 200 enable and Undo', { timeout: 90000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.legacy, '1.3.0');
    await bridge.seedAdvice();
    await withPage(t, bridge, fixtures.candidate, async (ui) => {
      const enabled = await ui.mutation(ui.enable(), 200);
      assert.equal(enabled.response.request().headers()['x-mcp-pooling-batch'], '1');
      assertImmediate(enabled.body, '1.3.0');
      await ui.row.getByRole('status').filter({ hasText: /^Enabled \d+ warm slot/ }).waitFor();
      assert.equal(JSON.parse(bridge.text()).alpha.sharing, 'pool');
      const undo = await ui.mutation(ui.row.getByRole('button', { name: 'Undo', exact: true }), 200);
      assert.equal(undo.body.ok, true);
      assertSnapshot(undo.body.snapshot, '1.3.0');
      await ui.row.getByRole('status').filter({ hasText: 'Previous pooling settings restored.' }).waitFor();
      await bridge.assertUnchanged();
    });
  });
});

test('1.3.0 built dashboard -> real 2.0.0: current nonce, protocol 409, no write', { timeout: 90000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.candidate, '2.0.0');
    await bridge.seedAdvice();
    await withPage(t, bridge, fixtures.legacy, async (ui) => {
      const rejected = await ui.mutation(ui.enable(), 409);
      assert.equal(rejected.response.request().headers()['x-mcp-nonce'], bridge.nonce);
      assert.equal(rejected.response.request().headers()['x-mcp-pooling-batch'], undefined);
      assert.match(rejected.body.error, /Reload the dashboard or update the CLI/);
      await ui.row.getByRole('alert').filter({ hasText: 'Reload the dashboard or update the CLI' }).waitFor();
      await bridge.assertUnchanged();
      assert.deepEqual((await bridge.snapshot()).prewarm.batches, []);
    });
  });
});

test('real old tab survives actual 1.3.0 -> 2.0.0 restart: 401 then refresh and accepted save', { timeout: 120000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    const old = await bridge.start(fixtures.legacy, '1.3.0');
    await bridge.seedAdvice();
    // No UI interception in this test: the old tab and refreshed assets are
    // served by their respective real backend processes on the same port.
    await withPage(t, bridge, undefined, async (ui) => {
      const oldNonce = bridge.nonce;
      await ui.enable().waitFor();
      await bridge.stop();
      const current = await bridge.start(fixtures.candidate, '2.0.0');
      assert.notEqual(current.instanceId, old.instanceId);
      assert.notEqual(bridge.nonce, oldNonce);
      await bridge.seedAdvice();
      await ui.page.getByText(/v2\.0\.0/).waitFor();
      const expired = await ui.mutation(ui.enable(), 401);
      assert.equal(expired.response.request().headers()['x-mcp-nonce'], oldNonce);
      assert.equal(expired.text, 'bad nonce');
      await ui.row.getByRole('alert').filter({ hasText: 'Admin session expired.' }).waitFor();
      await bridge.assertUnchanged();

      await ui.page.reload();
      await ui.prewarming();
      await ui.batches.waitFor();
      const staged = await ui.mutation(ui.enable(), 202);
      assert.equal(staged.response.request().headers()['x-mcp-nonce'], bridge.nonce);
      assert.equal(staged.response.request().headers()['x-mcp-pooling-batch'], '1');
      assertPending(staged.body);
      const cancel = await ui.batchMutation(ui.batches.getByRole('button', { name: /^Cancel batch/ }), 200, 'Cancel');
      assert.equal(cancel.body.cancelled, true);
      await bridge.assertUnchanged();
    });
  });
});

test('packed 2.0.0 dashboard -> real 2.0.0: queued save, Cancel, apply and whole-batch Undo', { timeout: 120000 }, async (t) => {
  await new CompatibilityBridge().run(t, async (bridge) => {
    await bridge.start(fixtures.candidate, '2.0.0');
    await bridge.seedAdvice();
    await withPage(t, bridge, undefined, async (ui) => {
      const first = await ui.mutation(ui.enable(), 202);
      assertPending(first.body);
      assert.equal(bridge.text(), bridge.original);
      await ui.row.getByRole('status').filter({ hasText: /^Pending/ }).waitFor();
      const cancel = await ui.batchMutation(ui.batches.getByRole('button', { name: /^Cancel batch/ }), 200, 'Cancel');
      assert.equal(cancel.body.ok, true);
      assert.equal(cancel.body.cancelled, true);
      await ui.batches.getByRole('status').filter({ hasText: /^Batch cancelled$/ }).waitFor();
      await bridge.assertUnchanged();

      const second = await ui.mutation(ui.enable(), 202);
      assertPending(second.body);
      assert.equal(bridge.text(), bridge.original);
      await bridge.applied(second.body.batchId);
      await ui.batches.getByRole('status').filter({ hasText: /^Batch applied$/ }).waitFor();
      assert.equal(JSON.parse(bridge.text()).alpha.sharing, 'pool');
      const pooledBytes = bridge.text();
      const undo = await ui.batchMutation(ui.batches.getByRole('button', { name: /^Undo batch/ }), 202, 'Undo');
      assertPending(undo.body);
      assert.equal(bridge.text(), pooledBytes);
      await bridge.applied(undo.body.batchId);
      await ui.row.getByRole('status').filter({ hasText: /^Batch applied/ }).waitFor();
      await ui.enable().waitFor();
      await bridge.assertUnchanged();
    });
  });
});
