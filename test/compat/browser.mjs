import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export class CompatibilityPage {
  constructor(bridge, browser) {
    this.bridge = bridge;
    this.browser = browser;
    this.errors = [];
    this.diagnostics = [];
  }

  async open(assetsRoot) {
    this.context = await this.browser.newContext({ viewport: { width: 1440, height: 1000 } });
    if (assetsRoot) await this.serveTestAssets(assetsRoot);
    this.page = await this.context.newPage();
    this.page.setDefaultTimeout(20000);
    this.page.on('pageerror', (error) => { this.errors.push(error.message); });
    this.page.on('console', (message) => {
      if (message.type() === 'error') this.diagnostics.push(message.text());
    });
    this.page.on('requestfailed', (request) => {
      this.diagnostics.push(`${request.url()}: ${request.failure()?.errorText}`);
    });
    await this.page.goto(this.bridge.base + '/ui');
    await this.prewarming();
    return this;
  }

  async serveTestAssets(root) {
    // TEST-ONLY UI asset serving: exact old/new built bytes, with the live nonce in
    // index.html. No /api, /admin or MCP request is intercepted or rewritten.
    const assets = new Map();
    const read = (relative) => {
      for (const entry of readdirSync(join(root, 'ui', 'dist', relative), { withFileTypes: true })) {
        const name = relative ? `${relative}/${entry.name}` : entry.name;
        if (entry.isDirectory()) read(name);
        else assets.set(name, readFileSync(join(root, 'ui', 'dist', name)));
      }
    };
    read('');
    this.assetHashes = Object.fromEntries([...assets].map(([name, bytes]) => [
      name, createHash('sha256').update(bytes).digest('hex'),
    ]));
    await this.context.route((url) => url.origin === this.bridge.base &&
      (url.pathname === '/ui' || url.pathname.startsWith('/ui/')), async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      const name = pathname === '/ui' || pathname === '/ui/' ? 'index.html' : pathname.slice('/ui/'.length);
      const bytes = assets.get(name);
      if (!bytes) {
        this.errors.push(`Unmapped built UI asset: ${name}`);
        await route.abort();
        return;
      }
      const html = name === 'index.html';
      const contentType = html ? 'text/html' : name.endsWith('.js') ? 'text/javascript'
        : name.endsWith('.css') ? 'text/css' : name.endsWith('.svg') ? 'image/svg+xml'
          : 'application/octet-stream';
      const body = html ? bytes.toString('utf8').replace('__MCP_NONCE__', this.bridge.nonce) : bytes;
      await route.fulfill({ status: 200, contentType, body });
    });
  }

  async prewarming() {
    await this.page.getByRole('button', { name: 'pre-warming', exact: true }).click();
    this.row = this.page.getByRole('row').filter({ has: this.page.getByText('alpha', { exact: true }) });
    await this.row.waitFor();
    this.batches = this.page.getByRole('region', { name: 'Configuration batches', exact: true });
  }

  enable() {
    return this.row.getByRole('button', { name: /^Enable pre-warming \(\d+\)$/ });
  }

  async mutation(button, status) {
    // Attach handlers to both promises immediately; a failed click must not leave
    // a later waitForResponse timeout as an unhandled rejection.
    const [response] = await Promise.all([
      this.page.waitForResponse((response) => response.request().method() === 'POST' &&
        response.url() === `${this.bridge.base}/admin/servers/alpha/pooling`),
      button.click(),
    ]);
    const text = await response.text();
    assert.equal(response.status(), status, text);
    return { response, text, body: status === 401 ? undefined : JSON.parse(text) };
  }

  async batchMutation(button, status, intent) {
    const confirmation = this.page.waitForEvent('dialog').then(async (dialog) => {
      assert.equal(dialog.type(), 'confirm');
      assert.ok(dialog.message().startsWith(`${intent} the whole batch (1 server: alpha)?`), dialog.message());
      await dialog.accept();
    });
    const [result] = await Promise.all([this.mutation(button, status), confirmation]);
    return result;
  }

  async close(t) {
    if (!this.context) return;
    t.diagnostic(`Browser diagnostics: ${JSON.stringify(this.diagnostics)}`);
    await this.context.close();
  }
}
