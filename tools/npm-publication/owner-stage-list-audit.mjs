import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const OWNER_LIST_LIMITS = Object.freeze({
  responseBytes: 128 * 1024, responseTotalBytes: 512 * 1024,
  stdoutBytes: 256 * 1024, stderrBytes: 64 * 1024,
  receiptBytes: 1024 * 1024, contextBytes: 64 * 1024,
  commandMs: 30_000, pages: 20, pageSize: 100,
});
export const OWNER_LIST_REGISTRY = 'https://registry.npmjs.org/';
export const OWNER_LIST_PACKAGE = 'mcp-pacemaker';
export const ownerListHash = value => createHash('sha256').update(value).digest('hex');
const stageId = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;

export function boundedOwnerJson(value, limit) {
  let nodes = 0;
  let budget = 0;
  const seen = new Set();
  const visit = (item, depth) => {
    assert.ok(depth <= 16 &&
      ++nodes <= 20_000, 'Owner read JSON complexity limit');
    if (item === null ||
        typeof item === 'boolean' ||
        typeof item === 'number') {
      assert.ok(typeof item !== 'number' ||
        Number.isFinite(item), 'Invalid owner read JSON number');
      budget += 8;
    } else if (typeof item === 'string') {
      assert.ok(Buffer.byteLength(item) <= limit, 'Owner read JSON string limit');
      budget += Buffer.byteLength(JSON.stringify(item));
    } else {
      assert.ok(item &&
        typeof item === 'object' &&
        !seen.has(item), 'Invalid owner read JSON value');
      assert.ok(Array.isArray(item) ||
        Object.getPrototypeOf(item) === Object.prototype ||
        Object.getPrototypeOf(item) === null, 'Invalid owner read JSON object');
      seen.add(item);
      const keys = Object.keys(item);
      assert.ok(keys.length <= 20_000, 'Owner read JSON member limit');
      budget += 2 + keys.length;
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        assert.ok(Object.hasOwn(descriptor, 'value'), 'Owner read JSON accessors forbidden');
        if (!Array.isArray(item)) visit(key, depth + 1);
        visit(descriptor.value, depth + 1);
      }
      seen.delete(item);
    }
    assert.ok(budget <= limit * 2, 'Owner read JSON budget');
  };
  visit(value, 0);
  const bytes = Buffer.from(JSON.stringify(value));
  assert.ok(bytes.length <= limit, 'Owner read JSON byte limit');
  return bytes;
}

export class StageListAudit {
  #pending;
  #total;
  #failed = false;
  #closed = false;
  #pages = [];
  #items = [];
  #ids = new Set();
  #parsedBytes = 0;

  #validate(action) {
    this.healthy();
    try {
      return action();
    } catch (error) {
      this.#failed = true;
      throw error;
    }
  }

  healthy() {
    assert.equal(this.#failed, false, 'Previous stage-list validation failed');
    assert.equal(this.#closed, false, 'Stage-list audit already consumed');
  }

  poison() {
    this.#failed = true;
  }

  pendingQuery() {
    this.healthy();
    assert.ok(this.#pending, 'No pending owner stage-list request');
    return { ...this.#pending };
  }

  begin(uri, options = {}) {
    this.#validate(() => {
      assert.equal(uri, '/-/stage', 'Unexpected stage-list endpoint');
      assert.equal(options.registry, OWNER_LIST_REGISTRY, 'Unexpected stage registry');
      assert.equal(options.method ?? 'GET', 'GET', 'Stage-list audit is read-only');
      assert.equal(options.body, undefined, 'Stage-list GET body forbidden');
      assert.equal(this.#pending, undefined, 'Overlapping stage-list requests');
      assert.ok(this.#pages.length < OWNER_LIST_LIMITS.pages, 'Stage-list page limit exceeded');
      assert.ok(this.#total === undefined ||
        this.#items.length < this.#total, 'Stage list is already complete');
      assert.deepEqual(options.query, {
        page: this.#pages.length, perPage: OWNER_LIST_LIMITS.pageSize, package: OWNER_LIST_PACKAGE,
      }, 'Unexpected stage-list page query');
      this.#pending = { ...options.query };
    });
  }

  accept(response, body) {
    this.#validate(() => {
      assert.ok(this.#pending, 'Unsolicited stage-list response');
      const encoded = boundedOwnerJson(response, OWNER_LIST_LIMITS.responseBytes);
      this.#parsedBytes += encoded.length;
      assert.ok(this.#parsedBytes <= OWNER_LIST_LIMITS.responseTotalBytes, 'Cumulative parsed response limit');
      assert.ok(response &&
        typeof response === 'object' &&
        !Array.isArray(response), 'Missing stage-list response envelope');
      assert.ok(Number.isSafeInteger(response.total) &&
        response.total >= 0 &&
        response.total <= OWNER_LIST_LIMITS.pageSize * OWNER_LIST_LIMITS.pages, 'Invalid stage-list total');
      assert.ok(Array.isArray(response.items) &&
        response.items.length <= OWNER_LIST_LIMITS.pageSize, 'Invalid stage-list items');
      if (this.#total !== undefined) assert.equal(response.total, this.#total, 'Stage-list total changed during enumeration');
      const count = this.#items.length + response.items.length;
      assert.ok(count <= response.total, 'Stage-list count exceeds declared total');
      assert.ok(response.items.length === OWNER_LIST_LIMITS.pageSize ||
        count === response.total, 'Incomplete stage-list page');
      for (const item of response.items) {
        assert.ok(item &&
          typeof item === 'object' &&
          !Array.isArray(item), 'Invalid stage item');
        assert.equal(item.packageName, OWNER_LIST_PACKAGE, 'Stage belongs to another package');
        assert.match(item.id ?? '', stageId, 'Invalid stage ID');
        assert.equal(item.id.length, 36, 'Invalid stage ID length');
        const id = item.id.toLowerCase();
        assert.equal(this.#ids.has(id), false, 'Repeated stage ID');
        this.#ids.add(id);
      }
      this.#total = response.total;
      this.#items.push(...structuredClone(response.items));
      this.#pages.push({
        query: this.#pending,
        response: { total: response.total, items: response.items.map(({ id, packageName }) => ({ id, packageName })) },
        parsedEnvelope: { bytes: encoded.length, sha256: ownerListHash(encoded) },
        ...(body ? { body } : {}),
      });
      this.#pending = undefined;
    });
  }

  finish(stdout) {
    return this.#validate(() => {
      assert.ok(this.#pages.length > 0, 'No completed stage-list request');
      assert.equal(this.#pending, undefined, 'Stage-list request did not complete');
      assert.equal(this.#items.length, this.#total, 'Incomplete stage enumeration');
      assert.equal(typeof stdout, 'string', 'Missing actual StageList output');
      assert.ok(Buffer.byteLength(stdout) <= OWNER_LIST_LIMITS.stdoutBytes, 'Stage-list stdout byte limit');
      const parsed = JSON.parse(stdout);
      boundedOwnerJson(parsed, OWNER_LIST_LIMITS.stdoutBytes);
      assert.deepEqual(parsed, this.#items, 'CLI output differs from response envelopes');
      this.#closed = true;
      return {
        packageName: OWNER_LIST_PACKAGE, total: this.#total,
        pages: this.#pages, parsedBytes: this.#parsedBytes,
        output: { bytes: Buffer.byteLength(stdout), sha256: ownerListHash(stdout) },
        projection: 'Only item id/packageName retained; other parsed fields and raw output omitted.',
        mutationAuthorized: false,
      };
    });
  }
}
