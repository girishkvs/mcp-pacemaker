import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateStageLoader, npmLoaderInventory } from './stage-loader.mjs';
import { StageListAudit, OWNER_LIST_LIMITS, OWNER_LIST_REGISTRY, ownerListHash } from './owner-stage-list-audit.mjs';
import { ownerListSourceBinding, publishOwnerListJson, readOwnerListJson } from './owner-stage-list-io.mjs';

export class OwnerStageListTransport {
  constructor(fetcher, audit, Response, timeoutMs = OWNER_LIST_LIMITS.commandMs) {
    assert.ok(Number.isSafeInteger(timeoutMs) &&
      timeoutMs > 0 &&
      timeoutMs <= OWNER_LIST_LIMITS.commandMs);
    this.fetcher = fetcher;
    this.audit = audit;
    this.Response = Response;
    this.expires = performance.now() + timeoutMs;
    this.totalBytes = 0;
    this.pages = new Set();
    this.secrets = new Set();
  }

  rejectSecrets(bytes) {
    for (const secret of this.secrets) assert.equal(bytes.includes(Buffer.from(secret)), false, 'Credential material in owner read projection');
  }

  async request(uri, options = {}) {
    let response;
    let timer;
    const controller = new AbortController();
    try {
      const query = this.audit.pendingQuery();
      const expected = `${OWNER_LIST_REGISTRY}-/stage?page=${query.page}&perPage=100&package=mcp-pacemaker`;
      assert.equal(String(uri), expected, 'Unexpected physical stage-list GET');
      assert.equal(options.method ?? 'GET', 'GET');
      assert.equal(options.body, undefined, 'Unexpected GET body');
      assert.equal(this.pages.has(query.page), false, 'Physical stage-list retry forbidden');
      this.pages.add(query.page);
      const auth = new Headers(options.headers).get('authorization');
      if (auth) {
        this.secrets.add(auth);
        const token = auth.slice(auth.indexOf(' ') + 1);
        if (token) this.secrets.add(token);
        if (auth.startsWith('Basic ')) {
          const decoded = Buffer.from(token, 'base64').toString('utf8');
          this.secrets.add(decoded);
          const password = decoded.slice(decoded.indexOf(':') + 1);
          if (password) this.secrets.add(password);
        }
      }
      const remaining = Math.ceil(this.expires - performance.now());
      assert.ok(remaining > 0, 'Owner stage-list deadline');
      const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
      const operation = async () => {
        response = await this.fetcher(expected, {
          ...options, redirect: 'error', retry: { retries: 0 }, strictSSL: true,
          cache: 'no-store', cachePath: undefined, memoize: false,
          size: OWNER_LIST_LIMITS.responseBytes, timeout: remaining, signal,
          proxy: undefined, noProxy: '*',
        });
        signal.throwIfAborted();
        assert.equal(response.status, 200, 'Stage-list response must be200');
        assert.ok(!response.headers.has('x-local-cache'), 'Stage-list cached response forbidden');
        const chunks = [];
        let count = 0;
        for await (const chunk of response.body) {
          signal.throwIfAborted();
          const length = typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.byteLength;
          assert.ok(Number.isSafeInteger(length) &&
            length >= 0, 'Invalid response chunk');
          count += length;
          this.totalBytes += length;
          assert.ok(count <= OWNER_LIST_LIMITS.responseBytes, 'Stage-list response byte limit');
          assert.ok(this.totalBytes <= OWNER_LIST_LIMITS.responseTotalBytes, 'Stage-list cumulative response byte limit');
          chunks.push(Buffer.from(chunk));
        }
        const bytes = Buffer.concat(chunks);
        new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        this.body = { bytes: count, sha256: ownerListHash(bytes), status: 200,
          representation: 'Decoded HTTP entity bytes before JSON parsing; raw body not retained.' };
        // Buffer bounded bytes unchanged; original registry.json still invokes the SDK JSON parser.
        return new this.Response(Readable.from([bytes]), { status: 200, headers: response.headers, url: expected });
      };
      return await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          response?.body?.destroy?.();
          reject(new Error('Owner stage-list deadline'));
        }, remaining);
      })]);
    } catch {
      this.audit.poison();
      controller.abort();
      response?.body?.destroy?.();
      throw new Error('Owner stage-list transport rejected; no retry or accepted observation');
    } finally {
      clearTimeout(timer);
    }
  }
}

export function installOwnerStageListAudit(cli, timeoutMs) {
  const { entry, root, require } = validateStageLoader(cli);
  assert.equal(ownerListHash(readFileSync(resolve(root, 'lib/commands/stage/list.js'))),
    'a70d3cf3f97c0579f749e71b57cb30c2d7669378cf1d5596ff4ca8404b19586a');
  const registryPath = require.resolve('npm-registry-fetch');
  const transportPath = require.resolve('make-fetch-happen');
  const originalTransport = require(transportPath);
  const audit = new StageListAudit();
  const transport = new OwnerStageListTransport(originalTransport, audit, originalTransport.Response, timeoutMs);
  const context = new AsyncLocalStorage();
  const guarded = (uri, options) => {
    if (!context.getStore()) {
      audit.poison();
      throw new Error('Unrelated owner stage-list transport forbidden');
    }
    return transport.request(uri, options);
  };
  const hooked = Object.assign(guarded, originalTransport);
  hooked.defaults = (url, options) => originalTransport.defaults(url, options, guarded);
  require.cache[transportPath].exports = hooked;
  const registry = require(registryPath);
  const originalJson = registry.json;
  const scoped = Object.assign(() => {
    audit.poison();
    throw new Error('Only owner stage-list JSON reads permitted');
  }, registry);
  scoped.json = async (uri, options) => {
    try {
      audit.begin(uri, options);
      const response = await context.run(true, () => originalJson(uri, options));
      audit.accept(response, transport.body);
      return response;
    } catch {
      audit.poison();
      throw new Error('Owner stage-list response rejected; no accepted observation');
    }
  };
  scoped.json.stream = scoped;
  require.cache[registryPath].exports = scoped;
  const loader = JSON.parse(readFileSync(new URL('./stage-sdk-loader.json', import.meta.url))).inventory;
  return { entry, root, audit, transport, loader };
}

function main() {
  assert.equal(process.argv.length, 3);
  assert.equal(process.versions.node, '24.21.0');
  const request = readOwnerListJson(resolve(process.argv[2]), OWNER_LIST_LIMITS.contextBytes);
  assert.deepEqual(ownerListSourceBinding(), request.source);
  const installed = installOwnerStageListAudit(request.cli, request.timeoutMs);
  const loaderBefore = installed.loader;
  let eventOutput;
  let outputCount = 0;
  process.on('output', (level, ...args) => {
    if (level !== 'standard') return;
    try {
      assert.equal(++outputCount, 1);
      assert.equal(typeof args[0], 'string');
      assert.ok(Buffer.byteLength(args[0]) <= OWNER_LIST_LIMITS.stdoutBytes);
      eventOutput = args[0];
    } catch {
      installed.audit.poison();
      throw new Error('Owner stage-list output rejected');
    }
  });
  const finalizeObservation = () => {
    try {
      assert.equal(process.exitCode ?? 0, 0);
      assert.equal(outputCount, 1);
      const audit = installed.audit.finish(eventOutput);
      assert.deepEqual(ownerListSourceBinding(), request.source);
      assert.deepEqual(npmLoaderInventory(installed.root), loaderBefore);
      const candidate = {
        kind: 'owner-stage-list-unaccepted-observation', requestId: request.requestId,
        source: request.source, cli: installed.entry, loader: loaderBefore,
        audit, physicalRequests: installed.transport.pages.size,
        responseBytes: installed.transport.totalBytes,
        expectedStdout: { bytes: Buffer.byteLength(`${eventOutput}\n`), sha256: ownerListHash(`${eventOutput}\n`) },
      };
      installed.transport.rejectSecrets(Buffer.from(JSON.stringify(candidate)));
      publishOwnerListJson(request.scratch, 'observation.json', candidate);
    } catch {
      process.exitCode = Number(process.exitCode) || 1;
    }
  };
  process.argv = [process.execPath, installed.entry, 'stage', 'list', 'mcp-pacemaker',
    '--json', `--registry=${OWNER_LIST_REGISTRY}`, '--logs-max=0', '--loglevel=silent',
    '--update-notifier=false', '--timing=false', `--cache=${join(request.scratch, 'npm-cache')}`];
  createRequire(installed.entry)(installed.entry);
  // Pinned npm registers its exit handler before its first await; finalize after its cleanup.
  process.on('exit', finalizeObservation);
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch {
    console.error('Owner stage-list child rejected; no accepted observation.');
    process.exitCode = 1;
  }
}
