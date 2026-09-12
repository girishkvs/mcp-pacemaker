import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../package.json', import.meta.url));
const ts = require('typescript');
const compile = (module, filename) => {
  const result = ts.transpileModule(readFileSync(filename, 'utf8'), {
    fileName: filename,
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX },
  });
  module._compile(result.outputText, filename);
};
require.extensions['.ts'] = compile;
require.extensions['.tsx'] = compile;

const React = require('react');
const { createRoot } = require('react-dom/client');
const { useEventSource } = require('./src/hooks/useEventSource.ts');
const { usePoolingActions } = require('./src/hooks/usePoolingActions.ts');
const { PoolingBatchStatus } = require('./src/components/PoolingBatchStatus.tsx');
const { PoolingControls } = require('./src/components/PoolingControls.tsx');
const { renderToStaticMarkup } = require('react-dom/server');

export class UiHookHarness {
  constructor() {
    this.events = [];
    this.requests = [];
    this.savedGlobals = new Map();
  }

  async start(snapshot) {
    for (const name of ['window', 'document', 'EventSource', 'fetch', 'IS_REACT_ACT_ENVIRONMENT']) {
      this.savedGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    }
    const document = {
      nodeType: 9,
      addEventListener() {},
      removeEventListener() {},
      querySelector: () => ({ getAttribute: () => 'test-nonce' }),
    };
    this.container = {
      nodeType: 1,
      nodeName: 'DIV',
      tagName: 'DIV',
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      ownerDocument: document,
      addEventListener() {},
      removeEventListener() {},
    };
    const window = {
      document,
      HTMLIFrameElement: class {},
      confirm: () => true,
      setInterval: (...args) => setInterval(...args).unref(),
      clearInterval,
    };
    const harness = this;
    class TestEventSource {
      constructor(url) {
        this.url = url;
        harness.events.push(this);
      }
      close() {
        this.closed = true;
      }
    }
    Object.assign(globalThis, {
      window,
      document,
      EventSource: TestEventSource,
      IS_REACT_ACT_ENVIRONMENT: true,
      fetch: (url, options) => new Promise((resolve) => {
        harness.requests.push({ url, options, resolve });
      }),
    });
    function Probe() {
      const channel = useEventSource('/api/events');
      const actions = usePoolingActions(channel.data, channel.connected, channel.setData);
      harness.current = { channel, actions };
      return null;
    }
    this.root = createRoot(this.container);
    await React.act(async () => this.root.render(React.createElement(Probe)));
    await React.act(async () => {
      this.events[0].onopen();
      this.events[0].onmessage({ data: JSON.stringify(snapshot) });
    });
  }

  async frame(snapshot) {
    await React.act(async () => this.events[0].onmessage({ data: JSON.stringify(snapshot) }));
  }

  async begin(action, ...args) {
    const operation = {};
    await React.act(async () => {
      operation.done = this.current.actions[action](...args);
    });
    operation.request = this.requests.at(-1);
    return operation;
  }

  async respond(operation, body, status = 200, frameBeforeResponse) {
    await React.act(async () => {
      if (frameBeforeResponse) this.events[0].onmessage({ data: JSON.stringify(frameBeforeResponse) });
      operation.request.resolve(new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }));
      await operation.done;
    });
  }

  async respondWithoutFinishing(request, body, status = 200) {
    await React.act(async () => {
      request.resolve(new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }));
    });
  }

  async close() {
    if (this.root) await React.act(async () => this.root.unmount());
    for (const [name, descriptor] of this.savedGlobals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }

  renderBatchStatus() {
    return renderToStaticMarkup(React.createElement(PoolingBatchStatus, {
      actions: this.current.actions,
      snapshot: this.current.channel.data,
      connected: this.current.channel.connected,
      snapshotError: this.current.channel.error,
    }));
  }

  renderPoolingControls(name) {
    return renderToStaticMarkup(React.createElement(PoolingControls, {
      server: this.current.channel.data.servers.find((server) => server.name === name),
      actions: this.current.actions,
      enabled: this.current.channel.connected && Boolean(this.current.channel.data.prewarm),
    }));
  }

  snapshot(snapshotVersion, revision, batches = [], instanceId = 'bridge-a') {
    return {
      ok: true,
      service: 'mcp-pacemaker',
      version: 'test',
      port: 1,
      uptimeSec: 1,
      instanceId,
      snapshotVersion,
      sessions: 0,
      prewarm: { revision, maxWarm: 4, batchDelayMs: 5000, batches },
      servers: [{
        name: 'alpha',
        type: 'stdio',
        sessions: 0,
        pids: [],
        requests: 0,
        lastError: null,
        lastActivitySec: null,
        sharing: revision === 'r0' ? 'isolated' : 'pool',
        minWarm: revision === 'r0' ? 0 : 1,
        prewarming: { eligible: true, suggestedMinWarm: 1, configuredMinWarm: null },
      }],
    };
  }

  batch(status = 'pending', revision = 'r0', id = 'batch-a') {
    return {
      id,
      status,
      revision,
      applyAt: status === 'pending' ? Date.now() + 5000 : null,
      changes: [{ name: 'alpha', mode: 'pool', minWarm: 1 }],
    };
  }

  receipt(snapshot, batchId = 'batch-a', undoId = 'private-test-token') {
    return { ok: true, name: 'alpha', pending: true, batchId, revision: snapshot.prewarm.revision, undoId, snapshot };
  }
}
