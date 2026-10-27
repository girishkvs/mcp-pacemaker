import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateOwnerContext, validateOwnerKey, validateOwnerReply, publishOwnerOnce } from './owner-bootstrap.mjs';
import { ownerState } from './owner-state.mjs';
import { createOwnerSdk } from './owner-sdk.mjs';

export function verificationRequest(send, binding, requestId, receive, signal) {
  return new Promise((resolveRequest, reject) => {
    const request = { type: 'revalidate', requestId, binding };
    const dispose = () => {
      receive.removeListener('message', reply);
      signal.removeEventListener('abort', abort);
    };
    const abort = () => { dispose(); reject(new Error('Owner verification cancelled')); };
    const reply = message => {
      dispose();
      try {
        validateOwnerReply(message, request);
        resolveRequest();
      } catch { reject(new Error('Owner verification correlation failed')); }
    };
    receive.once('message', reply);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) return abort();
    send(request);
  });
}

async function main() {
  assert.equal(process.argv.length, 2, 'Owner child accepts no credential or source arguments');
  assert.equal(typeof process.send, 'function', 'Owner process requires its verified parent IPC channel');
  assert.equal(process.env.GITHUB_TOKEN, undefined);
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const approval = JSON.parse(event.inputs.approval);
  validateOwnerContext({ env: process.env, event, approval });
  const state = ownerState(process.env, approval);
  const abort = new AbortController();
  const stop = () => abort.abort();
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  process.once('disconnect', stop);
  const timeout = setTimeout(stop, 20 * 60 * 1000);
  let recordId = 0;
  let requestId = 0;
  try {
    const sdk = createOwnerSdk({ cli: process.env.NPM_PUBLICATION_CLI, directory: join(state.directory, 'signed'),
      home: join(state.directory, 'home'), approval });
    await sdk.checkBytes();
    // The separately reviewed helper owns all envelope cryptography.
    const sealer = validateOwnerKey(approval.ownerAuth);
    const result = await publishOwnerOnce({ approval, sdk, signal: abort.signal,
      revalidate: () => verificationRequest(message => process.send(message), state.binding,
        ++requestId, process, abort.signal),
      record: async value => state.write('ledger', `owner-${String(++recordId).padStart(3, '0')}.json`,
        { schemaVersion: 1, binding: state.binding, recordedAt: new Date().toISOString(), ...value }),
      challenge: async (sequence, kind, url) => {
        const envelope = sealer.seal({ ...state.binding, sequence, kind }, url);
        state.write('challenges', `challenge-${sequence}.json`, envelope);
      },
    });
    state.write('ledger', 'done.json', { schemaVersion: 1, binding: state.binding,
      recordedAt: new Date().toISOString(), ...result });
    process.exitCode = result.success ? 0 : 1;
  } finally {
    clearTimeout(timeout);
    if (process.connected) process.disconnect();
  }
}

if (process.argv[1] &&
    resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    // No raw SDK error, URL, OTP or session material reaches stdout, stderr or IPC.
    process.exitCode = 1;
    if (process.connected) process.disconnect();
  });
}
