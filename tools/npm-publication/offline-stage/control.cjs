'use strict';
// Replace the real underlay FIRST. Even a broken denial helper cannot contact
// a socket/DNS/process while this positive blocker control runs.
const assert = require('node:assert/strict');
let underlayCalls = 0;
const underlay = () => { underlayCalls++; throw new Error('Synthetic underlay reached; no actual I/O'); };
const cases = [];
const add = (name, target, key) => {
  target[key] = underlay;
  cases.push({ name, call: () => target[key]('https://fixture.invalid/') });
};
for (const [name, fields] of Object.entries({
  'node:http': ['request', 'get', 'createServer'], 'node:https': ['request', 'get', 'createServer'],
  'node:http2': ['connect', 'createServer', 'createSecureServer'],
  'node:net': ['connect', 'createConnection', 'createServer'], 'node:tls': ['connect', 'createServer'],
  'node:dgram': ['createSocket'], 'node:child_process': ['spawn', 'spawnSync', 'exec', 'execSync',
    'execFile', 'execFileSync', 'fork'], 'node:worker_threads': ['Worker'],
})) {
  const api = require(name);
  for (const field of fields) add(`${name}.${field}`, api, field);
}
for (const [name, target, fields] of [
  ['Socket', require('node:net').Socket.prototype, ['connect']],
  ['Server', require('node:net').Server.prototype, ['listen']],
  ['ChildProcess', require('node:child_process').ChildProcess.prototype, ['spawn']],
  ['dgram.Socket', require('node:dgram').Socket.prototype, ['bind', 'connect', 'send']],
  ['dns', require('node:dns'), ['lookup', 'lookupService', 'resolve', 'reverse']],
  ['dns.promises', require('node:dns/promises'), ['lookup', 'lookupService', 'resolve', 'reverse']],
  ['Resolver', require('node:dns').Resolver.prototype, ['resolve', 'reverse']],
  ['PromiseResolver', require('node:dns/promises').Resolver.prototype, ['resolve', 'reverse']],
  ['global', globalThis, ['fetch', 'WebSocket']],
]) {
  for (const field of fields) add(`${name}.${field}`, target, field);
}
const attempts = require('./deny.cjs');
for (const item of cases) assert.throws(item.call, /OFFLINE FIXTURE denied/, item.name);
assert.equal(underlayCalls, 0);
assert.equal(attempts.length, cases.length);
console.log(JSON.stringify({ syntheticOnly: true, mode: 'deny-control', passed: true,
  blocked: cases.length, underlayCalls, actualNode: process.versions.node, realIo: false,
  coverage: cases.map(item => item.name) }));
