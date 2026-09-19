'use strict';
const { syncBuiltinESMExports } = require('node:module');
const attempts = [];
const deny = name => function () {
  attempts.push(name);
  throw new Error(`OFFLINE FIXTURE denied ${name}`);
};
for (const [module, names] of Object.entries({
  'node:child_process': ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'],
  'node:http': ['request', 'get', 'createServer'],
  'node:https': ['request', 'get', 'createServer'],
  'node:http2': ['connect', 'createServer', 'createSecureServer'],
  'node:net': ['connect', 'createConnection', 'createServer'],
  'node:tls': ['connect', 'createServer'],
  'node:dgram': ['createSocket'],
})) {
  const api = require(module);
  for (const name of names) api[name] = deny(`${module}.${name}`);
}
require('node:net').Socket.prototype.connect = deny('Socket.connect');
require('node:net').Server.prototype.listen = deny('Server.listen');
require('node:child_process').ChildProcess.prototype.spawn = deny('ChildProcess.spawn');
for (const name of ['bind', 'connect', 'send']) {
  require('node:dgram').Socket.prototype[name] = deny(`dgram.Socket.${name}`);
}
for (const module of ['node:dns', 'node:dns/promises']) {
  const api = require(module);
  for (const name of Object.keys(api)) {
    if (name.startsWith('resolve') ||
        ['lookup', 'lookupService', 'reverse', 'setServers'].includes(name)) {
      api[name] = deny(`${module}.${name}`);
    }
  }
  for (const name of Object.getOwnPropertyNames(api.Resolver.prototype)) {
    if (name !== 'constructor') api.Resolver.prototype[name] = deny(`Resolver.${name}`);
  }
}
require('node:worker_threads').Worker = deny('Worker');
globalThis.fetch = deny('fetch');
globalThis.WebSocket = deny('WebSocket');
syncBuiltinESMExports();
module.exports = attempts;
