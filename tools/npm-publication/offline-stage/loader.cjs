'use strict';
const denied = require('./deny.cjs');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { cpSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { dirname, join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { fixture } = require('./fixture.cjs');
const [rootArgument, cliArgument, mode, homeArgument] = process.argv.slice(2);
const root = resolve(rootArgument);
const home = resolve(homeArgument);
const original = resolve(dirname(cliArgument), '..');
const owned = join(home, 'npm-owned');
cpSync(original, owned, { recursive: true, dereference: false });
const cli = join(owned, 'bin/npm-cli.js');
const req = createRequire(cli);
const marker = '__stageLoaderUnpinnedExecuted';
const source = `globalThis.${marker} = true; module.exports = require('./lib/index.js');\n`;
const packageRoot = join(owned, 'node_modules/make-fetch-happen');
const packageFile = join(packageRoot, 'package.json');
const pkg = JSON.parse(readFileSync(packageFile, 'utf8'));
Object.assign(process.env, {
  ACTIONS_ID_TOKEN_REQUEST_URL: 'https://offline.invalid/oidc',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-loader-control-credential',
});
if (mode === 'loader-main') {
  writeFileSync(join(packageRoot, 'unpinned.cjs'), source);
  pkg.main = 'unpinned.cjs';
  writeFileSync(packageFile, JSON.stringify(pkg));
} else if (mode === 'loader-exports') {
  writeFileSync(join(packageRoot, 'unpinned.cjs'), source);
  pkg.exports = { '.': './unpinned.cjs' };
  writeFileSync(packageFile, JSON.stringify(pkg));
} else if (mode === 'loader-delegate') {
  const target = join(owned, 'node_modules/libnpmpublish/lib/index.js');
  writeFileSync(target, `globalThis.${marker} = true;\n${readFileSync(target, 'utf8')}`);
} else if (mode === 'loader-shadow') {
  const target = join(owned, 'node_modules/@sigstore/sign/node_modules/make-fetch-happen');
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, 'package.json'), '{"name":"make-fetch-happen","main":"index.js"}');
  writeFileSync(join(target, 'index.js'), `globalThis.${marker} = true; module.exports = () => {};\n`);
} else {
  const requests = {
    'loader-cache-transport': 'make-fetch-happen',
    'loader-cache-registry': 'npm-registry-fetch',
    'loader-cache-low': 'minipass-fetch',
    'loader-cache-signing': 'sigstore',
    'loader-cache-provider': '@sigstore/sign',
    'loader-cache-hidden': 'make-fetch-happen',
  };
  assert.ok(Object.hasOwn(requests, mode));
  const path = req.resolve(requests[mode]);
  Object.defineProperty(req.cache, path, {
    configurable: true, enumerable: mode !== 'loader-cache-hidden',
    value: { id: path, filename: path, loaded: true,
      get exports() { globalThis[marker] = true; return () => {}; } },
  });
}
(async () => {
  const { installStageCapture } = await import(pathToFileURL(join(root, 'tools/npm-publication/stage-sdk.mjs')));
  const directory = join(home, 'capture');
  mkdirSync(directory);
  assert.throws(() => installStageCapture({ cli, expected: fixture('2.0.1').record, directory }),
    /loader distribution changed|empty module cache|require.resolve/);
  assert.equal(globalThis[marker], undefined, 'Alternate/cache code executed before rejection');
  assert.deepEqual(denied, []);
  console.log(JSON.stringify({ syntheticOnly: true, mode, actualNode: process.versions.node,
    passed: true, unpinnedEntryExecuted: false, deniedHostAttempts: [],
    originalVendorModified: false, ownedVendor: owned }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
