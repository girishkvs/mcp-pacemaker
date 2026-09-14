import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import {
  configurationText, consumerConfiguration, consumerEnvironment, readConsumerConfiguration,
} from '../tools/npm-consumer/environment.mjs';
import { ownedDirectory, removeOwnedDirectory } from '../tools/compatibility/fixtures.mjs';
import { CompatibilityBridge } from './compat/bridge.mjs';

const config = {
  registry: 'https://registry.npmjs.org/', cache: 'cache-directory', offline: true,
  '@clack:registry': 'https://approved-scoped.example.test/npm/',
  'strict-ssl': true, 'min-release-age': 7, 'ignore-scripts': false,
};

function credentialUrl(base) {
  const url = new URL(base);
  url.username = 'user';
  url.password = 'password';
  return url.href;
}

test('consumer npm policy retains scoped registries and release-age controls without credentials', () => {
  const selected = consumerConfiguration({ ...config, '//registry.npmjs.org/:_authToken': 'synthetic-only' },
    ['@clack:registry']);
  assert.deepEqual(selected, config);
  assert.match(configurationText(selected), /@clack:registry="https:\/\/approved-scoped\.example\.test\/npm\/"/);
  assert.match(configurationText(selected), /min-release-age=7/);
  assert.doesNotMatch(configurationText(selected), /synthetic-only|_authToken/);
  const missing = { ...config };
  delete missing['@clack:registry'];
  assert.throws(() => consumerConfiguration(missing, ['@clack:registry']), /no fallback selected/);
  assert.throws(() => consumerConfiguration({ ...config, registry: credentialUrl('https://example.test/') }));
  assert.throws(() => consumerConfiguration({ ...config, 'strict-ssl': false }), /TLS verification/);
});

test('configuration discovery reads effective settings without executing caller preloads', async () => {
  const calls = [];
  const result = await readConsumerConfiguration({
    PATH: process.env.PATH, NODE_OPTIONS: '--import=untrusted-preload.mjs',
    NODE_PATH: '/untrusted/modules', NPM_TOKEN: 'synthetic-only',
    npm_config_userconfig: '/owned/settings.npmrc',
  }, async (args, options) => {
    calls.push({ args, env: options.env });
    return args.includes('--json') ? JSON.stringify(config)
      : '@clack:registry = "https://approved-scoped.example.test/npm/"\n';
  });
  assert.deepEqual(result, config);
  for (const { env } of calls) {
    assert.equal(env.NODE_OPTIONS, undefined);
    assert.equal(env.NODE_PATH, undefined);
    assert.equal(env.NPM_TOKEN, undefined);
    assert.equal(env.npm_config_userconfig, '/owned/settings.npmrc');
  }
});

test('consumer Node subprocesses cannot execute an inherited NODE_OPTIONS preload', () => {
  const owned = ownedDirectory();
  try {
    const marker = join(owned.dir, 'preload-executed');
    const preload = join(owned.dir, 'preload.mjs');
    writeFileSync(preload,
      `import {writeFileSync} from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'executed');`);
    const injected = { ...consumerEnvironment(), NODE_OPTIONS: `--import=${pathToFileURL(preload).href}` };
    execFileSync(process.execPath, ['-e', ''], { env: consumerEnvironment(injected) });
    assert.equal(existsSync(marker), false);
    execFileSync(process.execPath, ['-e', ''], { env: injected });
    assert.equal(existsSync(marker), true, 'The control must execute the same preload without the filter');
  } finally {
    removeOwnedDirectory(owned);
  }
});

test('proxy routing is preserved or explicitly refused, never silently changed to direct access', () => {
  const original = {
    HTTPS_PROXY: 'http://policy-proxy.example.test:8080/', NO_PROXY: 'localhost,127.0.0.1',
    http_proxy: 'http://policy-proxy.example.test:8080/', NODE_USE_ENV_PROXY: '1',
    PROXY: 'http://generic-proxy.example.test:8080/',
  };
  assert.deepEqual(consumerEnvironment(original), original);
  assert.throws(() => consumerEnvironment({ HTTPS_PROXY: credentialUrl('http://proxy.example.test/') }),
    /no direct-connection fallback/);
  assert.throws(() => consumerEnvironment({ HTTPS_PROXY: 'https://synthetic-private-value@[' }), (error) => {
    assert.equal(error.input, undefined);
    assert.doesNotMatch(String(error.stack), /synthetic-private-value/);
    return true;
  });
});

test('a scope containing auth is a registry mapping, not a credential variable', async () => {
  const source = {
    'npm_config_@auth0:registry': 'https://approved-auth.example.test/npm/',
    npm_config_authToken: 'synthetic-only',
    HTTPS_PROXY: 'http://policy-proxy.example.test:8080/',
  };
  const mapped = { ...config, '@auth0:registry': source['npm_config_@auth0:registry'] };
  const result = await readConsumerConfiguration(source, async (args, { env }) => {
    assert.equal(env['npm_config_@auth0:registry'], source['npm_config_@auth0:registry']);
    assert.equal(env.npm_config_authToken, undefined);
    assert.equal(env.HTTPS_PROXY, source.HTTPS_PROXY);
    if (args.includes('--json')) return JSON.stringify(mapped);
    assert.ok(args.includes('--json=false'));
    return '@auth0:registry = "https://approved-auth.example.test/npm/"';
  });
  assert.equal(result['@auth0:registry'], source['npm_config_@auth0:registry']);
});

test('scoped environment mappings follow npm case normalization', async () => {
  const source = { 'NPM_CONFIG_@CLACK:REGISTRY': config['@clack:registry'] };
  const result = await readConsumerConfiguration(source, async (args, { env }) => {
    assert.equal(env['NPM_CONFIG_@CLACK:REGISTRY'], config['@clack:registry']);
    return args.includes('--json') ? JSON.stringify(config)
      : '@clack:registry = "https://approved-scoped.example.test/npm/"';
  });
  assert.equal(result['@clack:registry'], config['@clack:registry']);
});

test('the real compatibility fixture uses the supplied sanitized environment for every child', () => {
  const original = { token: process.env.NPM_TOKEN, config: process.env.npm_config_userconfig, options: process.env.NODE_OPTIONS };
  let bridge;
  try {
    process.env.NPM_TOKEN = 'synthetic-inherited-token';
    process.env.npm_config_userconfig = '/not-the-consumer.npmrc';
    process.env.NODE_OPTIONS = '--import=must-not-execute.mjs';
    const env = consumerEnvironment();
    env.npm_config_userconfig = '/owned/consumer.npmrc';
    bridge = new CompatibilityBridge({ env });
    assert.equal(bridge.env.NPM_TOKEN, undefined);
    assert.equal(bridge.env.NODE_OPTIONS, undefined);
    assert.equal(bridge.env.npm_config_userconfig, '/owned/consumer.npmrc');
    assert.notEqual(bridge.env.HOME, process.env.HOME);
  } finally {
    for (const [key, value] of [
      ['NPM_TOKEN', original.token], ['npm_config_userconfig', original.config], ['NODE_OPTIONS', original.options],
    ]) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    if (bridge) removeOwnedDirectory(bridge.owned);
  }
});
