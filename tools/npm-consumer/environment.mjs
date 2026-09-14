import assert from 'node:assert/strict';
import { npm } from '../compatibility/fixtures.mjs';

const environmentNames = new Set([
  'path', 'pathext', 'systemroot', 'windir', 'comspec', 'systemdrive', 'os',
  'programfiles', 'programfiles(x86)', 'programw6432', 'processor_architecture',
  'number_of_processors', 'home', 'userprofile', 'appdata', 'localappdata',
  'tmp', 'temp', 'tmpdir', 'xdg_config_home', 'xdg_state_home', 'xdg_cache_home',
  'lang', 'lc_all', 'lc_ctype', 'tz', 'term', 'no_color', 'force_color', 'ci',
  'node_extra_ca_certs', 'ssl_cert_file', 'ssl_cert_dir',
  'http_proxy', 'https_proxy', 'all_proxy', 'proxy', 'no_proxy', 'node_use_env_proxy',
]);
const configurationNames = new Set([
  'registry', 'cache', 'replace-registry-host', 'offline', 'prefer-offline',
  'strict-ssl', 'ca', 'cafile', 'proxy', 'https-proxy', 'noproxy', 'local-address',
  'fetch-retries', 'fetch-retry-factor', 'fetch-retry-mintimeout',
  'fetch-retry-maxtimeout', 'fetch-timeout', 'ignore-scripts',
  'min-release-age', 'min-release-age-exclude', 'allow-scripts', 'strict-dep-builds',
]);

function policyUrl(value) {
  try { return new URL(value); }
  catch (error) {
    if (error.code !== 'ERR_INVALID_URL') throw error;
    throw new Error('Invalid registry/proxy policy URL; no fallback selected');
  }
}

export function consumerEnvironment(source = process.env) {
  const selected = Object.fromEntries(Object.entries(source)
    .filter(([key]) => environmentNames.has(key.toLowerCase())));
  for (const [key, value] of Object.entries(selected)) {
    if (!['http_proxy', 'https_proxy', 'all_proxy', 'proxy'].includes(key.toLowerCase()) ||
        value === '') continue;
    const url = policyUrl(value);
    assert.ok(['http:', 'https:'].includes(url.protocol) &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash, 'Unsupported or credential-bearing proxy environment; no direct-connection fallback selected');
  }
  return selected;
}

function registryKey(key) {
  return key.startsWith('@') &&
    key.endsWith(':registry') &&
    /^@[a-z0-9][a-z0-9._-]*:registry$/.test(key);
}

export function consumerConfiguration(config, listedScopes = []) {
  assert.ok(config &&
    typeof config === 'object' &&
    !Array.isArray(config), 'Invalid effective npm configuration');
  for (const key of listedScopes) {
    assert.ok(Object.hasOwn(config, key), 'A scoped registry cannot be read without private credentials; no fallback selected');
  }
  const selected = {};
  for (const [key, value] of Object.entries(config)) {
    if (!configurationNames.has(key) &&
        !registryKey(key)) continue;
    if (value === null) continue;
    if (key === 'registry' ||
        registryKey(key) ||
        key === 'proxy' ||
        key === 'https-proxy') {
      assert.equal(typeof value, 'string', 'Invalid effective registry or proxy');
      const url = policyUrl(value);
      assert.ok(['http:', 'https:'].includes(url.protocol) &&
        !url.username &&
        !url.password &&
        !url.hash &&
        !url.search, 'Registry/proxy credentials and ambiguous URLs are not supported; no fallback selected');
    }
    assert.ok(['string', 'boolean', 'number'].includes(typeof value) ||
      (Array.isArray(value) && value.every((item) => typeof item === 'string')),
    'Unsupported effective npm policy value');
    selected[key] = value;
  }
  assert.equal(typeof selected.registry, 'string', 'Missing effective default registry; no fallback selected');
  assert.equal(typeof selected.cache, 'string', 'Missing effective npm cache');
  assert.equal(typeof selected.offline, 'boolean', 'Missing effective npm offline policy');
  assert.notEqual(selected['strict-ssl'], false, 'Consumer validation cannot disable TLS verification');
  return selected;
}

export function configurationText(config) {
  return Object.entries(config).flatMap(([key, value]) => Array.isArray(value)
    ? value.map((item) => `${key}[]=${JSON.stringify(item)}`)
    : [`${key}=${JSON.stringify(value)}`]).join('\n') + '\n';
}

export async function readConsumerConfiguration(source = process.env, execute = npm) {
  const probe = consumerEnvironment(source);
  // Configuration discovery reads the caller's settings, but cannot preload caller code.
  // No discovery output or credential-bearing config is copied to consumer subprocesses.
  for (const [key, value] of Object.entries(source)) {
    if (!key.toLowerCase().startsWith('npm_config_')) continue;
    const option = key.slice('npm_config_'.length).toLowerCase();
    const ordinary = option.toLowerCase().replaceAll('_', '-');
    if (registryKey(option) ||
        configurationNames.has(ordinary) ||
        ['userconfig', 'globalconfig', 'prefix'].includes(ordinary)) probe[key] = value;
  }
  let config;
  let listing;
  try {
    config = JSON.parse(await execute(['config', 'list', '--json'], { env: probe }));
    listing = await execute(['config', 'list', '--long', '--json=false'], { env: probe });
  } catch {
    throw new Error('Cannot read effective npm policy safely; no registry fallback selected');
  }
  const scopes = listing.split(/\r?\n/).map((line) => line.split('=')[0].trim()).filter(registryKey);
  return consumerConfiguration(config, scopes);
}
