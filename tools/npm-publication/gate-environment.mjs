import assert from 'node:assert/strict';
import { isAbsolute, posix } from 'node:path';

export function temporaryEnvironment(root, platform = process.platform) {
  assert.ok(typeof root === 'string' &&
    isAbsolute(root) &&
    !/[\0\r\n]/.test(root), 'Publication scratch root must be an absolute path');
  if (platform !== 'win32') {
    const socket = posix.join(root, 'pacemaker-compat-XXXXXX', 'service-65535.sock');
    assert.ok(Buffer.byteLength(socket) <= 103,
      'Publication scratch root is too long for T32; choose a shorter temporary root before running');
  }
  return { TMPDIR: root, TMP: root, TEMP: root };
}

export function scannerEnvironment(env) {
  const result = {};
  for (const scanner of ['GITLEAKS', 'TRUFFLEHOG']) {
    const binary = `MCP_${scanner}_BIN`;
    const hash = `MCP_${scanner}_SHA256`;
    if (env[binary] ||
        env[hash]) {
      assert.ok(env[binary] &&
        isAbsolute(env[binary]), `${binary} must be an absolute reviewed binary path`);
      assert.match(env[hash] ?? '', /^[a-f0-9]{64}$/, `${hash} must pin the actual scanner binary`);
      result[binary] = env[binary];
      result[hash] = env[hash];
    }
  }
  if (env.MCP_GITLEAKS_BIN) {
    assert.ok(env.MCP_GITLEAKS_CONFIG, 'MCP_GITLEAKS_CONFIG is required with the reviewed Gitleaks binary');
  }
  if (env.MCP_GITLEAKS_CONFIG) {
    assert.ok(isAbsolute(env.MCP_GITLEAKS_CONFIG), 'MCP_GITLEAKS_CONFIG must be an absolute reviewed config path');
    result.MCP_GITLEAKS_CONFIG = env.MCP_GITLEAKS_CONFIG;
  }
  for (const name of ['MCP_GO_BIN', 'MCP_GIT_BIN']) {
    if (env[name]) {
      assert.ok(isAbsolute(env[name]), `${name} must be an absolute tool path`);
      result[name] = env[name];
    }
  }
  return result;
}
