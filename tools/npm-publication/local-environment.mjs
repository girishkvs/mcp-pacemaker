import assert from 'node:assert/strict';

export function windowsSystemEnvironment(parent) {
  const environment = {};
  for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'USERDOMAIN', 'USERNAME']) {
    if (parent[key]) environment[key] = parent[key];
  }
  return environment;
}

export function bindGuestIdentity(environment, token) {
  assert.equal(typeof token.name, 'string', 'Guest token account is required');
  assert.ok(typeof token.sid === 'string' &&
    token.sid.startsWith('S-1-'), 'Guest token SID is required');
  const separator = token.name.indexOf('\\');
  assert.ok(separator > 0 &&
    separator < token.name.length - 1, 'Guest token account must be domain-qualified');
  const values = { USERDOMAIN: token.name.slice(0, separator), USERNAME: token.name.slice(separator + 1) };
  for (const [key, value] of Object.entries(values)) {
    if (environment[key]) {
      assert.equal(environment[key].toLowerCase(), value.toLowerCase(), `Guest ${key} differs from its token`);
    }
    environment[key] = value;
  }
  return { name: token.name, sid: token.sid };
}
