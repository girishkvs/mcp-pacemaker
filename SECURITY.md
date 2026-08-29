# Security Policy

## Supported versions

This project is pre-1.0. Fixes land on the latest released minor version only.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/girishkvs/mcp-pacemaker/security/advisories/new).
Do not open a public issue for a vulnerability.

Include the version, your platform, what an attacker can achieve, and steps to reproduce.
You can expect an acknowledgement within 7 days and an assessment within 30.

## Threat model

The bridge is a local service holding long-lived credentials for the MCP servers it manages,
so a few properties matter more than usual:

- **It binds to `127.0.0.1` by default.** Passing `--host 0.0.0.0` exposes every configured
  server, and the credentials injected on their behalf, to anything that can reach the port.
  Do not do this on an untrusted network.
- **There is no user authentication on the proxy path.** Any local process that can open the
  port can use the bridged servers. Treat access to the port as equivalent to access to every
  credential the bridge holds.
- **Administrative endpoints require a nonce.** `/admin/*` is guarded by a random nonce written
  to `~/.mcp-pacemaker/admin.nonce` on startup, readable only by the user running the bridge.
- **Tokens live in memory only.** Credentials obtained from an auth command are cached in the
  process and never written to disk. The dashboard shows time-to-expiry, never the value.
- **Session state is written to disk, credentials are not.** To re-establish a session after a
  restart, `~/.mcp-pacemaker/sessions.json` records session ids and the `initialize` parameters
  the client sent (protocol version, declared capabilities, client name). It contains no
  credentials and no request or response content. Delete it to drop all resumable sessions, or
  run with `MCP_RESUME=0` to never write it.
- **Auth commands run in a shell.** `servers.json` is a trusted input: anything in an `auth`
  command executes with your privileges. Do not load a `servers.json` you did not write.
- **Client configs are rewritten in place.** `install` backs each file up to `<file>.bak`
  before writing, and `plan` shows the exact change first.

## Out of scope

- Vulnerabilities in the MCP servers the bridge launches or proxies to.
- Consequences of deliberately binding to a non-loopback address.
- Anything requiring an attacker to already have write access to your `servers.json` or your
  host's MCP configuration.
