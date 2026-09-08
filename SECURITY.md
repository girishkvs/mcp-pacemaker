# Security Policy

## Supported versions

Fixes land on the latest released minor version only.

| Version | Supported |
| ------- | --------- |
| Latest released 1.x minor | yes |
| Earlier releases | no |

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
  This covers `/admin/reload`, which re-reads `servers.json` — see the note below on why that
  file is a trusted input.
- **Pooling controls are opt-in configuration writes.** The dashboard's Enable/Disable/Undo
  buttons and the equivalent CLI actions require the admin nonce. Browser writes also require
  a matching Origin when provided. Only `sharing` and `minWarm` can be changed; commands,
  environment and auth settings are not accepted. Requests are bounded to 4 KiB.
  Edits require a content revision, preserve unrelated JSON, keep a backup and replace the file
  atomically. Undo restores the previous bytes only while that revision is still current.
  These checks detect stale clients and observed editor changes; a non-cooperating external
  writer can still race the final filesystem check/rename because portable filesystem CAS
  is unavailable. Do not edit the file concurrently with an admin action.
- **Config backups and Undo contain config data.** `servers.json.bak` has the previous config
  and is protected like the source file, including its Windows DACL. Temporary files are given
  the same permissions before data is written. Bounded in-memory Undo records can include
  credential-bearing configuration; they are not returned to the browser or written elsewhere.
- **Windows timestamp changes are not permission changes by themselves.** Automatic writes
  capture native non-audit security sections, audit policy and file attributes. A changed
  timestamp is accepted only when that verified state, content and file identity still match.
  Unreadable audit policy is refused before staging; security that cannot be preserved on both
  replacement and backup files is also refused. No automatic elevation or security-policy
  changes are performed. The built-in audit-read API uses only rights assigned to the account.
- **Shared mode is not a user-security boundary.** It is opt-in for stateless tools with one
  common credential context. Only a tools capability derived from the real upstream is exposed;
  unsupported client capabilities and protocol methods fail explicitly. IDs, progress,
  cancellation and cursors are scoped to virtual sessions, but a tool implementation can still
  keep hidden process-global state. The operator must confirm that sharing that state is safe.
  Do not enable it for separate users, accounts, workspaces or conversations. Dispatched work
  is never replayed automatically, and deleting one session does not prove its tool stopped.
- **The bridge reloads `servers.json` when it changes.** A running bridge watches its config and
  applies edits without a restart, so anything that can write that file can change what the
  bridge runs, at the moment it writes — not only at the next start. The file is already a
  trusted input for the reason below; watching it widens *when* that trust is exercised. Set
  `MCP_CONFIG_WATCH=0` to require an explicit `mcp-pacemaker reload` instead.
- **Health probing makes requests you did not.** With `MCP_HEALTH_INTERVAL_MS` set, the bridge
  periodically sends an `initialize` to each HTTP server, carrying that server's configured
  credential. It is off by default for exactly that reason. stdio servers are never probed.
- **Tokens live in memory only.** Credentials obtained from an auth command are cached in the
  process and never written to disk. The dashboard shows time-to-expiry, never the value.
- **Session initialization metadata is written to disk.** To re-establish a session after a
  restart, `~/.mcp-pacemaker/sessions.json` records session ids and the `initialize` parameters
  the client sent (protocol version, declared capabilities, client name and any extra fields).
  Business requests and tool results are not recorded there. Treat it as sensitive because
  client-defined initialization fields can contain additional data. Delete it to drop all resumable sessions, or
  run with `MCP_RESUME=0` to never write it. Records past `MCP_RESUME_TTL_MS` (24h by default)
  are refused and pruned, so the file does not accumulate indefinitely.
- **The log records activity, not content.** `~/.mcp-pacemaker/bridge.log` holds the same lines
  the dashboard shows: server names, session ids, pids, timings and errors. It does not contain
  credentials, request bodies or tool results, though a server's own stderr is included and an
  error message a server chooses to print could carry anything. It is rolled at
  `MCP_LOG_MAX_BYTES`; set that to `0` to disable the file entirely.
- **Auth commands run in a shell.** `servers.json` is a trusted input: anything in an `auth`
  command executes with your privileges. Do not load a `servers.json` you did not write.
- **Client configs are rewritten in place.** `install` backs each file up to `<file>.bak`
  before writing, and `plan` shows the exact change first.

## Out of scope

- Vulnerabilities in the MCP servers the bridge launches or proxies to.
- Consequences of deliberately binding to a non-loopback address.
- Anything requiring an attacker to already have write access to your `servers.json` or your
  host's MCP configuration.
