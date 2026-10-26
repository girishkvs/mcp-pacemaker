# How mcp-pacemaker compares

Checked on October 16, 2026, from each project's documentation and source. We did not run the
other tools. Corrections are welcome: open an issue with a link.

| Project | Release checked |
|---|---|
| [Supergateway](https://github.com/supercorp-ai/supergateway) | v4.2.0 (2026-10-15) |
| [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) | v0.13.0 (2026-10-10) |
| [MCP Hub](https://github.com/ravitemer/mcp-hub) | v4.2.1 (2025-08-22, no later commits) |
| [ToolHive](https://github.com/stacklok/toolhive) | v0.54.0 (2026-10-14), desktop app v0.40.2 |

✅ means documented or implemented. ❌ means we did not find it in the README, docs, CLI options
or source; it does not mean the feature is impossible. Text in a cell describes partial support.
ToolHive's desktop app counts as part of ToolHive.

| | Supergateway | mcp-proxy | MCP Hub | ToolHive | **mcp-pacemaker** |
|---|---|---|---|---|---|
| Serves stdio servers over Streamable HTTP | ✅ | ✅ | ❌ | ✅ | ✅ |
| Serves stdio servers over SSE (legacy) | ✅ | ✅ | ✅ | ✅ (deprecated) | ✅ |
| What you install | npm, binary or Docker | PyPI or Docker | npm or Nix | Go binary + Docker or Podman | npm; the bridge has **zero** dependencies |
| Restarts crashed processes automatically | new child per connection | ❌ | manual restart (API) | ✅ | ✅ bridge and warm pools |
| Starts at OS logon | ❌ | ❌ | ❌ | desktop app only | ✅ Windows, macOS, Linux |
| Starts again after unlock or wake | ❌ | ❌ | ❌ | ❌ | ✅ Windows |
| Auth header from your own command, auto-refreshed | ❌ | ❌ | at connect only | ❌ | ✅ |
| Sessions survive a bridge restart without re-initializing | ❌ | ❌ | ❌ | Kubernetes with Redis only | ✅ |
| Timed restart to refresh an interactive login | ❌ | ❌ | ❌ | ❌ | ✅ |
| Reuses existing client MCP config files | ✅ | stdio entries only | ✅ | ❌ | ✅ |
| Wires editors and CLIs for you | ❌ | ❌ | ❌ | ✅ | ✅ |
| Web dashboard | ❌ | ❌ | ❌ | desktop app instead | ✅ |
| Terminal dashboard | ❌ | ❌ | ❌ | ✅ (experimental) | ✅ |
| HTTP control API | health checks only | `/status` only | ✅ | ✅ | ✅ |

## Sources

### Supergateway v4.2.0

- **Transports:** stdio → SSE is the default output
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L50-L63)); stdio →
  Streamable HTTP in both directions
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L84-L130)).
- **Install:** npm, standalone executables
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L258-L294)) or Docker
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L334-L380)).
- **Crashed processes:** each SSE/WebSocket connection gets its own child and a reconnecting client
  gets a fresh one ([CHANGELOG](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/CHANGELOG.md#L83));
  when a child exits, its calls fail and the session ends
  ([source](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/src/gateways/sseSession.ts#L120-L170)).
- **Logon start, unlock, timed restart:** not in the option list
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L13-L48),
  [options](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/src/cliOptions.ts)); the only
  related option, `--sessionTimeout`, expires idle sessions.
- **Auth:** static `--header` and `--oauth2Bearer`
  ([options](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/src/cliOptions.ts#L106-L117));
  `${VAR}` in the config file is expanded once at load
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L209)).
- **Sessions:** stateful sessions are kept in memory, and an unknown session ID after a restart gets
  404 ([source](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/src/gateways/statefulSessions.ts#L211-L232)).
  Stateless mode has no session to lose
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L107-L129)).
- **Config reuse and wiring:** `--config` reads a Claude Desktop `mcpServers` file
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L179-L218)); client
  entries are written by hand
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L382-L467)).
- **Dashboards and API:** health endpoints only
  ([README](https://github.com/supercorp-ai/supergateway/blob/v4.2.0/README.md#L39-L40)).

### mcp-proxy v0.13.0

- **Transports:** `/sse` and `/mcp` server routes
  ([source](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/src/mcp_proxy/mcp_server.py#L89-L93));
  stdio → SSE server mode
  ([README](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/README.md#L98-L170)).
- **Install:** uv, pipx or Docker, Python 3.10 or newer
  ([README](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/README.md#L222-L261)).
- **Crashed processes, logon start, timed restart:** not in the option list
  ([README](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/README.md#L318-L398)). The Docker
  Compose example relies on Docker's `restart: unless-stopped`
  ([README](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/README.md#L297-L316)).
- **Auth:** static headers, `API_ACCESS_TOKEN`, OAuth2 client credentials and Basic/Digest
  ([README](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/README.md#L56-L74)). OAuth2 tokens
  refresh, but no user command produces the header.
- **Sessions:** kept in memory (`event_store=None`)
  ([source](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/src/mcp_proxy/mcp_server.py#L89-L93));
  `--stateless` avoids sessions.
- **Config reuse and wiring:** `--named-server-config` reads the stdio entries of an `mcpServers` file
  ([source](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/src/mcp_proxy/config_loader.py#L15-L70));
  client entries are written by hand
  ([README](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/README.md#L76-L96)).
- **Dashboards and API:** a read-only `/status` JSON
  ([source](https://github.com/sparfenyuk/mcp-proxy/blob/v0.13.0/src/mcp_proxy/mcp_server.py#L48-L73)).

### MCP Hub v4.2.1

- **Transports:** its single `/mcp` endpoint is SSE
  ([source](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/src/server.js#L345-L372)); Streamable HTTP
  is only used to connect to remote servers
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L19-L20)).
- **Install:** npm (one bundled file) or a Nix flake
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L136-L140)).
- **Crashed processes:** restart is manual through `POST /api/restart`
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L791)); we did not find an
  automatic restart of a local server in the source
  ([source](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/src/MCPConnection.js#L626-L631)).
- **Logon start:** not documented; the 2.2.0 notes suggest running it under systemd yourself
  ([CHANGELOG](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/CHANGELOG.md#L430-L436)).
- **Auth:** headers accept `${cmd: …}`, which runs when the server connects
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L255-L262),
  [source](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/src/MCPConnection.js#L161-L164)).
- **Sessions:** SSE sessions are kept in memory
  ([source](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/src/mcp/server.js#L473-L490)).
- **Config reuse and wiring:** existing `.vscode/mcp.json` and `mcpServers` files work directly
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L168-L253)); clients are
  pointed at the hub by hand
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L51-L60)).
- **Dashboards and API:** REST API
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L422-L800)); a web UI and TUI
  are listed as to-do items
  ([README](https://github.com/ravitemer/mcp-hub/blob/v4.2.1/README.md#L1262-L1266)).

### ToolHive v0.54.0 and desktop app v0.40.2

- **Transports:** `--proxy-mode` is Streamable HTTP by default; SSE is deprecated
  ([CLI docs](https://docs.stacklok.com/toolhive/reference/cli/thv_run)).
- **Install:** a Go binary that needs a container runtime
  ([install](https://docs.stacklok.com/toolhive/guides-cli/install#prerequisites)), or the desktop app
  ([install](https://docs.stacklok.com/toolhive/guides-ui/install)).
- **Crashed processes:** exited containers restart with backoff
  ([source](https://github.com/stacklok/toolhive/blob/v0.54.0/pkg/workloads/manager.go#L534-L640)).
- **Logon start:** the desktop app's "Start on login" setting
  ([docs](https://docs.stacklok.com/toolhive/guides-ui/install#application-settings)); the CLI has no
  autostart command.
- **Auth:** OAuth/OIDC with automatic refresh, a static bearer token read once, forwarded headers
  and token exchange
  ([CLI docs](https://docs.stacklok.com/toolhive/reference/cli/thv_run)).
- **Sessions:** with Redis session storage, clients can reconnect and resume; with local storage
  they re-initialize
  ([architecture](https://github.com/stacklok/toolhive/blob/v0.54.0/docs/arch/13-vmcp-scalability.md#L193-L210)).
- **Timed restart:** restarts are on demand only
  ([docs](https://docs.stacklok.com/toolhive/guides-cli/manage-mcp-servers#lifecycle-management)).
- **Config reuse and wiring:** `thv client setup` and `thv client register` configure 26 clients
  ([CLI docs](https://github.com/stacklok/toolhive/blob/v0.54.0/docs/cli/thv_client_register.md#L20-L46));
  import and export cover only ToolHive's own run configuration
  ([CLI docs](https://github.com/stacklok/toolhive/blob/v0.54.0/docs/cli/thv_export.md#L20-L24)).
- **Dashboards and API:** `thv tui` (experimental)
  ([CLI docs](https://github.com/stacklok/toolhive/blob/v0.54.0/docs/cli/thv_tui.md#L14-L20)) and
  `thv serve`
  ([CLI docs](https://github.com/stacklok/toolhive/blob/v0.54.0/docs/cli/thv_serve.md#L18-L36)); the
  web console is in the enterprise edition only
  ([platform](https://docs.stacklok.com/platform)).

### mcp-pacemaker

- **Transports and hosts:** see [Supported hosts](../README.md#supported-hosts).
- **Install:** the npm dependencies belong to the setup CLI and terminal dashboard; the bridge
  imports only Node.js built-ins.
- **Crashed processes:** the supervisor restarts the bridge, and warm-pool children are replaced
  with backoff. See [configuration](configuration.md).
- **Logon and unlock:** a Windows scheduled task starts at logon and on workstation unlock, which
  also covers wake from sleep; macOS uses a launchd agent and Linux a systemd user unit.
- **Auth:** `auth.type: "command"` runs your command and refreshes the token on a schedule
  ([configuration](configuration.md#serversjson)).
- **Sessions and timed restart:** session resume (`MCP_RESUME`) and scheduled recycle
  (`recycleMinutes`) in [configuration](configuration.md).
- **Config reuse and wiring:** `import --from` and `install --client`; see the
  [command reference](operations.md#command-reference).
- **Dashboards and API:** [dashboards](dashboards.md) and [HTTP API](http-api.md).
