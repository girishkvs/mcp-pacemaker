# Isolated macOS Homebrew SSH canary

This adapts the existing private Windows regression transport without changing
that session, branch, job, environment, credentials or test bundle.

The transport remains one key-authenticated SSH connection through Microsoft
Dev Tunnels: fixed commands, pinned host key, no password login, no general shell,
no forwarding, one hash-bound upload/execute and a 30-minute absolute deadline.
The host accepts only this repository's `homebrew-macos-validation-20261008`
branch on a first-attempt `macos-15` ARM64 GitHub-hosted job.

The bundle validates the exact local Homebrew formula: Ruby syntax, style/audit,
installation, retained shrinkwrap and all 48 production versions, isolated
`brew test`, a real synthetic MCP initialize/tool-call/delete round trip, no
automatic per-user setup, package removal and local tap cleanup.

It does not establish a physical reboot/login cycle, application or Node upgrade
survival, Intel support, or the full launchd teardown contract. Those remain
separately reported lifecycle gaps even if this canary passes.

GitHub authentication is completed by the user. The controller holds credentials
in memory, does not persist a personal gh login, creates only the scoped temporary
environment/bootstrap secret and relay, and removes them after the one job ends.
The public commit contains only transport/workflow source with no private keys
or result archive. The test bundle and results travel privately over SSH.

Local testing reuses the already installed transport dependencies via `NODE_PATH`;
it performs no new dependency acquisition on the work machine. The hosted
runner uses the source lock as an ordinary public CI dependency install.
