# Isolated macOS Homebrew SSH canary

This adapts the existing private Windows regression transport without changing
that session, branch, job, environment, credentials or test bundle.

The transport remains one key-authenticated SSH connection through Microsoft
Dev Tunnels: fixed commands, pinned host key, no password login, no general shell,
no forwarding, one hash-bound upload/execute and a 30-minute absolute deadline.
The host accepts only this repository's `homebrew-macos-validation-20261008`
branch on a first-attempt `macos-15` ARM64 GitHub-hosted job.

The bundle stages the formula with LF line endings and public source permissions
(`0644`) inside the temporary tap; private SSH extraction stays `0600`.
It validates the exact local Homebrew formula: Ruby syntax, style/audit,
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

The first macOS run reached Homebrew 6.0.22 on macOS 15.7.9 ARM64 through the
verified SSH session. Ruby syntax passed, but Homebrew style found private
extraction permissions, CRLF and formula-helper/hash-alignment issues before
installation began. Results and cleanup receipts are retained in the first run
directory. The local fixes need a separately approved follow-up job; that first
run is not installation or lifecycle evidence.

The second run passed Ruby syntax and Homebrew style. Audit then found one
redundant `version "2.0.2"` stanza, since the immutable tarball URL already
identifies that version. The local formula now lets Homebrew infer it from
that URL. Both failed-run results and verified cleanup receipts are preserved;
installation and functional checks have not yet run.

The next candidate collects style and audit failures, then continues independent
installation checks on the same qualified input. Every nonzero check still fails
the overall result. Syntax, installation and runtime failures remain fail-fast;
this does not disable an audit or convert its failure into success.
