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

The third run passed syntax, style and audit, fetched the exact tarball and lock,
and reached the formula install method. Homebrew's protected `Pathname#write`
refused to overwrite the existing staged `package.json`; the candidate now uses
the documented `atomic_write` API. That run also exposed a stock runner command
link from `/opt/homebrew/bin/openssl` to the old `openssl@1.1` keg while installing
the Node dependency's OpenSSL 3. A proposed next bundle temporarily removes only
that verified alias and restores its original target during cleanup. It does
not remove an OpenSSL package/library, use overwrite flags, or trust other taps.
Those changes require approval of the next run; none has been executed yet.

The fourth approved run installed the formula successfully and restored the
stock OpenSSL link during cleanup. The first CLI invocation then failed with
ENOENT. Inspection of Homebrew's helper source established that
`env_script_all_files` wraps files already in its receiver directory; it does
not create wrappers from the argument directory. The empty public `bin` therefore
produced no commands. The local formula now writes both explicit wrappers to
the npm-created `libexec/bin` entrypoints. The next candidate also records the
installed layout and verifies the dependency graph before invoking the CLI.
No fifth run has been approved or started.
