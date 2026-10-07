# Windows regression lab

This component provides one private, key-authenticated SSH session for the
repository's Windows regression-test lab. It is not an interactive desktop or
general-purpose shell.

The public workflow contains only transport and lifecycle code. The authorized
test bundle is supplied privately over SSH, must match the approved SHA-256, and
must contain a `run.ps1` entry point. Its output and result archive travel back
over the same SSH connection. No test-output artifact is uploaded to Actions.

## Session protocol

The SSH application user is `lab`; it is not a new Windows account. One fresh
client public key is authorized. The client pins the corresponding server host
key. Password login, interactive shells, arbitrary commands and forwarding
requests are not supported.

The fixed commands are `status`, `upload`, `execute`, `download` and `finish`.
Upload and execution are accepted once. A second SSH connection is not admitted
after successful authentication. A dropped session is not replayed.

The SSH listener binds to `127.0.0.1:2222`. An authenticated Microsoft Dev Tunnels
connection transports that port; it does not forward SMB or expose a public SSH
listener. Anonymous access grants are rejected.

The job accepts a bootstrap secret bound to its exact repository, ref and commit,
and an absolute deadline no more than thirty minutes away. The local controller
uses one user-authorized GitHub device token with `repo`, `workflow` and
`read:user` scopes for GitHub operations and Microsoft Dev Tunnels authentication.
That token stays in the controller process and is not supplied to the runner.
The controller is responsible for creating the narrowly scoped relay capabilities, delivering
the bootstrap secret and deleting the temporary environment and relay afterward.
The host removes its owned work directory after the private result is collected.

`session.cjs` keeps the authorization only in memory for up to ten minutes after
a cleaned-up relay setup failure. It performs no automatic retry. A retry needs
a new hash-bound approval, and is refused after a branch/job or test execution
has been attempted. Closing the local process discards that authorization.

## Local checks

Run `npm ci --ignore-scripts --omit=optional --no-audit --no-fund` and `npm test`.
The local SSH checks use only short-lived loopback connections, generated
in-memory keys and synthetic text. They do not create cloud resources or run a
product test.
