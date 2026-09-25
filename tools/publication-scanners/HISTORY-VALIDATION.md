# Windows history scanner correction

## Recovered failure

Pinned TruffleHog 3.97.1 reported:

```text
Error waiting for git command to complete.
exec: canceling Cmd: TerminateProcess: Access is denied.
```

The second line's SHA-256 is
`5a34aa0bb07eab659d98abe009f1e6ecee13e0d379cc510317cc97a63115b822`.
This matches the original recorded error hash exactly. One reproducing captured-stderr
SHA-256 was `c4f245c86f0f124e543c1c2ccc0b8df2a247af277edc69dc643e9db0acdaeb0a`.
No raw finding, private path, policy rule or credential is retained here.

The v3.97.1 native Git parser closes `diffChan` in `FromReader`
(`pkg/gitparse/gitparse.go:373`) before its caller waits for the Git process
(`pkg/gitparse/gitparse.go:335-345`). The source manager cancels its source context when
the source run returns (`pkg/sources/source_manager.go`). Go's command-context watcher can
then try to terminate the already-exited but still-unreaped Windows process. A failed
`TerminateProcess` is wrapped as `exec: canceling Cmd`, matching the recovered error.
A completion message and finding exit 183 therefore cannot override the error.

## Cheap controls

All controls used disposable two-commit repositories, no online verification or updates,
and serial executions. Failed observations were retained, not retried until green.

| Fixed control | Observed result |
|---|---|
| `git -C <bare> log`, `safe.bareRepository=explicit` | Exit 128: bare repository denied |
| `git --git-dir=<bare> log`, same safeguard | Exit 0 |
| `git -C <normal-clone> log`, same safeguard | Exit 0; same history-output hash |
| Native TruffleHog Git, default scheduler, three runs | Two matching cancellation failures |
| Native TruffleHog Git, `GOMAXPROCS=1`, three runs | One matching cancellation failure |
| Explicit bare and normal-clone native TruffleHog controls, three runs each | All completed in that sample; neither changes the upstream close-before-Wait sequence |

This distinguishes the actual cancellation failure from a bare-repository policy denial.
The passing native samples are not treated as proof the race is fixed.

## Implemented correction

1. Preserve `safe.bareRepository=explicit` in the isolated environment. Address owned bare
   history using `--git-dir` or `GIT_DIR`; never disable the safeguard.
2. Keep Gitleaks's native Git scan of the owned HEAD bundle.
3. Export every Git object reachable from that exact HEAD with bounded
   `rev-list` and `cat-file --batch-check/--batch`.
4. Verify each object's type, size, complete raw body and recomputed Git object ID.
   Reject malformed, missing, changed, oversized or trailing output.
5. Run pinned TruffleHog filesystem scanning over that owned raw-object corpus. This includes
   deleted files, complete binary/archive blobs, tree filenames and commit/author metadata,
   without starting TruffleHog's native Git subprocess.
6. Hash the corpus before/after scanning, retain only safe evidence and remove the owned
   workspace. Keep errors blocking; no diagnostic suppression, waits, retries, timeout
   increases, scanner binary changes or global configuration changes.

The final tiny real-tool fixture adds a distinct synthetic credential inside a **deleted
gzip history blob**, alongside the deleted text credential. TruffleHog must detect both.
The existing clean source/history/artifact, ignored/untracked file and artifact-only archive
fixtures remain enabled through `MCP_PUBLICATION_SCANNER_FIXTURES=1`.

Limits remain explicit: HEAD ancestors only; no unreachable objects or external submodule
repositories; at most 200,000 exported objects, 256 MiB/object and 1 GiB raw history bytes.
Pattern detection is not proof that every binary/archive format is understood. Actual
candidate scans, cross-platform qualification and owner private-content review are separate.
