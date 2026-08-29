#!/usr/bin/env node
// Fails the way a misconfigured server does: writes a diagnostic to stderr and exits non-zero
// immediately, rather than failing to spawn at all. A spawn failure surfaces via child 'error';
// this path only surfaces if the bridge records the exit and its stderr.
process.stderr.write("Error: Cannot find module 'C:\\wrong\\path\\index.js'\n");
process.exit(1);
