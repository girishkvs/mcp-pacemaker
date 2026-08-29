#!/usr/bin/env node
// Test double for an auth command (e.g. `az account get-access-token`).
//
// Appends one byte to <tally> per invocation so a test can count how many times it ran, then
// prints <output> — or nothing when <output> is "-", which reproduces a real az failure mode:
// exiting 0 while printing no token.
import { appendFileSync } from 'node:fs';

const [, , tally, output] = process.argv;
appendFileSync(tally, 'x');
if (output && output !== '-') process.stdout.write(output);
