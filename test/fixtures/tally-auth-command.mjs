#!/usr/bin/env node
// Test double for an auth command (e.g. `az account get-access-token`).
//
// Appends one byte to <tally> per invocation so a test can count how many times it ran, then
// prints <output> — or nothing when <output> is "-", which reproduces a real az failure mode:
// exiting 0 while printing no token.
//
// When <output> is "jwt:<seconds>" it prints an unsigned JWT whose `exp` claim is <seconds>
// from now, so a test can exercise how long the bridge is willing to cache a credential.
// Negative values produce an already-expired token, which is what a provider hands back when
// it serves a token from its own cache that is nearly spent.
import { appendFileSync } from 'node:fs';

const [, , tally, output] = process.argv;
appendFileSync(tally, 'x');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (secondsFromNow) =>
  `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ exp: Math.floor(Date.now() / 1000) + secondsFromNow })}.sig`;

if (!output || output === '-') process.exit(0);
const m = /^jwt:(-?\d+)$/.exec(output);
process.stdout.write(m ? jwt(Number(m[1])) : output);
