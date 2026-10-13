#!/usr/bin/env node
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dispatchCli } from './cli-dispatch.mjs';

try {
  await dispatchCli(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
