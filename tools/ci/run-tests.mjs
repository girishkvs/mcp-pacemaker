import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditEnvironment, auditEvidence } from '../npm-publication/local-audit-report.mjs';
import { readFileSync } from 'node:fs';
import { qualificationPlan, testContract } from './test-contracts.mjs';
import { ExecutionContext } from './execution-context.mjs';
import { testTotals } from '../npm-publication/local-gate.mjs';
import { ensureWindowsProcessLifetime } from '../../bin/windows-process-lifetime.mjs';
import { TestProcess } from './test-process.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const inputArgs = process.argv.slice(2);
const [name, option] = inputArgs;
try {
  if (inputArgs.length < 1 ||
      inputArgs.length > 2) throw new Error('Use CONTRACT [--check] or plan');
  if (name === 'plan' &&
      option === undefined) {
    console.log(JSON.stringify({ contracts: qualificationPlan(root), executionPerformed: false }, null, 2));
  } else {
    if (option !== undefined &&
        option !== '--check') throw new Error('Use CONTRACT [--check] or plan');
    const contract = testContract(root, name);
    if (contract.checkOnly &&
        option !== '--check') throw new Error('service-context is an observation, not a test suite; use --check');
    const context = await new ExecutionContext().require(contract);
    console.log(JSON.stringify({ contract: contract.name, ...context }));
    if (option !== '--check') {
      const version = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).version;
      const env = name === 'audit' ? auditEnvironment({ ...process.env }, version) : { ...process.env };
      await ensureWindowsProcessLifetime();
      const { stdout } = await new TestProcess().run(contract, { cwd: root, env });
      if (name === 'audit') {
        testTotals(stdout);
        auditEvidence(stdout, version, process.version);
      }
    }
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
