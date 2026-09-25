import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { guarded, inventory, readJson, requireCondition, sha256, validateBinding } from './core.mjs';

export async function scanPrivateContent({ root, policyPath, binding, source = false }) {
  return guarded('private-content-policy', async () => {
    if (!policyPath) {
      return { status: 'not-run', reason: 'no-local-private-policy', ownerReview: 'pending' };
    }
    const approvedBinding = validateBinding(binding, !source);
    const input = await readJson(policyPath);
    const policy = input.value;
    requireCondition(policy?.schemaVersion === 1 && Array.isArray(policy.literals) &&
      policy.literals.length > 0 && policy.literals.length <= 1000, 'private-policy-schema');
    const patterns = policy.literals.map(item => {
      requireCondition(typeof item.value === 'string' && item.value.length >= 3 &&
        item.value.length <= 4096 && typeof item.ignoreCase === 'boolean', 'private-policy-literal-schema');
      const text = item.ignoreCase ? item.value.toLowerCase() : item.value;
      return { text, ignoreCase: item.ignoreCase,
        utf8: Buffer.from(text, 'utf8'), utf16: Buffer.from(text, 'utf16le') };
    });
    const before = await inventory(root, { source });
    const evidence = [];
    for (const entry of before.entries) {
      const bytes = await readFile(join(root, entry.path));
      for (let index = 0; index < patterns.length; index++) {
        const pattern = patterns[index];
        const path = pattern.ignoreCase ? entry.path.toLowerCase() : entry.path;
        let found = path.includes(pattern.text);
        if (pattern.ignoreCase) {
          found ||= bytes.toString('utf8').toLowerCase().includes(pattern.text) ||
            bytes.toString('utf16le').toLowerCase().includes(pattern.text);
        } else {
          found ||= bytes.includes(pattern.utf8) || bytes.includes(pattern.utf16);
        }
        if (found) evidence.push({ fileSha256: entry.sha256, pattern: index });
      }
    }
    const after = await inventory(root, { source });
    requireCondition(before.evidence.sha256 === after.evidence.sha256, 'private-policy-input-changed');
    return {
      status: evidence.length ? 'findings' : 'passed', ownerReview: 'pending',
      binding: approvedBinding, policySha256: input.sha256, evidenceSha256: sha256(JSON.stringify(evidence)),
      matches: evidence.length, scope: { ...before.evidence,
        selection: source ? 'working-tree-excluding-git-and-node_modules' : 'all-unpacked-files' },
      limits: 'Literal filename/UTF-8/UTF-16LE byte review only; no history or archive expansion. ' +
        'Not owner private-content-review approval. Owner evidence must bind exact commit and tarball.',
    };
  });
}
