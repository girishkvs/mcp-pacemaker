import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import postcss from 'postcss';
import tailwindcss from '@tailwindcss/postcss';
import { BundleInventory } from '../../tools/third-party-notices/inventory.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const source = join(root, 'src', 'index.css');
const policyFile = join(root, '..', 'tools', 'third-party-notices', 'reviewed-licenses.json');

async function compile() {
  return postcss([tailwindcss({ base: root, optimize: false })])
    .process(fs.readFileSync(source, 'utf8'), { from: source });
}

test('Tailwind 4 retains themed dashboard utilities and attributes its generated preflight', async () => {
  const result = await compile();
  for (const selector of ['.bg-panel', '.text-fg', '.border-line', '.rounded-xl', '.outline-hidden']) {
    let found = false;
    result.root.walkRules(selector, () => { found = true; });
    assert.equal(found, true, `Missing dashboard utility: ${selector}`);
  }
  for (const color of ['#171a23', '#e6e8ee', '#2a2f3a']) {
    assert.ok(result.css.includes(color), `Missing dashboard theme color: ${color}`);
  }
  const inventory = new BundleInventory(root, JSON.parse(fs.readFileSync(policyFile)));
  inventory.css(result.root);
  inventory.tailwindCss(result.root);
  assert.equal(inventory.generated.get('node_modules/tailwindcss/preflight.css')?.package,
    'tailwindcss@4.3.3');
  assert.ok(inventory.packageRecords().some(pkg => pkg.name === 'tailwindcss' &&
    pkg.version === '4.3.3' && pkg.licenses.some(license => license.file === 'LICENSE')));
});

test('Tailwind attribution rejects output missing a preflight selector', async () => {
  const result = await compile();
  const preflight = postcss.parse(fs.readFileSync(join(root, 'node_modules', 'tailwindcss', 'preflight.css'), 'utf8'));
  const expected = preflight.nodes.find(node => node.type === 'rule').selector.replace(/\s+/g, ' ');
  let removed = false;
  result.root.walkRules(rule => {
    if (rule.selector.replace(/\s+/g, ' ') === expected) {
      rule.remove();
      removed = true;
    }
  });
  assert.equal(removed, true, 'The negative control must remove real generated preflight');
  const inventory = new BundleInventory(root, JSON.parse(fs.readFileSync(policyFile)));
  assert.throws(() => inventory.tailwindCss(result.root), /preflight output changed/);
});

test('Tailwind attribution rejects an unreviewed license digest', async () => {
  const result = await compile();
  const policy = JSON.parse(fs.readFileSync(policyFile));
  policy['tailwindcss@4.3.3'] = { license: 'MIT', files: { LICENSE: '0'.repeat(64) } };
  const inventory = new BundleInventory(root, policy);
  assert.throws(() => inventory.tailwindCss(result.root), /Changed license\/NOTICE text/);
});

test('Tailwind selector normalization cannot hide a changed attribute value', async () => {
  const result = await compile();
  let changed = false;
  result.root.walkRules(rule => {
    if (rule.selector.includes('[type="button"]')) {
      rule.selector = rule.selector.replaceAll('[type="button"]', '[type="checkbox"]');
      changed = true;
    }
  });
  assert.equal(changed, true);
  const inventory = new BundleInventory(root, JSON.parse(fs.readFileSync(policyFile)));
  assert.throws(() => inventory.tailwindCss(result.root), /preflight output changed/);
});

test('Tailwind selector normalization preserves mixed quotes and escapes', () => {
  const inventory = new BundleInventory(root, JSON.parse(fs.readFileSync(policyFile)));
  for (const selector of [`[data-label="can't"]`, String.raw`[data-label='can\'t']`]) {
    assert.equal(inventory.selectorKey(selector), selector);
  }
});
