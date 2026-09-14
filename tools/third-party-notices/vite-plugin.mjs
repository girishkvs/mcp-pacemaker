import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BundleInventory, MANIFEST_FILE, NOTICE_FILE, artifactRecords, jsonText,
  readText, renderNotices, sha256,
} from './inventory.mjs';
import { runtimeNotices } from './runtime.mjs';

const POLICY = fileURLToPath(new URL('./reviewed-licenses.json', import.meta.url));

export function bundledNotices() {
  let inventory;
  let config;
  let notices;
  const tailwindRoots = new WeakSet();
  const cssPlugin = {
    postcssPlugin: 'mcp-bundled-css-notices',
    Once(root) {
      root.walkAtRules('tailwind', (rule) => {
        if (rule.params === 'base') tailwindRoots.add(root);
      });
    },
    OnceExit(root) {
      if (!inventory) return;
      inventory.css(root);
      if (tailwindRoots.has(root)) inventory.tailwindCss(root);
    },
  };
  const vitePlugin = {
    name: 'mcp-bundled-third-party-notices',
    apply: 'build',
    enforce: 'post',
    configResolved(resolved) {
      config = resolved;
      inventory = new BundleInventory(config.root, JSON.parse(readText(POLICY)));
    },
    generateBundle: {
      order: 'post',
      handler(_options, bundle) {
        const chunks = inventory.collect(bundle);
        const packages = inventory.packageRecords();
        const runtime = runtimeNotices(path.join(config.root, '..'));
        notices = renderNotices(packages, runtime);
        const manifest = {
          schemaVersion: 1,
          scope: 'Rollup rendered modules and generated CSS; not a legal certification',
          producers: inventory.producers(this.meta.rollupVersion),
          producerLockSha256: sha256(readText(path.join(config.root, 'package-lock.json'))),
          projectLicenseSha256: sha256(readText(path.join(config.root, '..', 'LICENSE'))),
          noticesSha256: sha256(notices),
          chunks,
          generated: [...inventory.generated.values()].sort((a, b) => a.id < b.id ? -1 : 1),
          sources: inventory.sourceRecords(),
          packages,
          runtimeNotices: runtime,
          artifacts: artifactRecords(bundle),
        };
        this.emitFile({ type: 'asset', fileName: NOTICE_FILE, source: notices });
        this.emitFile({ type: 'asset', fileName: MANIFEST_FILE, source: jsonText(manifest) });
      },
    },
    writeBundle() {
      fs.writeFileSync(path.join(config.root, '..', NOTICE_FILE), notices);
    },
  };
  return { vitePlugin, cssPlugin };
}
