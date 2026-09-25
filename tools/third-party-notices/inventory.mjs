import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

export const NOTICE_FILE = 'THIRD_PARTY_NOTICES.txt';
export const MANIFEST_FILE = 'third-party-manifest.json';
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const normalizeText = (value) => value.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
export const jsonText = (value) => `${JSON.stringify(value, null, 2)}\n`;

export function relativeFile(root, file) {
  const relative = path.relative(root, file).replaceAll('\\', '/');
  if (!relative ||
      relative.startsWith('../') ||
      path.isAbsolute(relative)) {
    throw new Error('Notice input must be a file inside its expected source directory');
  }
  return relative;
}

export function readText(file) {
  const bytes = fs.readFileSync(file);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (!text.trim() ||
      text.includes('\0')) {
    throw new Error('Empty or non-text license/source input');
  }
  return normalizeText(text);
}

export function noticeComments(source) {
  const comments = source.match(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g) ?? [];
  return [...new Set(comments.filter((comment) =>
    /@license|@preserve|copyright|SPDX-License-Identifier/i.test(comment) ||
    comment.startsWith('/*!')))].sort();
}

function licenseFiles(directory, prefix = '') {
  const result = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules' ||
        entry.name === '.git') {
      continue;
    }
    const name = `${prefix}${entry.name}`;
    if (entry.isSymbolicLink()) {
      throw new Error('Symlinks in a bundled package require notice review');
    }
    if (entry.isDirectory()) {
      result.push(...licenseFiles(path.join(directory, entry.name), `${name}/`));
    } else {
      const isNotice = /^(licen[cs]e|notice|copying|copyright)([._-]|$)/i.test(entry.name) &&
        !/\.(?:[cm]?[jt]sx?|map)$/i.test(entry.name);
      if (isNotice) result.push(name);
    }
  }
  return result.sort();
}

export class BundleInventory {
  constructor(uiRoot, policy) {
    this.uiRoot = uiRoot;
    this.policy = policy;
    this.lock = JSON.parse(readText(path.join(uiRoot, 'package-lock.json')));
    this.packages = new Map();
    this.sources = new Map();
    this.generated = new Map();
  }

  packageAt(lockPath) {
    const existing = this.packages.get(lockPath);
    if (existing) return existing;
    const directory = path.join(this.uiRoot, lockPath);
    if (fs.realpathSync(directory) !== path.resolve(directory)) {
      throw new Error('Linked producer packages require notice review');
    }
    const metadata = JSON.parse(readText(path.join(directory, 'package.json')));
    const locked = this.lock.packages[lockPath];
    if (!locked ||
        metadata.version !== locked.version ||
        metadata.license !== locked.license) {
      throw new Error(`Installed producer differs from UI lock: ${lockPath}`);
    }
    const key = `${metadata.name}@${metadata.version}`;
    const reviewed = this.policy[key];
    if (!reviewed ||
        reviewed.license !== metadata.license) {
      throw new Error(`Unreviewed bundled package/license: ${key}`);
    }
    const files = licenseFiles(directory);
    if (JSON.stringify(files) !== JSON.stringify(Object.keys(reviewed.files).sort())) {
      throw new Error(`Missing or unreviewed license/NOTICE files: ${key}`);
    }
    let licenses = files.map((file) => {
      const text = readText(path.join(directory, file));
      const digest = sha256(text);
      if (digest !== reviewed.files[file]) {
        throw new Error(`Changed license/NOTICE text requires review: ${key}/${file}`);
      }
      return { file, sha256: digest, text };
    });
    if (reviewed.include) {
      licenses = licenses.filter(({ file }) => reviewed.include.includes(file));
    }
    licenses = licenses.flatMap((license) => {
      const headings = reviewed.sections?.[license.file];
      if (!headings) return [license];
      const lines = license.text.split('\n');
      return headings.map((heading) => {
        const start = lines.indexOf(heading);
        if (start < 0) throw new Error(`Reviewed license section missing: ${key}`);
        const depth = heading.match(/^#+/)[0].length;
        let end = start + 1;
        while (end < lines.length) {
          const next = lines[end].match(/^(#+) /);
          if (next &&
              next[1].length <= depth) break;
          end++;
        }
        const text = `${lines.slice(start, end).join('\n').trimEnd()}\n`;
        return { file: license.file, section: heading, sourceSha256: license.sha256, sha256: sha256(text), text };
      });
    });
    for (const supplemental of reviewed.supplemental ?? []) {
      const directory = fileURLToPath(new URL('./', import.meta.url));
      const file = path.resolve(directory, supplemental.file);
      relativeFile(directory, file);
      const text = readText(file);
      if (sha256(text) !== supplemental.sha256) {
        throw new Error(`Changed supplementary license text requires review: ${key}`);
      }
      licenses.push({ ...supplemental, text });
    }
    if (!licenses.some(({ file }) => /(^|\/)licen[cs]e([._-]|$)/i.test(file))) {
      throw new Error(`Missing license text: ${key}`);
    }
    const record = {
      name: metadata.name,
      version: metadata.version,
      license: metadata.license,
      lockPath,
      licenses,
      comments: new Set(),
    };
    this.packages.set(lockPath, record);
    return record;
  }

  source(file) {
    const relative = relativeFile(this.uiRoot, file);
    const source = readText(file);
    this.sources.set(relative, sha256(source));
    const marker = relative.lastIndexOf('node_modules/');
    if (marker < 0) return { id: relative, package: null };
    const remainder = relative.slice(marker + 'node_modules/'.length).split('/');
    const count = remainder[0].startsWith('@') ? 2 : 1;
    const lockPath = relative.slice(0, marker) + 'node_modules/' + remainder.slice(0, count).join('/');
    const pkg = this.packageAt(lockPath);
    for (const comment of noticeComments(source)) pkg.comments.add(comment);
    return { id: relative, package: `${pkg.name}@${pkg.version}` };
  }

  module(id) {
    if (id === '\0vite/modulepreload-polyfill.js' ||
        id === '\0commonjsHelpers.js') {
      const pkg = this.packageAt('node_modules/vite');
      return {
        id: id.slice(1),
        package: `${pkg.name}@${pkg.version}`,
        generated: true,
      };
    }
    const clean = id.replace(/^\0/, '').replace(/\?commonjs-(proxy|es-import|exports|module)$/, '');
    if (!path.isAbsolute(clean)) {
      throw new Error('Unknown virtual bundled module requires notice review');
    }
    const record = this.source(clean);
    const suffix = id.match(/\?commonjs-(proxy|es-import|exports|module)$/)?.[0] ?? '';
    return id.startsWith('\0') ?
      { ...record, id: `commonjs:${record.id}${suffix}`, generated: true } : record;
  }

  css(root) {
    root.walk((node) => {
      const file = node.source?.input?.file;
      if (!file) return;
      const relative = relativeFile(this.uiRoot, file);
      if (!this.sources.has(relative)) this.sources.set(relative, sha256(readText(file)));
      if (relative.includes('node_modules/')) {
        const record = this.source(file);
        this.generated.set(record.id, { ...record, kind: 'css-source' });
      }
    });
  }

  collect(bundle) {
    const chunks = [];
    for (const output of Object.values(bundle)) {
      if (output.type !== 'chunk') continue;
      const modules = Object.entries(output.modules)
        .filter(([, details]) => details.renderedLength > 0)
        .map(([id, details]) => ({ ...this.module(id), renderedLength: details.renderedLength }))
        .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
      chunks.push({ file: output.fileName, modules });
    }

    chunks.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : 0);
    if (!chunks.length ||
        !this.packages.size) {
      throw new Error('No bundled UI package modules were captured');
    }
    return chunks;
  }

  sourceRecords() {
    return [...this.sources.entries()]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([path, sha256]) => ({ path, sha256 }));
  }

  packageRecords() {
    return [...this.packages.values()]
      .sort((a, b) => a.lockPath < b.lockPath ? -1 : a.lockPath > b.lockPath ? 1 : 0)
      .map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        license: pkg.license,
        lockPath: pkg.lockPath,
        licenses: pkg.licenses,
        comments: [...pkg.comments].sort(),
      }));
  }

  tailwindCss(root) {
    const file = path.join(this.uiRoot, 'node_modules/tailwindcss/lib/css/preflight.css');
    const require = createRequire(path.join(this.uiRoot, 'package.json'));
    const preflight = require('postcss').parse(readText(file));
    const selectors = new Set();
    root.walkRules((rule) => selectors.add(rule.selector.replace(/\s+/g, ' ')));
    let missing = false;
    preflight.walkRules((rule) => {
      if (!selectors.has(rule.selector.replace(/\s+/g, ' '))) missing = true;
    });
    if (missing) {
      throw new Error('Tailwind preflight output changed; generated CSS attribution requires review');
    }
    const record = this.source(file);
    this.generated.set(record.id, { ...record, kind: 'tailwind-preflight', evidence: 'emitted CSS selectors' });
  }

  producers(rollupVersion) {
    return ['@vitejs/plugin-react', 'autoprefixer', 'postcss', 'rollup', 'tailwindcss', 'vite'].map((name) => {
      const lockPath = `node_modules/${name}`;
      const metadata = JSON.parse(readText(path.join(this.uiRoot, lockPath, 'package.json')));
      const wrongRollup = name === 'rollup' && metadata.version !== rollupVersion;
      if (metadata.name !== name ||
          metadata.version !== this.lock.packages[lockPath]?.version ||
          wrongRollup) {
        throw new Error(`Installed build producer differs from UI lock: ${name}`);
      }
      return { name, version: metadata.version };
    });
  }
}

export function renderNotices(packages, runtime = []) {
  const text = [
    'MCP Pacemaker - third-party notices',
    '',
    'Dashboard entries come from retained Rollup modules and observed generated CSS.',
    'Runtime supplements bind upstream license text to reviewed installed producer versions.',
    'ui/dist/third-party-manifest.json records module and artifact hashes.',
    'The project itself remains under its separate MIT LICENSE.',
    'This inventory is technical attribution evidence, not a legal compliance certification.',
    '',
    'CLI dependencies are installed separately by npm, not copied into this UI bundle.',
    'Attribution supplied by those packages remains in their installed package directories.',
    'This UI inventory does not audit every separately resolved CLI dependency.',
    'Those dependencies are not represented as bundled UI code in this notice.',
    '',
  ];
  const sections = [
    { title: 'Bundled dashboard code', packages },
    { title: 'Separately installed runtime supplements (not UI-bundled)', packages: runtime },
  ];
  for (const section of sections) {
    if (!section.packages.length) continue;
    text.push(section.title, '');
    for (const pkg of section.packages) {
      text.push('='.repeat(78), `${pkg.name}@${pkg.version}`, `Declared license: ${pkg.license}`, '');
      for (const license of pkg.licenses) {
        const title = license.section ? `${license.file}: ${license.section}` : license.file;
        text.push(`--- ${title} ---`);
        if (license.sourceUrl) text.push(`Source: ${license.sourceUrl}`, license.reason, '');
        text.push(license.text.trimEnd(), '');
      }
      if (pkg.comments.length) {
        text.push('--- Notices retained from contributing source files ---', ...pkg.comments, '');
      }
    }
  }
  return `${text.join('\n').trimEnd()}\n`;
}

export function artifactRecords(bundle) {
  return Object.values(bundle)
    .map((output) => ({
      file: output.fileName,
      sha256: sha256(output.type === 'chunk' ? output.code : output.source),
    }))
    .sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : 0);
}

export function verifyArtifacts(root) {
  const dist = path.join(root, 'ui', 'dist');
  const manifest = JSON.parse(readText(path.join(dist, MANIFEST_FILE)));
  if (manifest.schemaVersion !== 1 ||
      !manifest.chunks?.length ||
      !manifest.packages?.length ||
      !manifest.artifacts?.length) {
    throw new Error('Missing or unsupported bundled notice manifest');
  }
  if (!manifest.runtimeNotices?.length ||
      manifest.runtimeNotices.some((pkg) => pkg.distribution !== 'separately-installed')) {
    throw new Error('Missing or mislabeled separately installed runtime license supplement');
  }
  if (!Array.isArray(manifest.sources) ||
      !manifest.sources.length) {
    throw new Error('Source hashes must use explicit path/sha256 records');
  }
  const sourcePaths = new Set();
  const ui = path.join(root, 'ui');
  for (const source of manifest.sources) {
    const validSource = typeof source?.path === 'string' &&
      typeof source.sha256 === 'string' &&
      /^[0-9a-f]{64}$/.test(source.sha256) &&
      Object.keys(source).length === 2;
    if (!validSource) throw new Error('Invalid source path/sha256 record');
    if (relativeFile(ui, path.resolve(ui, source.path)) !== source.path ||
        sourcePaths.has(source.path)) {
      throw new Error('Noncanonical or repeated source path');
    }
    sourcePaths.add(source.path);
  }
  const packageKeys = new Set(manifest.packages.map((pkg) => `${pkg.name}@${pkg.version}`));
  for (const pkg of [...manifest.packages, ...manifest.runtimeNotices]) {
    if (!pkg.name ||
        !pkg.version ||
        !pkg.license ||
        !pkg.licenses?.length) {
      throw new Error('Incomplete bundled package license record');
    }
    for (const license of pkg.licenses) {
      if (!license.text?.trim() ||
          sha256(license.text) !== license.sha256) {
        throw new Error('Missing or changed bundled license text');
      }
    }
  }
  const modules = [...manifest.chunks.flatMap(({ modules }) => modules), ...(manifest.generated ?? [])];
  for (const module of modules) {
    if (module.package &&
        !packageKeys.has(module.package)) {
      throw new Error('Bundled module has no matching package license');
    }
  }
  const notices = renderNotices(manifest.packages, manifest.runtimeNotices);
  for (const file of [path.join(root, NOTICE_FILE), path.join(dist, NOTICE_FILE)]) {
    if (readText(file) !== notices ||
        sha256(notices) !== manifest.noticesSha256) {
      throw new Error('Bundled third-party notices are missing or stale');
    }
  }
  if (sha256(readText(path.join(root, 'LICENSE'))) !== manifest.projectLicenseSha256) {
    throw new Error('Project LICENSE differs from bundled notice manifest');
  }
  const actual = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Unexpected linked UI artifact');
      if (entry.isDirectory()) visit(file);
      else actual.push(relativeFile(dist, file));
    }
  };
  visit(dist);
  const expected = [...manifest.artifacts.map(({ file }) => file), NOTICE_FILE, MANIFEST_FILE].sort();
  if (JSON.stringify(actual.sort()) !== JSON.stringify(expected)) {
    throw new Error('UI artifact closure differs from bundled notice manifest');
  }
  for (const artifact of manifest.artifacts) {
    const file = path.resolve(dist, artifact.file);
    relativeFile(dist, file);
    if (sha256(fs.readFileSync(file)) !== artifact.sha256) {
      throw new Error(`UI artifact differs from bundled notice manifest: ${artifact.file}`);
    }
  }
  return manifest;
}
