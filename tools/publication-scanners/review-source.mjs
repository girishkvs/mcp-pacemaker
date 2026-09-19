import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { inventory, requireCondition, runBounded, sha256 } from './core.mjs';
import { diagnosticLocations } from './locations.mjs';
import { localCommitment } from '../npm-publication/local-regression.mjs';

// Eligibility limits, not approvals: every byte, finding, report and owner dispatch must still match.
export const SYNTHETIC_URI_LOCATIONS = Object.freeze([
  Object.freeze({ path: 'test/helpers/npm-publication-stage-issuer.mjs', line: 36 }),
  Object.freeze({ path: 'test/helpers/npm-publication-stage-fulcio.mjs', line: 41 }),
  Object.freeze({ path: 'tools/npm-publication/offline-stage/npm.cjs', line: 44 }),
]);

export function syntheticUriLocation(pathSha256, line) {
  return SYNTHETIC_URI_LOCATIONS.some(item => sha256(item.path) === pathSha256 && item.line === line);
}

const SYNTHETIC_URI_PAIRS = Object.freeze([
  Object.freeze({ path: 'test/helpers/npm-publication-stage-issuer.mjs', line: 36,
    blob: '2abc5b2058695c2274c3913b99b1be6d5427af5d', rawBytes: 44, fullBytes: 50,
    rawSha256: '26186b00db0c3b3805718b9b75394f26fc14cc8c98539d4b1ad83b916cdf77b1',
    fullSha256: '04d7df8ca05cb24d14cc42cbc1bf9147911453b65cd6114a6ca3cada68534e59' }),
  Object.freeze({ path: 'test/helpers/npm-publication-stage-fulcio.mjs', line: 41,
    blob: '0aebdd4a2945cbf1cca60c6bc21ce0d5631faf0f', rawBytes: 37, fullBytes: 56,
    rawSha256: '21d0bd781fbbee210dba0d184c249ded57230825ec5ebe02650262d8dc068e18',
    fullSha256: '424592cb5945aa8ab78bb0be0d527511e21a0d1c1e2bfadcf528f4a8f1d1a9b8' }),
  Object.freeze({ path: 'tools/npm-publication/offline-stage/npm.cjs', line: 44,
    blob: '7dbaed1775a2aa3b83c963fa1d56ff479ceaca7f', rawBytes: 40, fullBytes: 45,
    rawSha256: 'c8348334ee6dfac5306189aaee5556a286036ea3168044dd36b330703d060aa8',
    fullSha256: '618386be8b79f7991b70268ae66b5dfbeaed06c2efb02a36c0027683980f388a' }),
]);

class SyntheticUriRepresentation {
  constructor(tool, completion) {
    this.tool = tool;
    this.completion = completion;
  }

  hasKeys(value, names) {
    return value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Object.keys(value).length === names.length &&
      names.every(name => Object.hasOwn(value, name));
  }

  matchesMetadata(row, scope, pin) {
    // The caller supplies verifyTool's result; this is not an authentication capability.
    const pinnedTool = this.tool?.name === 'trufflehog' &&
      this.tool.version === '3.97.1' &&
      typeof this.tool.sha256 === 'string' &&
      /^[a-f0-9]{64}$/.test(this.tool.sha256) &&
      this.completion.trufflehog_version === '3.97.1' &&
      this.completion.verified_secrets === 0;
    const nativeFields = this.hasKeys(row, ['SourceMetadata', 'SourceID', 'SourceType', 'SourceName',
      'DetectorType', 'DetectorName', 'DetectorDescription', 'DecoderName', 'Verified',
      'VerificationFromCache', 'Raw', 'RawV2', 'Redacted', 'ExtraData', 'StructuredData', 'SecretParts']);
    const filesystem = this.hasKeys(row.SourceMetadata, ['Data']) &&
      this.hasKeys(row.SourceMetadata.Data, ['Filesystem']) &&
      this.hasKeys(row.SourceMetadata.Data.Filesystem, ['file', 'line']) &&
      typeof row.SourceMetadata.Data.Filesystem.file === 'string' &&
      row.SourceMetadata.Data.Filesystem.line === pin.line;
    return pinnedTool &&
      nativeFields &&
      filesystem &&
      ['working-tree', 'history'].includes(scope) &&
      row.SourceID === 1 &&
      row.SourceType === 15 &&
      row.SourceName === 'trufflehog - filesystem' &&
      row.DetectorType === 17 &&
      row.DetectorName === 'URI' &&
      row.DetectorDescription === 'This detector identifies URLs with embedded credentials, which can be used to access web resources without explicit user interaction.' &&
      row.DecoderName === 'PLAIN' &&
      row.Verified === false &&
      row.VerificationFromCache === false &&
      row.ExtraData === null &&
      row.StructuredData === null &&
      this.hasKeys(row.SecretParts, ['host', 'username', 'password']);
  }

  matches(row, entry, lineNumber, line, scope) {
    const pin = SYNTHETIC_URI_PAIRS.find(item => item.path === entry.path &&
      item.line === lineNumber && item.blob === entry.blob);
    if (!pin ||
        typeof row.RawV2 !== 'string' ||
        typeof line !== 'string') return false;
    const exactValues = Buffer.byteLength(row.Raw) === pin.rawBytes &&
      Buffer.byteLength(row.RawV2) === pin.fullBytes &&
      sha256(row.Raw) === pin.rawSha256 &&
      sha256(row.RawV2) === pin.fullSha256;
    if (!exactValues ||
        !this.matchesMetadata(row, scope, pin)) return false;

    const start = line.indexOf(row.RawV2);
    const quote = line[start - 1];
    const quotedLiteral = start > 0 &&
      (quote === "'" || quote === '"') &&
      line[start - 2] !== '\\' &&
      line[start + row.RawV2.length] === quote &&
      line.indexOf(row.RawV2, start + 1) === -1;
    if (!quotedLiteral) return false;

    // Only the pinned literal bytes are split; no URL decoding or normalization is allowed.
    const scheme = 'https://';
    const authority = row.Raw.slice(scheme.length);
    const at = authority.indexOf('@');
    const colon = authority.indexOf(':');
    const path = row.RawV2.slice(row.Raw.length);
    const shape = row.Raw.slice(0, scheme.length) === scheme &&
      colon > 0 &&
      at > colon + 1 &&
      at === authority.lastIndexOf('@') &&
      path[0] === '/' &&
      row.RawV2 === `${row.Raw}${path}`;
    if (!shape) return false;
    const username = authority.slice(0, colon);
    const password = authority.slice(colon + 1, at);
    const host = authority.slice(at + 1);
    return row.SecretParts.username === username &&
      row.SecretParts.password === password &&
      row.SecretParts.host === host &&
      row.Redacted === `${scheme}${username}:********@${host}${path}`;
  }
}

export async function readReviewSource(root, { tools, context, run = runBounded }) {
  const git = async (args, binaryOutput = false) => {
    const result = await run(tools.git ?? 'git', ['--no-optional-locks',
      '-c', 'core.hooksPath=', '-c', 'credential.helper=', '-c', 'core.fsmonitor=false',
      '-c', 'core.attributesFile=', '-c', 'core.autocrlf=false', '-C', root, ...args],
    { ...context, binaryOutput, timeoutMs: 30_000 });
    requireCondition(result.code === 0 && result.stderr === '', 'review-source-git-failed');
    return result.stdout;
  };
  requireCondition(isAbsolute(root) && resolve(root) === await realpath(root), 'review-source-root');
  const head = (await git(['rev-parse', '--show-toplevel', 'HEAD', 'HEAD^{tree}'])).trim().split(/\r?\n/);
  requireCondition(head.length === 3 && resolve(head[0]) === resolve(root) &&
    head.slice(1).every(value => /^[a-f0-9]{40}$/.test(value)), 'review-source-head');
  requireCondition((await git(['status', '--porcelain=v1', '--untracked-files=all'])).trim() === '',
    'review-source-dirty');
  const attributesFile = (await git(['rev-parse', '--path-format=absolute', '--git-path', 'info/attributes'])).trim();
  requireCondition(isAbsolute(attributesFile) && !await lstat(attributesFile).catch(error => {
    if (error.code === 'ENOENT') return null;
    throw error;
  }), 'review-source-attribute-override');
  const rows = (await git(['ls-tree', '-rz', '--full-tree', head[1]])).split('\0');
  requireCondition(rows.pop() === '' && rows.length > 0 && rows.length <= 10_000, 'review-source-tree');
  const entries = rows.map(row => {
    const match = /^(100644|100755) blob ([a-f0-9]{40})\t([^\0\r\n]+)$/.exec(row);
    requireCondition(Boolean(match), 'review-source-tree-entry');
    const path = match[3];
    requireCondition(!path.includes('\\') && !path.includes(':') &&
      path.split('/').every(part => part && part !== '.' && part !== '..'), 'review-source-path');
    return { path, mode: match[1], blob: match[2] };
  });
  requireCondition(new Set(entries.map(item => item.path.toLowerCase())).size === entries.length,
    'review-source-path-collision');
  const files = await inventory(root, { source: true, trackedPaths: entries.map(item => item.path) });
  requireCondition((await git(['rev-parse', 'HEAD'])).trim() === head[1], 'review-source-changed');
  return {
    root, entries, files: files.entries,
    binding: { commit: head[1], tree: head[2], rootSha256: sha256(resolve(root)),
      filesSha256: files.evidence.sha256, treeEntriesSha256: sha256(JSON.stringify(entries)) },
    async producerEvidence() {
      requireCondition(files.entries.length === entries.length &&
        files.entries.every(file => entries.some(entry => entry.path === file.path)),
      'producer-source-membership');
      const facts = [];
      for (const file of files.entries) {
        const entry = entries.find(entry => entry.path === file.path);
        const stat = await lstat(join(root, entry.path));
        requireCondition(stat.isFile() && stat.nlink === 1, 'producer-source-linked-file');
        const attributes = await this.attributes(entry);
        requireCondition(['set', 'auto', 'unset'].includes(attributes.text) &&
          ['lf', 'crlf', 'unspecified'].includes(attributes.eol), 'producer-source-attributes');
        const blob = await this.bytes(entry);
        const clean = await git([`--attr-source=${head[1]}`, 'hash-object', `--path=${entry.path}`,
          '--', join(root, entry.path)]);
        requireCondition(clean.trim() === entry.blob, 'producer-source-clean-blob');
        const rendered = await git(['-c', 'core.eol=lf', `--attr-source=${head[1]}`,
          'cat-file', '--filters', `--path=${entry.path}`, entry.blob], true);
        requireCondition(Buffer.isBuffer(rendered) && rendered.length === file.size &&
          sha256(rendered) === file.sha256, 'producer-source-not-lf-checkout');
        if (attributes.text === 'unset') requireCondition(rendered.equals(blob), 'producer-binary-changed');
        facts.push({ pathSha256: sha256(file.path), size: file.size, mode: file.mode,
          sha256: file.sha256, gitMode: entry.mode, blob: entry.blob,
          blobSha256: sha256(blob), attributes });
      }
      const plain = files.entries.map(({ path, size, sha256 }) => ({ path, size, sha256 }))
        .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
      requireCondition((await inventory(root, { source: true, trackedPaths: entries.map(entry => entry.path) }))
        .evidence.sha256 === files.evidence.sha256, 'producer-source-changed');
      return { schemaVersion: 1, kind: 'exact-committed-lf-policy-checkout',
        inventoryFormat: 'json-ordered-path-size-mode-sha256-v1',
        privateFormat: 'localCommitment-path-sorted-path-size-sha256-v1',
        filesSha256: files.evidence.sha256, privateFilesSha256: localCommitment(plain),
        privateTreeSha256: localCommitment([...entries].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
        checkoutPolicy: { autocrlf: false, eol: 'lf' }, files: facts };
    },
    async bytes(entry) {
      const bytes = await git(['cat-file', 'blob', entry.blob], true);
      requireCondition(Buffer.isBuffer(bytes) && bytes.length <= 256 * 1024 * 1024 &&
        createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') === entry.blob,
      'review-source-blob');
      return bytes;
    },
    async attributes(entry) {
      const names = ['text', 'eol', 'filter', 'working-tree-encoding', 'ident'];
      const fields = (await git(['check-attr', `--source=${head[1]}`, '-z', ...names, '--', entry.path])).split('\0');
      requireCondition(fields.pop() === '' && fields.length === names.length * 3, 'review-source-attributes');
      const values = {};
      for (const [index, name] of names.entries()) {
        requireCondition(fields[index * 3] === entry.path && fields[index * 3 + 1] === name,
          'review-source-attributes');
        values[name] = fields[index * 3 + 2];
      }
      requireCondition(['filter', 'working-tree-encoding', 'ident'].every(name => values[name] === 'unspecified'),
        'review-source-conversion');
      return values;
    },
  };
}

export async function findingSourceBinding(source, entry, line, scope, scanBytes) {
  const blob = await source.bytes(entry);
  const checkout = await readFile(join(source.root, entry.path));
  const attributes = await source.attributes(entry);
  let checkoutForm = 'exact-git-blob';
  if (attributes.eol === 'crlf') {
    requireCondition(attributes.text === 'set', 'review-source-undeclared-checkout');
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(blob);
    requireCondition(!/[\r\0\ufeff]/.test(text) &&
      Buffer.from(text).equals(blob) && Buffer.from(text.replace(/\n/g, '\r\n')).equals(checkout),
    'review-source-checkout-bytes');
    checkoutForm = 'declared-crlf';
  } else {
    requireCondition(checkout.equals(blob), 'review-source-undeclared-checkout');
    if (attributes.eol === 'lf') requireCondition(!blob.includes(13), 'review-source-declared-lf');
  }
  const scanned = scope === 'history' ? blob : checkout;
  if (scanBytes) requireCondition(scanned.equals(scanBytes), 'review-source-scanned-bytes');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(scanned);
  requireCondition(!/[\0\ufeff]/.test(text), 'review-source-text-encoding');
  requireCondition(Number.isSafeInteger(line) && line > 0 &&
    line <= text.split(/\r?\n/).length, 'review-source-line');
  return { pathSha256: sha256(entry.path), line, blob: entry.blob, blobSha256: sha256(blob),
    checkoutSha256: sha256(checkout), scanFileSha256: sha256(scanned),
    attributesSha256: sha256(JSON.stringify(attributes)), checkoutForm };
}

export async function collectFindingIdentities(result, scope, target, source, entries, tool) {
  const rows = result.stdout.split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line));
  requireCondition(rows.length <= 64, 'review-finding-limit');
  const completion = result.stderr.split(/\r?\n/).filter(line => line.trim())
    .map(line => JSON.parse(line)).filter(item => item.msg === 'finished scanning');
  requireCondition(completion.length === 1 && completion[0].unverified_secrets === rows.length,
    'review-completion-count-mismatch');
  const uriRepresentation = new SyntheticUriRepresentation(tool, completion[0]);
  const locations = diagnosticLocations('trufflehog', result, target, entries);
  const identities = [];
  for (const [index, row] of rows.entries()) {
    const noVerificationError = row.Verified === false &&
      (row.VerificationFromCache === undefined || row.VerificationFromCache === false) &&
      (row.VerificationError === undefined || row.VerificationError === null || row.VerificationError === '');
    requireCondition(noVerificationError, 'review-verification-error-or-cache');
    const location = locations[index];
    const rawFile = row.SourceMetadata.Data.Filesystem.file;
    requireCondition(!/(?:^|[\\/])\.{1,2}(?:[\\/]|$)/.test(rawFile), 'review-location-traversal');
    let binding = null;
    const eligible = row.DetectorName === 'URI' &&
      typeof row.Raw === 'string' &&
      row.Raw.length > 0 &&
      location.line !== null;
    if (eligible) {
      const matches = scope === 'history'
        ? source.entries.filter(entry => `${entry.blob}.blob` === location.path)
        : source.entries.filter(entry => entry.path === location.path);
      if (matches.length === 1 && syntheticUriLocation(sha256(matches[0].path), location.line)) {
        const bytes = await readFile(join(target, location.path));
        const line = bytes.toString('utf8').split(/\r?\n/)[location.line - 1];
        const unchangedRepresentation = row.RawV2 === undefined ||
          row.RawV2 === '' ||
          row.RawV2 === row.Raw;
        const supportedRepresentation = unchangedRepresentation ||
          uriRepresentation.matches(row, matches[0], location.line, line, scope);
        if (supportedRepresentation) {
          requireCondition(typeof line === 'string' && line.split(row.Raw).length === 2,
            'review-finding-not-literal');
          binding = await findingSourceBinding(source, matches[0], location.line, scope, bytes);
        }
      }
    }
    const identity = { detector: row.DetectorName === 'URI' ? 'URI' : 'other',
      detectorSha256: sha256(row.DetectorName), valueSha256: sha256(row.Raw),
      recordSha256: sha256(JSON.stringify(row)), binding };
    identities.push({ id: sha256(JSON.stringify({ scope, ...identity })), ...identity });
  }
  requireCondition(new Set(identities.map(item => item.id)).size === identities.length, 'review-duplicate-finding');
  return identities;
}
