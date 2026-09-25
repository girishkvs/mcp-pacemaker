import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { LIMITS, inventory, requireCondition, runBounded, sha256 } from './core.mjs';

const OBJECT_ID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const TYPES = new Set(['blob', 'tree', 'commit', 'tag']);

async function git(history, tools, context, args, options = {}) {
  const result = await runBounded(tools.git ?? 'git', [
    '-c', 'core.hooksPath=', '-c', 'credential.helper=', `--git-dir=${history}`, ...args,
  ], { ...context, ...options });
  requireCondition(result.code === 0 && result.stderr.trim() === '', 'history-object-command-failed');
  return result.stdout;
}

export function historyObjectMetadata(text, ids) {
  const lines = text.trimEnd().split(/\r?\n/);
  requireCondition(ids.length > 0 && ids.length <= LIMITS.files && lines.length === ids.length,
    'history-object-count-mismatch');
  let bytes = 0;
  const metadata = lines.map((line, index) => {
    const fields = line.split(' ');
    requireCondition(fields.length === 3 && fields[0] === ids[index] && OBJECT_ID.test(fields[0]) &&
      TYPES.has(fields[1]) && /^(?:0|[1-9]\d*)$/.test(fields[2]), 'history-object-metadata-schema');
    const size = Number(fields[2]);
    bytes += size;
    requireCondition(Number.isSafeInteger(size) && size <= LIMITS.fileBytes &&
      bytes <= LIMITS.treeBytes, 'history-object-size-limit');
    return { id: fields[0], type: fields[1], size };
  });
  return { metadata, bytes };
}

export async function writeHistoryObjects(output, metadata, destination) {
  requireCondition(Buffer.isBuffer(output), 'history-object-binary-output-required');
  let offset = 0;
  for (const object of metadata) {
    const header = Buffer.from(`${object.id} ${object.type} ${object.size}\n`);
    requireCondition(output.subarray(offset, offset + header.length).equals(header), 'history-object-header-mismatch');
    offset += header.length;
    const body = output.subarray(offset, offset + object.size);
    requireCondition(body.length === object.size && output[offset + object.size] === 10,
      'history-object-body-truncated');
    const actual = createHash(object.id.length === 40 ? 'sha1' : 'sha256')
      .update(`${object.type} ${object.size}\0`).update(body).digest('hex');
    requireCondition(actual === object.id, 'history-object-content-mismatch');
    await writeFile(join(destination, `${object.id}.${object.type}`), body, { flag: 'wx', mode: 0o600 });
    offset += object.size + 1;
  }
  requireCondition(offset === output.length, 'history-object-trailing-output');
}

export async function materializeHistory({ history, commit, destination, tools, context }) {
  requireCondition(OBJECT_ID.test(commit), 'invalid-history-commit');
  const listed = await git(history, tools, context, ['rev-list', '--objects', '--no-object-names', commit]);
  const ids = listed.trimEnd().split(/\r?\n/);
  requireCondition(ids.length > 0 && ids.length <= LIMITS.files &&
    ids.every(id => OBJECT_ID.test(id)) && new Set(ids).size === ids.length, 'history-object-inventory-schema');
  const input = Buffer.from(`${ids.join('\n')}\n`);
  const checked = await git(history, tools, context, ['cat-file', '--batch-check'], { input });
  const { metadata, bytes } = historyObjectMetadata(checked, ids);
  const framedBytes = bytes + metadata.reduce((total, object) =>
    total + Buffer.byteLength(`${object.id} ${object.type} ${object.size}\n`) + 1, 0);
  const output = await git(history, tools, context, ['cat-file', '--batch'], {
    input, binaryOutput: true, maxOutputBytes: framedBytes,
  });
  await mkdir(destination);
  await writeHistoryObjects(output, metadata, destination);
  const contents = await inventory(destination);
  requireCondition(contents.evidence.files === ids.length && contents.evidence.bytes === bytes,
    'history-export-inventory-mismatch');
  return {
    ...contents.evidence, objects: ids.length,
    objectTypes: Object.fromEntries([...TYPES].map(type => [type, metadata.filter(item => item.type === type).length])),
    objectMetadataSha256: sha256(JSON.stringify(metadata)),
    exportLimits: { objects: LIMITS.files, objectBytes: LIMITS.fileBytes,
      rawBytes: LIMITS.treeBytes, batchOutputBytes: framedBytes },
    selection: 'all-raw-objects-reachable-from-HEAD; complete blobs, trees and commit metadata',
    objectIdentity: 'Git object IDs recomputed over every exported body',
  };
}
