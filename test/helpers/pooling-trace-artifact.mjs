import fs from 'node:fs';
import os from 'node:os';
import { dirname, join } from 'node:path';
import { TRACE_MAX_BYTES, TRACE_MAX_EVENTS, TRACE_MAX_LINE_BYTES, validateTraceRecord } from '../../bin/pooling-trace.mjs';

export const TRACE_MAX_FILES = 4;
export const TRACE_ARTIFACT_BYTES = TRACE_MAX_FILES * TRACE_MAX_BYTES + 8192;
const issueNames = ['missing-source', 'invalid-source', 'source-limit', 'truncated',
  'write-failed', 'invalid-record', 'metadata-unavailable'];
const slots = ['active', 'pending', 'next', 'old', 'previous', 'transaction'];
const integer = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
const exact = (value, keys) => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const matches = (value, pattern) => typeof value === 'string' && pattern.test(value);
const imageOS = (value) => value === null || matches(value, /^(win|ubuntu|macos)\d{2,4}(-vs\d{4}|-arm64)?$/);
const imageVersion = (value) => value === null || matches(value, /^\d{8}\.\d{1,6}(\.\d{1,6})?$/);

export function validateTraceArtifact(artifact) {
  const environment = artifact?.environment;
  const validEnvironment = exact(environment, ['node', 'platform', 'release', 'arch', 'cpuModel',
    'cpuCount', 'availableParallelism', 'effectiveConcurrency', 'concurrencySource', 'imageOS', 'imageVersion']) &&
    matches(environment.node, /^v\d{1,3}\.\d{1,3}\.\d{1,3}$/) &&
    ['win32', 'linux', 'darwin'].includes(environment.platform) &&
    matches(environment.release, /^[0-9][0-9A-Za-z.+-]{0,79}$/) &&
    ['x64', 'arm64', 'ia32'].includes(environment.arch) &&
    matches(environment.cpuModel, /^[A-Za-z0-9 ()@.+-]{1,120}$/) &&
    integer(environment.cpuCount) && environment.cpuCount > 0 && environment.cpuCount <= 4096 &&
    integer(environment.availableParallelism) && environment.availableParallelism > 0 && environment.availableParallelism <= 1024 &&
    integer(environment.effectiveConcurrency) && environment.effectiveConcurrency > 0 && environment.effectiveConcurrency <= 1024 &&
    ['explicit', 'node-default'].includes(environment.concurrencySource) &&
    imageOS(environment.imageOS) && imageVersion(environment.imageVersion);
  const validFiles = artifact?.files === null || exact(artifact?.files, slots) &&
    slots.every((slot) => exact(artifact.files[slot], ['exists', 'bytes']) &&
      typeof artifact.files[slot].exists === 'boolean' && integer(artifact.files[slot].bytes) &&
      artifact.files[slot].bytes <= 1024 * 1024);
  const valid = exact(artifact, ['version', 'capture', 'issues', 'environment', 'files', 'records']) &&
    artifact.version === 1 && artifact.capture === 'unsealed' &&
    Array.isArray(artifact.issues) && artifact.issues.length <= issueNames.length &&
    artifact.issues.every((issue) => issueNames.includes(issue)) &&
    validEnvironment && validFiles &&
    Array.isArray(artifact.records) && artifact.records.length <= TRACE_MAX_FILES * TRACE_MAX_EVENTS;
  if (!valid) throw new Error('Invalid pooling trace artifact.');
  for (const record of artifact.records) validateTraceRecord(record);
  if (Buffer.byteLength(JSON.stringify(artifact)) > TRACE_ARTIFACT_BYTES) {
    throw new Error('Pooling trace artifact exceeds its bound.');
  }
  return artifact;
}

export class PoolingTraceArtifact {
  environment() {
    const flag = process.execArgv.find((arg) => arg.startsWith('--test-concurrency='));
    const parallelism = os.availableParallelism();
    return {
      node: process.version, platform: process.platform, release: os.release(), arch: process.arch,
      cpuModel: os.cpus()[0].model.trim(), cpuCount: os.cpus().length,
      availableParallelism: parallelism,
      effectiveConcurrency: flag ? Number(flag.split('=')[1]) : Math.max(parallelism - 1, 1),
      concurrencySource: flag ? 'explicit' : 'node-default',
      imageOS: imageOS(process.env.ImageOS) ? process.env.ImageOS : null,
      imageVersion: imageVersion(process.env.ImageVersion) ? process.env.ImageVersion : null,
    };
  }

  boundedRead(path, limit) {
    const stat = fs.lstatSync(path);
    if (!stat.isFile() ||
        stat.isSymbolicLink() ||
        stat.nlink !== 1 ||
        stat.size > limit) throw new Error('Invalid pooling trace input.');
    const fd = fs.openSync(path, 'r');
    try {
      const bytes = Buffer.alloc(limit + 1);
      const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
      if (count > limit) throw new Error('Pooling trace input exceeds its bound.');
      return bytes.subarray(0, count).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  }

  fileState(directory) {
    const names = ['servers.json', 'servers.pending.json', 'servers.pending-next.json',
      'servers.pending-old.json', 'servers.previous.json', 'servers.json.pooling-transaction'];
    return Object.fromEntries(slots.map((slot, index) => {
      try {
        const stat = fs.lstatSync(join(directory, names[index]));
        if (stat.isSymbolicLink() ||
            stat.size > 1024 * 1024 ||
            (slot === 'transaction' ? !stat.isDirectory() : !stat.isFile())) {
          throw new Error('Unsupported pooling metadata.');
        }
        return [slot, { exists: true, bytes: slot === 'transaction' ? 0 : stat.size }];
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        return [slot, { exists: false, bytes: 0 }];
      }
    }));
  }

  collect(traceDirectory, configDirectory) {
    const issues = new Set();
    const records = [];
    let names = [];
    try {
      const directory = fs.opendirSync(traceDirectory);
      try {
        let entry;
        while (names.length <= TRACE_MAX_FILES &&
            (entry = directory.readSync())) names.push(entry.name);
      } finally {
        directory.closeSync();
      }
    } catch {
      issues.add('missing-source');
    }
    if (!names.length) issues.add('missing-source');
    if (names.length > TRACE_MAX_FILES) issues.add('source-limit');
    for (const name of names.slice(0, TRACE_MAX_FILES)) {
      try {
        if (!/^\d{1,10}-\d{1,10}\.jsonl$/.test(name)) throw new Error('Invalid trace filename.');
        const text = this.boundedRead(join(traceDirectory, name), TRACE_MAX_BYTES);
        const lines = text.split('\n');
        if (lines.pop() !== '') issues.add('invalid-source');
        if (lines.length > TRACE_MAX_EVENTS) throw new Error('Too many trace records.');
        let sequence = 0;
        for (const line of lines) {
          if (Buffer.byteLength(line + '\n') > TRACE_MAX_LINE_BYTES) throw new Error('Oversized trace record.');
          const record = validateTraceRecord(JSON.parse(line));
          if (record.sequence !== ++sequence ||
              name !== `${record.pid}-${record.thread}.jsonl`) throw new Error('Invalid trace identity or sequence.');
          records.push(record);
          if (record.event === 'capture-truncated') issues.add('truncated');
          if (record.event === 'capture-failed') issues.add('write-failed');
          if (record.event === 'capture-invalid') issues.add('invalid-record');
        }
      } catch {
        issues.add('invalid-source');
      }
    }
    let files = null;
    try {
      files = this.fileState(configDirectory);
    } catch {
      issues.add('metadata-unavailable');
    }
    // A killed process cannot seal its output. Valid records are a snapshot,
    // not a promise that the writer's final events reached disk.
    return validateTraceArtifact({
      version: 1, capture: 'unsealed', issues: [...issues], environment: this.environment(), files, records,
    });
  }

  write(path, artifact) {
    const text = JSON.stringify(validateTraceArtifact(artifact));
    fs.mkdirSync(dirname(path), { recursive: true });
    fs.writeFileSync(path, text, { flag: 'wx', mode: 0o600 });
  }

  publish(source, destination) {
    const artifact = validateTraceArtifact(JSON.parse(this.boundedRead(source, TRACE_ARTIFACT_BYTES)));
    this.write(destination, artifact);
  }
}
