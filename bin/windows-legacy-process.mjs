import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const HELPER = fileURLToPath(new URL('./windows-legacy/LegacyProcessBroker.exe', import.meta.url));
const METADATA = fileURLToPath(new URL('./windows-legacy/LegacyProcessBroker.build.json', import.meta.url));

class LegacyBroker {
  constructor() {
    this.pending = null;
    this.buffer = '';
    this.stderr = '';
    this.closed = false;
    this.committed = false;
  }

  verifyHelper() {
    const metadataBytes = readFileSync(METADATA);
    if (metadataBytes.length > 65536) throw new Error('Invalid packaged legacy helper metadata');
    const metadata = JSON.parse(metadataBytes);
    const digest = metadata.binarySha256;
    const valid = metadata.schemaVersion === 1 &&
      metadata.binary === 'LegacyProcessBroker.exe' &&
      typeof digest === 'string' &&
      digest.length === 64 &&
      [...digest].every((character) => '0123456789abcdef'.includes(character));
    if (!valid) throw new Error('Invalid packaged legacy helper digest');
    const size = statSync(HELPER).size;
    if (size < 1 ||
        size > 4 * 1024 * 1024 ||
        createHash('sha256').update(readFileSync(HELPER)).digest('hex') !== digest) {
      throw new Error('Packaged legacy helper identity mismatch');
    }
  }

  start() {
    if (process.platform !== 'win32') throw new Error('Legacy process handoff requires Windows');
    this.verifyHelper();
    this.child = spawn(HELPER, [], {
      detached: true, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child.stdout.setEncoding('utf8');
    this.child.stderr.setEncoding('utf8');
    this.exit = new Promise((resolve) => {
      this.child.on('error', (error) => {
        this.failure(error);
        resolve({ code: null, signal: null, error: error.code });
      });
      this.child.on('close', (code, signal) => {
        this.closed = true;
        if (this.pending) this.failure(new Error(`Legacy process broker exited (code ${code}, signal ${signal})`));
        resolve({ code, signal });
      });
    });
    this.child.stdin.on('error', (error) => this.failure(error));
    this.child.stdout.on('error', (error) => this.failure(error));
    this.child.stderr.on('error', (error) => this.failure(error));
    this.child.stderr.on('data', (chunk) => {
      this.stderr = (this.stderr + chunk).slice(-2048);
    });
    this.child.stdout.on('data', (chunk) => {
      this.buffer += chunk;
      if (this.buffer.length > 262144) {
        this.failure(new Error('Legacy broker response exceeded bounds'));
        this.child.kill();
        return;
      }
      const newline = this.buffer.indexOf('\n');
      if (newline === -1) return;
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      if (!this.pending ||
          this.buffer.trim() !== '') {
        this.failure(new Error('Unexpected legacy broker response'));
        this.child.kill();
        return;
      }
      const pending = this.pending;
      this.pending = null;
      clearTimeout(pending.timer);
      try {
        const response = JSON.parse(line);
        if (response.ok !== true) {
          const error = new Error(`Legacy process handoff refused at ${response.stage || 'protocol'} (${response.type || 'invalid response'})`);
          if (typeof response.reason === 'string' &&
              response.reason.length <= 100) error.message += `: ${response.reason}`;
          error.code = response.error || 'LEGACY_PROCESS_REFUSED';
          error.detail = response;
          throw error;
        }
        pending.resolve(response);
      } catch (error) {
        this.error = error;
        pending.reject(error);
      }
    });
  }

  failure(error) {
    this.error = error;
    if (!this.pending) return;
    const pending = this.pending;
    this.pending = null;
    clearTimeout(pending.timer);
    pending.reject(error);
  }

  request(value, milliseconds) {
    if (this.closed ||
        this.error) return Promise.reject(this.error || new Error('Legacy broker closed'));
    if (this.pending) return Promise.reject(new Error('Concurrent legacy broker request refused'));
    let bytes;
    try { bytes = this.encode(value); }
    catch (error) { return Promise.reject(error); }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.failure(new Error('Legacy process broker deadline exceeded; outcome is unverified'));
        this.child.kill();
      }, milliseconds);
      this.pending = { resolve, reject, timer };
      this.child.stdin.write(bytes, (error) => {
        if (error) this.failure(error);
      });
    });
  }

  encode(value) {
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
    if (bytes.length > 262144) throw new Error('Legacy broker request exceeded bounds');
    return bytes;
  }

  async prepare(options) {
    const { port, root, expected = null } = options;
    if (!Number.isInteger(port) ||
        port < 1 ||
        port > 65535 ||
        typeof root !== 'string' ||
        !isAbsolute(root)) throw new Error('Exact absolute legacy root and port 1..65535 required');
    const request = { action: 'prepare', port, root: realpathSync.native(root), expected };
    this.encode(request);
    this.start();
    try {
      const result = await this.request(request, 20000);
      const plan = result.plan;
      if (plan?.kind !== 'legacy-observed-process-set' ||
          plan.protocol !== 1 ||
          plan.treeCompleteness !== 'unproven' ||
          typeof result.token !== 'string') throw new Error('Invalid legacy broker plan');
      this.plan = structuredClone(plan);
      this.token = result.token;
      return {
        plan: structuredClone(plan),
        diagnostics: structuredClone(result.diagnostics),
        stop: () => this.stop(),
        status: () => this.status(),
        close: () => this.close(),
      };
    } catch (error) {
      await this.close();
      throw error;
    }
  }

  receipt(value) {
    if (value?.treeCompleteness !== 'unproven' ||
        typeof value.legacyRootStopVerified !== 'boolean' ||
        typeof value.observedDescendantsStopped !== 'boolean' ||
        !Array.isArray(value.errors)) throw new Error('Invalid partial legacy process receipt');
    return value;
  }

  async status() {
    const response = await this.request({ action: 'status' }, 3000);
    return this.receipt(response.receipt);
  }

  async stop() {
    if (this.committed) throw new Error('Legacy stop approval already consumed');
    this.committed = true;
    try {
      const response = await this.request({
        action: 'stop', token: this.token, planSha256: this.plan.planSha256,
      }, 30000);
      const receipt = this.receipt(response.receipt);
      const exit = await this.finish();
      if (exit.code !== 0 ||
          exit.signal !== null) throw new Error('Legacy broker exit was not verified after stop');
      return { ...receipt, diagnostics: structuredClone(response.diagnostics) };
    } finally { await this.close(); }
  }

  async finish() {
    let timer;
    try {
      return await Promise.race([this.exit, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Legacy broker did not exit')), 3000);
      })]);
    } finally { clearTimeout(timer); }
  }

  async close() {
    if (!this.child) return;
    if (this.closed) return this.exit;
    let closeError;
    if (!this.pending &&
        !this.error &&
        !this.committed) {
      try { await this.request({ action: 'close' }, 2000); }
      catch (error) { closeError = error; }
    }
    if (!this.closed &&
        this.child.exitCode == null &&
        this.child.signalCode == null) this.child.kill();
    const exit = await this.finish();
    if (closeError) throw closeError;
    return exit;
  }

  async verify(plan) {
    this.encode({ action: 'verify', expected: plan });
    this.start();
    try {
      const response = await this.request({ action: 'verify', expected: plan }, 20000);
      const receipt = this.receipt(response.receipt);
      const exit = await this.finish();
      if (exit.code !== 0) throw new Error('Legacy verification broker exit failed');
      return receipt;
    } finally { await this.close(); }
  }
}

export async function prepareLegacyProcesses(options) {
  return new LegacyBroker().prepare(options);
}

export async function verifyLegacyProcessesGone(plan) {
  return new LegacyBroker().verify(plan);
}
