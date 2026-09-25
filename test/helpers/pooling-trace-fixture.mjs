import { mkdirSync, realpathSync, watch } from 'node:fs';
import { join } from 'node:path';
import { PoolingTraceArtifact } from './pooling-trace-artifact.mjs';

const targets = {
  api: 'one-click apply and undo preserve active sessions even when file watching is off',
  batch: 'batch API stages a complete copy and activates only after the five-second reload',
};
const workerEvents = ['worker-enter', 'worker-result', 'worker-error', 'helper-start', 'helper-end'];

export class PoolingTraceFixture {
  constructor(t, configDirectory, target) {
    this.enabled = Object.hasOwn(targets, target) && t.name === targets[target];
    if (!this.enabled) return;
    this.test = t;
    this.configDirectory = configDirectory;
    this.target = target;
    this.artifacts = new PoolingTraceArtifact();
    this.destination = process.env.MCP_POOLING_TRACE_ARTIFACT_DIR;
    try {
      const directory = join(configDirectory, 'trace');
      mkdirSync(directory);
      this.directory = directory;
    } catch {
      t.diagnostic('POOLING_TRACE_CAPTURE {"issue":"setup-failed"}');
    }
  }

  settled(records, pid) {
    const sends = records.filter((record) => record.event === 'writer-send');
    const related = records.filter((record) =>
      workerEvents.includes(record.event) || record.event === 'writer-result');
    if (new Set(sends.map((send) => `${send.pid}:${send.operation}`)).size !== sends.length ||
        related.some((record) => !sends.some((send) =>
          record.operation === send.operation && record.pid === send.pid))) return false;
    return sends.every((send) => {
      if (send.pid !== pid ||
          send.thread !== 0) return false;
      const operation = records.filter((record) =>
        record.operation === send.operation && record.pid === send.pid);
      const enters = operation.filter((record) => record.event === 'worker-enter' &&
        record.method === send.method && record.thread > 0 && record.elapsedMs >= send.elapsedMs);
      if (enters.length !== 1) return false;
      const enter = enters[0];
      const worker = operation.filter((record) => workerEvents.includes(record.event));
      if (worker.some((record) => record.thread !== enter.thread)) return false;
      const terminals = worker.filter((record) =>
        ['worker-result', 'worker-error'].includes(record.event) && record.sequence > enter.sequence &&
        record.elapsedMs >= enter.elapsedMs);
      if (terminals.length !== 1) return false;
      const terminal = terminals[0];
      const results = operation.filter((record) => record.event === 'writer-result');
      if (results.length !== 1 ||
          results[0].thread !== send.thread ||
          results[0].sequence <= send.sequence ||
          results[0].elapsedMs < terminal.elapsedMs) return false;
      const starts = worker.filter((record) => record.event === 'helper-start');
      const endings = worker.filter((record) => record.event === 'helper-end');
      if (starts.length !== endings.length ||
          new Set(starts.map((start) => start.call)).size !== starts.length) return false;
      return starts.every((start) => {
        const ends = worker.filter((record) => record.event === 'helper-end' &&
          record.call === start.call && record.action === start.action &&
          record.sequence > start.sequence && record.sequence < terminal.sequence &&
          record.elapsedMs >= start.elapsedMs && record.elapsedMs <= terminal.elapsedMs);
        return start.sequence > enter.sequence && ends.length === 1;
      });
    });
  }

  observe(listener) {
    return watch(realpathSync.native(this.directory), listener);
  }

  async settle(child, timeoutMs = 5000) {
    if (!this.enabled ||
        !this.directory) return true;
    if (!Number.isInteger(timeoutMs) ||
        timeoutMs < 1 ||
        timeoutMs > 5000) throw new RangeError('Invalid pooling trace observation bound.');
    // Observe diagnostics only; the operation/request budgets remain 9s/10s.
    // The 5s cap leaves teardown inside the fault runner's existing 30s guard.
    return new Promise((resolve) => {
      let watcher;
      let timer;
      let done = false;
      const complete = (issue) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        watcher?.close();
        child.off('exit', onExit);
        if (issue) this.settlementIssue = issue;
        resolve(!issue);
      };
      const inspect = () => {
        try {
          const trace = this.artifacts.readRecords(this.directory);
          if (!trace.issues.length &&
              this.settled(trace.records, child.pid)) complete();
        } catch {
          complete('settlement-failed');
        }
      };
      const onExit = () => {
        inspect();
        complete('settlement-process-exited');
      };
      try {
        // Subscribe before reading so a completion cannot fall between them.
        watcher = this.observe(inspect);
        watcher.on('error', () => complete('settlement-failed'));
        child.once('exit', onExit);
        timer = setTimeout(() => {
          inspect();
          complete('settlement-timeout');
        }, timeoutMs);
        inspect();
        if (child.exitCode !== null ||
            child.signalCode !== null) onExit();
      } catch {
        complete('settlement-failed');
      }
    });
  }

  finish() {
    if (!this.enabled) return;
    let artifact;
    try {
      artifact = this.artifacts.collect(this.directory, this.configDirectory);
      if (this.settlementIssue) artifact.issues.push(this.settlementIssue);
      this.test.diagnostic(`POOLING_TRACE ${JSON.stringify(artifact)}`);
    } catch {
      this.test.diagnostic('POOLING_TRACE_CAPTURE {"issue":"capture-failed"}');
      return;
    }
    if (this.destination) {
      try {
        this.artifacts.write(join(this.destination, `${this.target}-${process.pid}.json`), artifact);
      } catch {
        this.test.diagnostic('POOLING_TRACE_CAPTURE {"issue":"write-failed"}');
      }
    }
  }
}
