import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { PoolingTraceArtifact } from './pooling-trace-artifact.mjs';

const targets = {
  api: 'one-click apply and undo preserve active sessions even when file watching is off',
  batch: 'batch API stages a complete copy and activates only after the five-second reload',
};

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

  finish() {
    if (!this.enabled) return;
    let artifact;
    try {
      artifact = this.artifacts.collect(this.directory, this.configDirectory);
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
