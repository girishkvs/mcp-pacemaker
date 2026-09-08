export class ServerMetrics {
  constructor(sampleLimit = 50) {
    this.sampleLimit = sampleLimit;
    this.servers = new Map();
  }

  get(name) {
    let metrics = this.servers.get(name);
    if (!metrics) {
      metrics = {
        attempts: 0,
        total: 0,
        failures: 0,
        warmAdoptions: 0,
        sessionStarts: 0,
        sessionResumes: 0,
        latencies: [],
      };
      this.servers.set(name, metrics);
    }
    return metrics;
  }

  attemptingSpawn(name) {
    this.get(name).attempts++;
  }

  spawned(name) {
    this.get(name).total++;
  }

  failedSpawn(name) {
    this.get(name).failures++;
  }

  adoptedWarmChild(name) {
    this.get(name).warmAdoptions++;
  }

  openedSession(name, resumed = false) {
    const metrics = this.get(name);
    if (resumed) {
      metrics.sessionResumes++;
    } else {
      metrics.sessionStarts++;
    }
  }

  initialized(name, elapsedMs) {
    const samples = this.get(name).latencies;
    samples.push(elapsedMs);
    if (samples.length > this.sampleLimit) samples.shift();
  }

  snapshot(name) {
    const { latencies, ...counts } = this.get(name);
    const sorted = [...latencies].sort((a, b) => a - b);
    const percentile = (fraction) => sorted.length
      ? sorted[Math.min(sorted.length - 1, Math.floor(fraction * sorted.length))]
      : null;
    return {
      ...counts,
      samples: sorted.length,
      p50Ms: percentile(0.5),
      p95Ms: percentile(0.95),
      maxMs: sorted.length ? sorted[sorted.length - 1] : null,
    };
  }
}
