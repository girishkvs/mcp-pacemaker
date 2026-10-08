const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { SingleSessionServer } = require('./identity.cjs');
const { Relay } = require('./relay.cjs');

function loadBootstrap(environment, platform = process.platform, now = Date.now()) {
  const hosted = (
    platform === 'win32' &&
    environment.GITHUB_ACTIONS === 'true' &&
    environment.RUNNER_ENVIRONMENT === 'github-hosted' &&
    environment.RUNNER_OS === 'Windows' &&
    environment.RUNNER_ARCH === 'X64' &&
    environment.GITHUB_REPOSITORY === 'girishkvs/mcp-pacemaker' &&
    environment.GITHUB_ACTOR === 'girishkvs' &&
    environment.GITHUB_EVENT_NAME === 'push' &&
    environment.GITHUB_RUN_ATTEMPT === '1' &&
    /^[0-9]+$/.test(environment.GITHUB_RUN_ID || '')
  );
  if (!hosted) {
    throw new Error('REFUSING_NON_HOSTED_CONTEXT');
  }
  let config;
  try {
    config = JSON.parse(environment.WINDOWS_LAB_BOOTSTRAP);
  } catch {
    throw new Error('INVALID_BOOTSTRAP_ENCODING');
  }
  const bound = (
    config.repository === environment.GITHUB_REPOSITORY &&
    config.ref === environment.GITHUB_REF &&
    config.ref === 'refs/heads/windows-regression-lab-20261006' &&
    /^[a-f0-9]{40}$/.test(config.sha || '') &&
    config.sha === environment.GITHUB_SHA &&
    /^[a-f0-9]{64}$/.test(config.bundleSha256 || '') &&
    typeof config.authorizationQuote === 'string' &&
    config.authorizationQuote.length > 0 &&
    Number.isFinite(Date.parse(config.authorizedAt))
  );
  if (!bound) {
    throw new Error('JOB_BINDING_MISMATCH');
  }
  const remaining = Date.parse(config.expiresAt) - now;
  if (!Number.isFinite(remaining) ||
      remaining <= 0 ||
      remaining > 30 * 60 * 1000) {
    throw new Error('INVALID_SESSION_DEADLINE');
  }
  for (const name of ['hostPrivateKey', 'clientPublicKey', 'hostAccessToken', 'tunnelId', 'clusterId']) {
    if (typeof config[name] !== 'string' ||
        config[name].length === 0 ||
        config[name].length > 32768) {
      throw new Error('BOOTSTRAP_FIELD_MISSING');
    }
  }
  return config;
}

class Host {
  constructor(config, environment) {
    this.config = config;
    this.environment = environment;
    this.root = path.join(environment.RUNNER_TEMP, `windows-lab-${environment.GITHUB_RUN_ID}-1`);
    this.state = 'ready';
    this.busy = false;
    this.closed = false;
    this.finishing = false;
    this.uploadVerified = false;
    this.relay = new Relay();
    this.done = new Promise(resolve => { this.endSession = resolve; });
    this.relay.onDisconnected = () => {
      if (!this.closed) {
        this.endSession('relay-disconnected');
      }
    };
    this.server = new SingleSessionServer({
      hostKey: config.hostPrivateKey,
      clientPublicKey: config.clientPublicKey,
      onCommand: (command, channel) => this.command(command, channel),
      onDisconnected: () => this.endSession(this.finishing ? 'client-finished' : 'connection-lost')
    });
  }

  reply(channel, code, value = '') {
    if (value) {
      channel.write(value);
    }
    channel.exit(code);
    channel.end();
  }

  async command(command, channel) {
    if (command === 'status') {
      this.reply(channel, 0, JSON.stringify({
        state: this.state, sha: this.config.sha,
        runId: this.environment.GITHUB_RUN_ID,
        runAttempt: 1, expiresAt: this.config.expiresAt
      }));
      return;
    }
    if (this.busy) {
      this.reply(channel, 1, 'COMMAND_ALREADY_IN_PROGRESS');
      return;
    }
    this.busy = true;
    try {
      if (command === 'upload') {
        await this.upload(channel);
      } else if (command === 'execute') {
        await this.execute(channel);
      } else if (command === 'download') {
        await this.download(channel);
      } else if (command === 'finish') {
        this.finishing = true;
        this.reply(channel, 0, 'SESSION_CLOSING');
        setTimeout(() => this.endSession('client-finished'), 100);
      }
    } finally {
      this.busy = false;
    }
  }

  async upload(channel) {
    if (this.state !== 'ready') {
      throw new Error('UPLOAD_ALREADY_CONSUMED');
    }
    this.state = 'receiving';
    const file = path.join(this.root, 'payload.zip');
    const output = fs.createWriteStream(file, { flags: 'wx' });
    const hash = crypto.createHash('sha256');
    let size = 0;
    try {
      await new Promise((resolve, reject) => {
        let finished = false;
        const receive = chunk => {
          size += chunk.length;
          if (size > 16 * 1024 * 1024) {
            output.destroy(new Error('PAYLOAD_TOO_LARGE'));
            return;
          }
          hash.update(chunk);
          if (!output.write(chunk)) {
            channel.pause();
          }
        };
        const disconnected = () => {
          if (!finished) {
            output.destroy(new Error('UPLOAD_CHANNEL_CLOSED'));
          }
        };
        channel.on('data', receive);
        channel.once('end', () => output.end());
        channel.once('close', disconnected);
        channel.once('error', error => output.destroy(error));
        output.on('drain', () => channel.resume());
        output.once('finish', () => { finished = true; });
        output.once('error', reject);
        output.once('close', () => {
          channel.removeListener('data', receive);
          channel.removeListener('close', disconnected);
          if (finished) {
            resolve();
          }
        });
      });
      if (hash.digest('hex') !== this.config.bundleSha256) {
        throw new Error('PAYLOAD_DIGEST_MISMATCH');
      }
      this.state = 'uploaded';
      this.uploadVerified = true;
      this.reply(channel, 0, 'PAYLOAD_ACCEPTED');
    } catch (error) {
      output.destroy();
      this.state = 'failed-upload';
      throw error;
    }
  }

  childEnvironment() {
    const names = [
      'SystemRoot', 'SystemDrive', 'ComSpec', 'PATH', 'PATHEXT',
      'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData',
      'GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_SHA',
      'GITHUB_ACTOR', 'GITHUB_EVENT_NAME', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
      'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_TEMP',
      'RUNNER_TRACKING_ID', 'JAVA_HOME_21_X64'
    ];
    const environment = {};
    const normalized = new Map(Object.entries(this.environment).map(([name, value]) => [name.toUpperCase(), value]));
    for (const name of names) {
      const value = normalized.get(name.toUpperCase());
      if (typeof value === 'string') {
        environment[name] = value;
      }
    }
    const owned = {
      USERPROFILE: 'home', HOME: 'home', APPDATA: 'appdata',
      LOCALAPPDATA: 'localappdata', TEMP: 'temp', TMP: 'temp'
    };
    for (const [name, relative] of Object.entries(owned)) {
      environment[name] = path.join(this.root, relative);
      fs.mkdirSync(environment[name], { recursive: true });
    }
    environment.PRIVATE_RESULTS_DIR = path.join(this.root, 'results');
    environment.ACTUAL_RUNNER_ENVIRONMENT = 'github-hosted';
    environment.PRIVATE_JOB_BINDING = JSON.stringify({
      repository: this.config.repository,
      ref: this.config.ref,
      sha: this.config.sha,
      event: this.environment.GITHUB_EVENT_NAME,
      runId: this.environment.GITHUB_RUN_ID,
      runAttempt: 1,
      environmentKind: 'github-hosted-windows',
      bundleSha256: this.config.bundleSha256,
      expiresAt: this.config.expiresAt,
      authorizationQuote: this.config.authorizationQuote,
      authorizedAt: this.config.authorizedAt,
      privateSsh: {
        endpoint: '127.0.0.1:2222',
        gateway: `${this.config.tunnelId}.${this.config.clusterId}.devtunnels`,
        user: 'lab',
        authenticated: this.server.used
      },
      uploadedBundleVerified: this.uploadVerified
    });
    fs.mkdirSync(environment.PRIVATE_RESULTS_DIR);
    return environment;
  }

  async execute(channel) {
    if (this.state !== 'uploaded') {
      throw new Error('EXECUTION_NOT_READY');
    }
    this.state = 'executing';
    execFileSync('pwsh', [
      '-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'extract-bundle.ps1'),
      '-Archive', path.join(this.root, 'payload.zip'),
      '-Destination', path.join(this.root, 'payload')
    ], { stdio: 'pipe', timeout: 30000 });
    this.child = spawn('pwsh', [
      '-NoProfile', '-NonInteractive', '-File', path.join(this.root, 'payload', 'run.ps1')
    ], {
      cwd: path.join(this.root, 'payload'),
      env: this.childEnvironment(),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    this.child.stdout.pipe(channel, { end: false });
    this.child.stderr.pipe(channel.stderr, { end: false });
    const [code] = await once(this.child, 'close');
    this.resultCode = Number.isInteger(code) ? code : 1;
    this.state = 'executed';
    this.reply(channel, this.resultCode);
  }

  async download(channel) {
    if (this.state !== 'executed') {
      throw new Error('RESULT_NOT_READY');
    }
    const file = path.join(this.root, 'results', 'result.zip');
    const stat = fs.lstatSync(file);
    if (!stat.isFile() ||
        stat.isSymbolicLink() ||
        stat.size > 64 * 1024 * 1024) {
      throw new Error('INVALID_RESULT_ARCHIVE');
    }
    const input = fs.createReadStream(file);
    for await (const chunk of input) {
      if (!channel.write(chunk)) {
        await once(channel, 'drain');
      }
    }
    this.state = 'downloaded';
    this.reply(channel, 0);
  }

  async run() {
    execFileSync('pwsh', [
      '-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'prepare-root.ps1'),
      '-Parent', this.environment.RUNNER_TEMP,
      '-Leaf', path.basename(this.root)
    ], { stdio: 'pipe', timeout: 30000 });
    const deadline = setTimeout(() => this.endSession('deadline'), Date.parse(this.config.expiresAt) - Date.now());
    const stop = () => this.endSession('interrupted');
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
    try {
      await this.server.listen(2222);
      await this.relay.host(
        { tunnelId: this.config.tunnelId, clusterId: this.config.clusterId },
        this.config.hostAccessToken,
        this.config.relayConfiguration
      );
      console.log('Private test transport ready.');
      const reason = await this.done;
      if (reason !== 'client-finished' ||
          this.state !== 'downloaded') {
        throw new Error('SESSION_INCOMPLETE');
      }
    } finally {
      clearTimeout(deadline);
      process.removeListener('SIGTERM', stop);
      process.removeListener('SIGINT', stop);
      await this.cleanup();
    }
  }

  async cleanup() {
    this.closed = true;
    const failures = [];
    const childRunning = (
      this.child &&
      this.child.exitCode === null &&
      this.child.signalCode === null
    );
    if (childRunning) {
      try {
        execFileSync('pwsh', [
          '-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'stop-owned-tree.ps1'),
          '-ProcessId', String(this.child.pid), '-ExpectedParent', String(process.pid)
        ], { stdio: 'pipe', timeout: 30000 });
        await once(this.child, 'close');
      } catch {
        failures.push('CHILD_PROCESS_CLEANUP_FAILED');
      }
    }
    this.server.close();
    try {
      await this.relay.close();
    } catch {
      failures.push('RELAY_HOST_CLEANUP_FAILED');
    }
    if (!failures.includes('CHILD_PROCESS_CLEANUP_FAILED')) {
      try {
        fs.rmSync(this.root, { recursive: true, maxRetries: 3, retryDelay: 100 });
      } catch {
        failures.push('WORK_DIRECTORY_CLEANUP_FAILED');
      }
    }
    this.config.hostPrivateKey = null;
    this.config.hostAccessToken = null;
    if (failures.length > 0) {
      throw new Error(failures.join('_'));
    }
  }
}

if (require.main === module) {
  (async () => {
    const config = loadBootstrap(process.env);
    delete process.env.WINDOWS_LAB_BOOTSTRAP;
    const host = new Host(config, { ...process.env });
    await host.run();
    console.log('Private test transport closed.');
    if (!Number.isInteger(host.resultCode)) {
      throw new Error('TEST_EXIT_CODE_MISSING');
    }
    process.exitCode = host.resultCode;
  })().catch(error => {
    const code = /^[A-Z0-9_]{3,180}$/.test(error.message || '') ?
      error.message : 'PRIVATE_TEST_TRANSPORT_FAILED';
    console.error(code);
    process.exitCode = 1;
  });
}

module.exports = { Host, loadBootstrap };
