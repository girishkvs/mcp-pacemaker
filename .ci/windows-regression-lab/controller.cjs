const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { once } = require('node:events');
const { SessionIdentity, PinnedClient } = require('./identity.cjs');
const { Relay } = require('./relay.cjs');
const { DeviceLogin, GitHubApi, RelayOwner, sealSecret, sleep } = require('./control.cjs');

class Controller {
  constructor(plan, approval, root, authorizationSession = null) {
    this.plan = plan;
    this.approval = approval;
    this.root = root;
    this.repository = 'girishkvs/mcp-pacemaker';
    this.branch = 'windows-regression-lab-20261006';
    this.environment = 'windows-regression-lab-20261006';
    this.prefix = '/repos/' + this.repository;
    this.owner = new RelayOwner();
    this.relay = new Relay();
    this.auditRecords = [];
    this.authorizationSession = authorizationSession;
  }

  digest(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
  }

  audit(value) {
    this.auditRecords.push({ at: new Date().toISOString(), ...value });
    fs.writeFileSync(path.join(this.root, 'audit.json'), JSON.stringify(this.auditRecords, null, 2));
  }

  save(name, value) {
    fs.writeFileSync(path.join(this.root, name), JSON.stringify(value, null, 2), { flag: 'wx' });
  }

  credentialSnapshot() {
    const result = spawnSync('cmdkey.exe', ['/list'], { encoding: 'utf8', timeout: 10000 });
    if (result.status !== 0) {
      throw new Error('CREDENTIAL_STATE_CHECK_FAILED');
    }
    return result.stdout.split(/\r?\n/).filter(line => /girishkvs/i.test(line)).map(line => line.trim());
  }

  verifyApproval() {
    const approved = (
      this.approval.status === 'approved' &&
      this.approval.planSha256 === this.digest(fs.readFileSync(this.plan.planPath)) &&
      this.approval.repository === this.repository &&
      this.approval.branch === this.branch &&
      this.approval.environment === this.environment &&
      this.approval.createRelay === true &&
      this.approval.createBootstrapSecret === true &&
      this.approval.pushOneJob === true &&
      this.approval.runApprovedBundle === true &&
      this.approval.deleteNewEnvironmentAndRelay === true &&
      this.approval.singleCodeAuthentication === true &&
      typeof this.approval.userQuote === 'string' &&
      this.approval.userQuote.length > 0 &&
      Number.isFinite(Date.parse(this.approval.authorizedAt)) &&
      this.plan.repository === this.repository &&
      this.plan.branch === this.branch &&
      this.plan.environment === this.environment &&
      this.plan.authenticationMode === 'single-device-code' &&
      /^[a-f0-9]{40}$/.test(this.plan.baseSha || '') &&
      this.plan.maxJobMinutes === 30
    );
    if (!approved) {
      throw new Error('EXACT_SETUP_APPROVAL_REQUIRED');
    }
    for (const entry of [...this.plan.publicFiles, ...this.plan.localExecutables]) {
      if (this.digest(fs.readFileSync(entry.localPath)) !== entry.sha256) {
        throw new Error('PUBLIC_SOURCE_CHANGED');
      }
    }
    if (this.digest(fs.readFileSync(this.plan.bundlePath)) !== this.plan.bundleSha256) {
      throw new Error('PRIVATE_BUNDLE_CHANGED');
    }
  }

  claimApproval() {
    const key = this.digest(Buffer.from(JSON.stringify({
      plan: this.approval.planSha256,
      authorizedAt: this.approval.authorizedAt,
      quote: this.approval.userQuote
    })));
    this.claimPath = path.join(path.dirname(this.plan.planPath), `authorization-${key}.claim.json`);
    try {
      fs.writeFileSync(this.claimPath, JSON.stringify({ runRoot: this.root, claimedAt: new Date().toISOString() }), { flag: 'wx' });
    } catch {
      throw new Error('APPROVAL_ALREADY_CLAIMED_OR_UNAVAILABLE');
    }
  }

  async authenticate() {
    const login = new DeviceLogin();
    const reused = this.authorizationSession?.credential !== undefined;
    const github = reused ? this.authorizationSession.credential :
      await login.login(
        'repo workflow read:user',
        'Single authorization: GitHub lab and Microsoft relay'
      );
    this.owner.validateIdentityScopes(github.scopes);
    this.github = new GitHubApi(github.token, entry => this.audit(entry));
    const actor = await this.github.identity();
    this.owner.validateIdentityScopes(actor.scopes);
    if (this.authorizationSession) {
      this.authorizationSession.credential = { token: github.token, scopes: actor.scopes };
    }
    this.save('identity-verification.json', {
      login: actor.value.login, githubScopes: actor.scopes,
      authenticationMode: 'single-device-code',
      tokenRecipients: ['api.github.com', 'Microsoft Dev Tunnels authentication'],
      tokenSentToRunner: false, tokensSaved: false, reusedAuthorization: reused
    });
    console.log('Single login verified as girishkvs. Continuing the full run.');
  }

  async prepareGitCommit() {
    const repo = (await this.github.request('GET', this.prefix)).value;
    if (!repo.permissions?.admin ||
        repo.full_name !== this.repository ||
        repo.default_branch !== 'main') {
      throw new Error('REPOSITORY_OR_PERMISSION_MISMATCH');
    }
    this.repositoryId = repo.id;
    const main = (await this.github.request('GET', this.prefix + '/git/ref/heads/main')).value;
    if (main.object.sha !== this.plan.baseSha) {
      throw new Error('MAIN_CHANGED_AFTER_REVIEW');
    }
    if (await this.github.request('GET', this.prefix + '/git/ref/heads/' + this.branch, undefined, true)) {
      throw new Error('LAB_BRANCH_ALREADY_EXISTS');
    }
    if (await this.github.request('GET', this.prefix + '/environments/' + this.environment, undefined, true)) {
      throw new Error('LAB_ENVIRONMENT_ALREADY_EXISTS');
    }
    const commit = (await this.github.request('GET', this.prefix + '/git/commits/' + this.plan.baseSha)).value;
    const baseTree = (await this.github.request('GET', this.prefix + '/git/trees/' + commit.tree.sha + '?recursive=1')).value;
    if (baseTree.truncated) {
      throw new Error('BASE_TREE_TRUNCATED');
    }
    const existing = new Set(baseTree.tree.map(entry => entry.path));
    for (const entry of this.plan.publicFiles) {
      if (existing.has(entry.repositoryPath)) {
        throw new Error('LAB_PATH_ALREADY_EXISTS');
      }
    }
    const tree = (await this.github.request('POST', this.prefix + '/git/trees', {
      base_tree: commit.tree.sha,
      tree: this.plan.publicFiles.map(entry => ({
        path: entry.repositoryPath, mode: '100644', type: 'blob',
        content: fs.readFileSync(entry.localPath, 'utf8')
      }))
    })).value;
    const verifiedTree = (await this.github.request('GET', this.prefix + '/git/trees/' + tree.sha + '?recursive=1')).value;
    if (verifiedTree.truncated) {
      throw new Error('NEW_TREE_TRUNCATED');
    }
    const before = new Map(baseTree.tree.filter(entry => entry.type !== 'tree')
      .map(entry => [entry.path, [entry.mode, entry.type, entry.sha]]));
    const after = new Map(verifiedTree.tree.filter(entry => entry.type !== 'tree')
      .map(entry => [entry.path, [entry.mode, entry.type, entry.sha]]));
    const changed = [...new Set([...before.keys(), ...after.keys()])]
      .filter(name => JSON.stringify(before.get(name)) !== JSON.stringify(after.get(name)))
      .sort();
    const expected = this.plan.publicFiles.map(entry => entry.repositoryPath).sort();
    if (JSON.stringify(changed) !== JSON.stringify(expected)) {
      throw new Error('UNEXPECTED_GIT_TREE_CHANGE');
    }
    const created = (await this.github.request('POST', this.prefix + '/git/commits', {
      message: 'Add a single-session Windows regression lab',
      tree: tree.sha, parents: [this.plan.baseSha]
    })).value;
    this.commitSha = created.sha;
    this.save('prepared-commit.json', {
      sha: created.sha, baseSha: this.plan.baseSha,
      publicPaths: this.plan.publicFiles.map(entry => entry.repositoryPath)
    });
  }

  async prepareEnvironment() {
    const environment = (await this.github.request('PUT', this.prefix + '/environments/' + this.environment, {
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }
    })).value;
    this.environmentCreated = true;
    this.environmentId = environment.id;
    const observedEnvironment = (await this.github.request('GET', this.prefix + '/environments/' + this.environment)).value;
    this.save('environment-readback.json', observedEnvironment);
    if (observedEnvironment.id !== this.environmentId ||
        observedEnvironment.deployment_branch_policy?.custom_branch_policies !== true ||
        observedEnvironment.deployment_branch_policy?.protected_branches !== false) {
      throw new Error('ENVIRONMENT_RESTRICTION_MISMATCH');
    }
    await this.github.request('POST', this.prefix + '/environments/' + this.environment + '/deployment-branch-policies', {
      name: this.branch, type: 'branch'
    });
    const policy = (await this.github.request('GET', this.prefix + '/environments/' + this.environment + '/deployment-branch-policies')).value;
    this.save('branch-policy-readback.json', policy);
    if (policy.total_count !== 1 ||
        policy.branch_policies[0].name !== this.branch ||
        policy.branch_policies[0].type !== 'branch') {
      throw new Error('ENVIRONMENT_BRANCH_POLICY_MISMATCH');
    }
    await this.owner.create(this.github.token, entry => this.audit(entry));
    this.identity = new SessionIdentity();
    this.expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const bootstrap = {
      repository: this.repository,
      ref: 'refs/heads/' + this.branch,
      sha: this.commitSha,
      bundleSha256: this.plan.bundleSha256,
      authorizationQuote: this.approval.userQuote,
      authorizedAt: this.approval.authorizedAt,
      expiresAt: this.expiresAt,
      ...this.owner.reference,
      hostPrivateKey: this.identity.host.private,
      clientPublicKey: this.identity.client.public,
      hostAccessToken: this.owner.tokens.host
    };
    const secretPrefix = this.prefix + '/environments/' + this.environment + '/secrets';
    const key = (await this.github.request('GET', secretPrefix + '/public-key')).value;
    const bootstrapText = JSON.stringify(bootstrap);
    if (Buffer.byteLength(bootstrapText, 'utf8') > 32768) {
      throw new Error('BOOTSTRAP_TOO_LARGE');
    }
    const encrypted = await sealSecret(bootstrapText, key.key);
    await this.github.request('PUT', secretPrefix + '/WINDOWS_LAB_BOOTSTRAP', {
      encrypted_value: encrypted, key_id: key.key_id
    });
    const secret = (await this.github.request('GET', secretPrefix + '/WINDOWS_LAB_BOOTSTRAP')).value;
    if (secret.name !== 'WINDOWS_LAB_BOOTSTRAP') {
      throw new Error('BOOTSTRAP_SECRET_METADATA_MISMATCH');
    }
    this.save('session-public-metadata.json', {
      ...this.owner.reference, expiresAt: this.expiresAt,
      hostKeySha256: this.identity.hostHash, commitSha: this.commitSha,
      bootstrapSavedLocally: false
    });
  }

  async publish() {
    const main = (await this.github.request('GET', this.prefix + '/git/ref/heads/main')).value;
    if (main.object.sha !== this.plan.baseSha) {
      throw new Error('MAIN_CHANGED_BEFORE_PUBLISH');
    }
    await this.github.request('POST', this.prefix + '/git/refs', {
      ref: 'refs/heads/' + this.branch, sha: this.commitSha
    });
    const readback = (await this.github.request('GET', this.prefix + '/git/ref/heads/' + this.branch)).value;
    if (readback.object.sha !== this.commitSha) {
      throw new Error('BRANCH_READBACK_MISMATCH');
    }
    console.log('Created the approved lab branch. Waiting for its one Windows job.');
  }

  async findRun() {
    const query = new URLSearchParams({ head_sha: this.commitSha, branch: this.branch, event: 'push', per_page: '10' });
    const response = (await this.github.request('GET', this.prefix + '/actions/runs?' + query)).value;
    const runs = response.workflow_runs.filter(run => run.head_sha === this.commitSha);
    if (runs.length > 1) {
      throw new Error('MORE_THAN_ONE_WORKFLOW_RUN');
    }
    if (!runs.length) {
      return null;
    }
    const run = runs[0];
    if (run.path !== '.github/workflows/windows-regression-lab.yml' ||
        run.run_attempt !== 1 ||
        run.event !== 'push') {
      throw new Error('UNEXPECTED_WORKFLOW_RUN');
    }
    this.run = run;
    return run;
  }

  async waitForHost() {
    const deadline = Math.min(Date.parse(this.expiresAt), Date.now() + 10 * 60 * 1000);
    while (Date.now() < deadline) {
      const run = await this.findRun();
      if (run?.status === 'completed') {
        this.save('early-completed-run.json', run);
        throw new Error('HOST_JOB_ENDED_BEFORE_SSH');
      }
      if (run?.status === 'in_progress') {
        const tunnel = await this.relay.get(this.owner.reference, this.owner.tokens.connect);
        if (tunnel.endpoints?.length) {
          this.save('active-run.json', run);
          return;
        }
      }
      await sleep(10000);
    }
    throw new Error('HOST_READINESS_TIMEOUT');
  }

  knownSecrets() {
    return [
      this.github?.token,
      this.identity?.host?.private, this.identity?.client?.private,
      ...Object.values(this.owner.tokens || {})
    ].filter(value => typeof value === 'string');
  }

  async command(name, input, maximum = 64 * 1024 * 1024) {
    const channel = await this.ssh.open(name);
    const output = [];
    const errors = [];
    let size = 0;
    channel.on('data', data => {
      size += data.length;
      if (size > maximum) {
        channel.destroy(new Error('PRIVATE_OUTPUT_LIMIT'));
      } else {
        output.push(data);
      }
    });
    channel.stderr.on('data', data => {
      size += data.length;
      if (size > maximum) {
        channel.destroy(new Error('PRIVATE_OUTPUT_LIMIT'));
      } else {
        errors.push(data);
      }
    });
    const closed = once(channel, 'close');
    if (input) {
      channel.end(input);
    }
    const [code] = await closed;
    if (!Number.isInteger(code)) {
      throw new Error('SSH_COMMAND_OUTCOME_UNKNOWN');
    }
    return { code, output: Buffer.concat(output), errors: Buffer.concat(errors) };
  }

  safeSave(name, bytes) {
    for (const secret of this.knownSecrets()) {
      if (bytes.includes(Buffer.from(secret))) {
        throw new Error('CREDENTIAL_IN_PRIVATE_OUTPUT');
      }
    }
    fs.writeFileSync(path.join(this.root, name), bytes, { flag: 'wx' });
  }

  inspectResult(bytes) {
    const metadata = Buffer.from(JSON.stringify({ secrets: this.knownSecrets() }));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(metadata.length);
    const inspected = spawnSync('python', [
      '-I', path.join(__dirname, 'inspect-private-result.py')
    ], {
      input: Buffer.concat([length, metadata, bytes]),
      encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024
    });
    if (inspected.status !== 0) {
      throw new Error('PRIVATE_RESULT_INSPECTION_FAILED');
    }
    const report = JSON.parse(inspected.stdout);
    if (report.safe !== true) {
      throw new Error('PRIVATE_RESULT_INSPECTION_FAILED');
    }
    this.save('result-inspection.json', report);
  }

  async execute() {
    const socket = await this.relay.client(this.owner.reference, this.owner.tokens.connect);
    this.ssh = new PinnedClient(this.identity.client.private, this.identity.hostHash);
    await this.ssh.connect(socket);
    const status = await this.command('status', null, 16384);
    if (status.code !== 0) {
      throw new Error('SSH_STATUS_FAILED');
    }
    const observed = JSON.parse(status.output);
    if (observed.sha !== this.commitSha ||
        observed.runId !== String(this.run.id) ||
        observed.state !== 'ready') {
      throw new Error('SSH_HOST_JOB_MISMATCH');
    }
    this.save('private-host-verification.json', observed);
    console.log('Private SSH host key and job binding verified.');
    const uploaded = await this.command('upload', fs.readFileSync(this.plan.bundlePath), 16384);
    if (uploaded.code !== 0 ||
        uploaded.output.toString() !== 'PAYLOAD_ACCEPTED') {
      throw new Error('PRIVATE_UPLOAD_FAILED');
    }
    this.audit({ operation: 'execute-approved-bundle', phase: 'attempt', bundleSha256: this.plan.bundleSha256 });
    const executed = await this.command('execute');
    this.safeSave('test-stdout.txt', executed.output);
    this.safeSave('test-stderr.txt', executed.errors);
    this.save('test-exit.json', { code: executed.code });
    const downloaded = await this.command('download');
    if (downloaded.code !== 0) {
      throw new Error('PRIVATE_RESULT_DOWNLOAD_FAILED');
    }
    this.inspectResult(downloaded.output);
    this.safeSave('result.zip', downloaded.output);
    this.save('result-receipt.json', {
      sha256: this.digest(downloaded.output), bytes: downloaded.output.length,
      testExitCode: executed.code, runUrl: this.run.html_url
    });
    const finished = await this.command('finish', null, 16384);
    if (finished.code !== 0) {
      throw new Error('SESSION_FINISH_NOT_ACKNOWLEDGED');
    }
    this.testExitCode = executed.code;
  }

  async waitForCompletion() {
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      const run = await this.findRun();
      if (run?.status === 'completed') {
        this.save('completed-run.json', run);
        console.log('Private test job completed: ' + run.html_url);
        return run;
      }
      await sleep(5000);
    }
    throw new Error('JOB_COMPLETION_NOT_OBSERVED');
  }

  async cleanup() {
    const failures = [];
    this.ssh?.close();
    try {
      await this.relay.close();
    } catch {
      failures.push('CLIENT_RELAY_CLOSE_FAILED');
    }
    if (this.environmentCreated) {
      try {
        await this.github.request('DELETE', this.prefix + '/environments/' + this.environment);
        const remaining = await this.github.request('GET', this.prefix + '/environments/' + this.environment, undefined, true);
        if (remaining !== null) {
          throw new Error('ENVIRONMENT_REMAINS');
        }
        this.audit({ operation: 'delete-environment', phase: 'verified', name: this.environment });
      } catch {
        failures.push('ENVIRONMENT_CLEANUP_UNVERIFIED');
      }
    }
    try {
      await this.owner.delete(entry => this.audit(entry));
    } catch {
      failures.push('TUNNEL_CLEANUP_UNVERIFIED');
    }
    this.identity?.discard();
    this.github?.discard();
    const credentialsAfter = this.credentialSnapshot();
    this.save('credential-after.json', credentialsAfter);
    if (JSON.stringify(credentialsAfter) !== JSON.stringify(this.credentialsBefore)) {
      failures.push('CREDENTIAL_STATE_CHANGED');
    }
    this.save('cleanup.json', { failures, credentialsSavedLocally: false });
    const mutationAttempted = this.auditRecords.some(entry => entry.phase === 'attempt');
    if (!mutationAttempted &&
        this.claimPath) {
      const claim = JSON.parse(fs.readFileSync(this.claimPath, 'utf8'));
      if (claim.runRoot !== this.root) {
        throw new Error('LOCAL_APPROVAL_CLAIM_CHANGED');
      }
      fs.unlinkSync(this.claimPath);
    }
    if (failures.length) {
      throw new Error(failures.join('_'));
    }
  }

  async start() {
    this.verifyApproval();
    this.claimApproval();
    this.credentialsBefore = this.credentialSnapshot();
    this.save('credential-before.json', this.credentialsBefore);
    try {
      await this.authenticate();
      await this.prepareGitCommit();
      await this.prepareEnvironment();
      await this.publish();
      await this.waitForHost();
      await this.execute();
      await this.waitForCompletion();
    } catch (error) {
      const code = /^[A-Z0-9_]{3,180}$/.test(error.message || '') ? error.message : 'CONTROLLER_FAILED';
      this.save('failure.json', { at: new Date().toISOString(), code });
      throw new Error(code);
    } finally {
      await this.cleanup();
    }
  }
}

if (require.main === module) {
  (async () => {
    const [planPath, approvalPath] = process.argv.slice(2);
    if (!planPath ||
        !approvalPath) {
      throw new Error('PLAN_AND_APPROVAL_FILES_REQUIRED');
    }
    const plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
    plan.planPath = planPath;
    const approval = JSON.parse(fs.readFileSync(approvalPath, 'utf8'));
    const root = path.join(path.dirname(planPath), 'run-' + new Date().toISOString().replace(/[:.]/g, '-'));
    fs.mkdirSync(root);
    const controller = new Controller(plan, approval, root);
    await controller.start();
    process.exitCode = controller.testExitCode;
  })().catch(error => {
    console.error(/^[A-Z0-9_]{3,180}$/.test(error.message || '') ? error.message : 'CONTROLLER_FAILED');
    process.exitCode = 1;
  });
}

module.exports = { Controller };
