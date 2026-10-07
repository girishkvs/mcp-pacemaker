const fs = require('node:fs');
const path = require('node:path');
const { Controller } = require('./controller.cjs');
const { sleep } = require('./control.cjs');

class SingleAuthorizationSession {
  constructor() {
    this.authorization = {};
    this.attemptNumber = 0;
  }

  canWait(controller, error) {
    const supportedFailure = [
      'RELAY_PRECHECK_FAILED', 'RELAY_CREATION_FAILED'
    ].includes(error.message);
    const branchAttempted = controller.auditRecords.some(entry =>
      entry.phase === 'attempt' && (
        entry.endpoint?.endsWith('/git/refs') ||
        entry.operation === 'execute-approved-bundle'
      )
    );
    const cleanupPath = path.join(controller.root, 'cleanup.json');
    const cleaned = fs.existsSync(cleanupPath) &&
      JSON.parse(fs.readFileSync(cleanupPath, 'utf8')).failures.length === 0;
    return supportedFailure &&
      !branchAttempted &&
      cleaned &&
      Boolean(this.authorization.credential) &&
      this.attemptNumber < 3;
  }

  async waitForApprovedRetry(root, base) {
    const deadline = Date.now() + 10 * 60 * 1000;
    fs.writeFileSync(path.join(root, 'waiting-for-retry.json'), JSON.stringify({
      status: 'waiting-for-explicit-retry-approval',
      expiresAt: new Date(deadline).toISOString(),
      credentialRetainedInMemory: true,
      remoteWorkRunning: false,
      retryRequestFile: 'resume-request.json'
    }, null, 2), { flag: 'wx' });
    console.log('SETUP_STOPPED: cleaned up. Authorization remains in memory for ten minutes; no retry without explicit approval.');
    const requestPath = path.join(root, 'resume-request.json');
    while (Date.now() < deadline) {
      if (fs.existsSync(requestPath)) {
        const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'));
        const valid = (
          request.status === 'approved' &&
          /^[A-Za-z0-9_.-]+\.json$/.test(request.planFile || '') &&
          /^[A-Za-z0-9_.-]+\.json$/.test(request.approvalFile || '')
        );
        if (!valid) {
          throw new Error('INVALID_RETRY_REQUEST');
        }
        return {
          planPath: path.join(base, request.planFile),
          approvalPath: path.join(base, request.approvalFile)
        };
      }
      await sleep(1000);
    }
    throw new Error('AUTHORIZATION_SESSION_EXPIRED');
  }

  async run(planPath, approvalPath) {
    const base = path.dirname(path.resolve(planPath));
    try {
      while (this.attemptNumber < 3) {
        this.attemptNumber++;
        if (path.dirname(path.resolve(planPath)) !== base ||
            path.dirname(path.resolve(approvalPath)) !== base) {
          throw new Error('RETRY_FILES_OUTSIDE_TASK');
        }
        const plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
        plan.planPath = planPath;
        const approval = JSON.parse(fs.readFileSync(approvalPath, 'utf8'));
        const root = path.join(base, 'run-' + new Date().toISOString().replace(/[:.]/g, '-'));
        fs.mkdirSync(root);
        const controller = new Controller(plan, approval, root, this.authorization);
        try {
          await controller.start();
          if (!Number.isInteger(controller.testExitCode)) {
            throw new Error('TEST_EXIT_CODE_MISSING');
          }
          return controller.testExitCode;
        } catch (error) {
          if (!this.canWait(controller, error)) {
            throw error;
          }
          ({ planPath, approvalPath } = await this.waitForApprovedRetry(root, base));
        }
      }
      throw new Error('AUTHORIZED_SESSION_ATTEMPT_LIMIT');
    } finally {
      if (this.authorization.credential) {
        this.authorization.credential.token = null;
        this.authorization.credential = undefined;
      }
    }
  }
}

if (require.main === module) {
  const [planPath, approvalPath] = process.argv.slice(2);
  if (!planPath ||
      !approvalPath) {
    console.error('PLAN_AND_APPROVAL_FILES_REQUIRED');
    process.exitCode = 1;
  } else {
    new SingleAuthorizationSession().run(planPath, approvalPath)
      .then(code => { process.exitCode = code; })
      .catch(error => {
        console.error(/^[A-Z0-9_]{3,180}$/.test(error.message || '') ? error.message : 'SESSION_FAILED');
        process.exitCode = 1;
      });
  }
}

module.exports = { SingleAuthorizationSession };
