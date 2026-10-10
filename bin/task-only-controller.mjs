import { isDeepStrictEqual } from 'node:util';
import { dirname } from 'node:path';
import { durableJson } from './managed-state.mjs';
import { canonicalJson, ControllerSignatures, operationDigest, peerBinding, taskRevision, validateTaskRequest, verifyTargetSession } from './task-transaction-protocol.mjs';
import { authorizeTaskActor } from './task-scope.mjs';
import { LEGACY_WARNING } from './legacy-installation.mjs';

export function workerTaskRecord(record, targetSid) {
  return { ...record, currentUserSid: targetSid };
}

export function minimalTaskRecord(record) {
  return {
    name: record.name, enabled: record.enabled, user: record.runAsName ?? record.userSid,
    logonType: record.logonType, runLevel: record.runLevel, actions: record.actions,
  };
}

export class TaskOnlyController {
  constructor({ binding, original, initial = original, task, channel,
    signatures = new ControllerSignatures(), confirm, journalPath }) {
    this.binding = structuredClone(binding);
    this.original = structuredClone(original);
    this.current = structuredClone(initial);
    this.initial = structuredClone(initial);
    this.task = task;
    this.channel = channel;
    this.targetSession = verifyTargetSession(channel.targetSession, { ownerSid: binding.targetSid, sessionId: binding.sessionId });
    this.signatures = signatures;
    this.confirm = confirm;
    this.journalPath = journalPath;
    this.sequence = 0;
    this.phase = 'new';
    this.digest = operationDigest(binding);
    this.stateDigest = this.digest;
    this.history = [];
  }

  save(phase) {
    this.phase = phase;
    this.stateDigest = operationDigest({ operationId: this.binding.operationId, phase, sequence: this.sequence,
      taskRevision: taskRevision(this.current) });
    if (this.journalPath) durableJson(this.journalPath, {
      protocol: 1, binding: this.binding, original: this.original, initial: this.initial, current: this.current,
      phase, sequence: this.sequence, stateDigest: this.stateDigest, history: this.history, peer: this.peer ?? null,
      targetSession: this.targetSession,
    });
  }

  async verifyTask() {
    const result = await this.channel.authorize();
    authorizeTaskActor(result.actorFacts, this.binding.targetSid);
    this.targetSession = verifyTargetSession(result.targetSession, this.targetSession);
    const actual = (await this.task.inspect()).record;
    if (taskRevision(actual) !== taskRevision(this.current)) throw new Error('Approved task revision or full security changed.');
    return actual;
  }

  assertPreserved(record) {
    if (record.path !== this.original.path ||
        record.userSid !== this.binding.targetSid ||
        record.logonType !== this.original.logonType ||
        record.runLevel !== this.original.runLevel ||
        !isDeepStrictEqual(record.security, this.original.security)) throw new Error('Task operation changed its sealed account or full security.');
  }

  async mutate(action, phase) {
    await this.verifyTask();
    this.save(`${phase}-intent`);
    const args = [this.current, this.original];
    if (action === 'bootstrap') args.push(this.binding.bootstrapTask);
    if (action === 'repoint') args.push(this.binding.launcher);
    const result = await this.task[action](...args);
    this.assertPreserved(result);
    this.current = result;
    this.history.push({ phase, revision: taskRevision(result) });
    if (this.history.length > 16) throw new Error('Task transaction exceeded its transition bound.');
    this.save(phase);
  }

  async restoreInitial(phase) {
    try {
      await this.verifyTask();
      this.save(`${phase}-intent`);
      const restored = await this.task.restore(this.current, this.initial);
      this.assertPreserved(restored);
      if (taskRevision(restored) !== taskRevision(this.initial)) throw new Error('Pre-bootstrap task revision was not restored exactly.');
      this.current = restored;
      this.save(phase);
    } catch (error) {
      const evidence = this.journalPath ? dirname(this.journalPath) : this.binding.manifestPath;
      throw new Error(`Automatic task restoration did not verify. Preserve the protected manifest and controller journal at ${JSON.stringify(evidence)}. ` +
        `Manual verified restoration of ${JSON.stringify(this.initial.path)} to its saved pre-bootstrap revision is required. ` +
        'There is no controller-operation-only recovery command: without a published instance, --instance cannot recover this state, and --task --recover is unsupported. ' +
        'Do not create target state or relax task security/session checks. ' + error.message, { cause: error });
    }
  }

  async accept(packet) {
    if (canonicalJson(peerBinding(packet.peer)) !== canonicalJson(this.peer)) throw new Error('Worker connection identity changed.');
    const request = validateTaskRequest(packet.frame, this.binding.operationId, this.sequence,
      this.sequence === 0 ? this.digest : this.stateDigest);
    let body;
    switch (request.verb) {
      case 'HELLO':
        if (this.phase !== 'bootstrap' ||
            canonicalJson(peerBinding(request.body.identity)) !== canonicalJson(this.peer)) throw new Error('Worker hello does not match its held OS identity.');
        this.challenge = request.body.challenge;
        await this.verifyTask();
        this.save('authenticated');
        body = { ok: true, original: workerTaskRecord(this.original, this.binding.targetSid) };
        break;
      case 'PLAN': {
        if (this.phase !== 'authenticated') throw new Error('Plan approval cannot be repeated.');
        const message = [
          `Approve ${this.binding.recover ? 'recovery' : 'upgrade'} for the sealed task ${JSON.stringify(this.binding.taskPath)}?`,
          `Original account: ${this.binding.targetSid}; port ${this.binding.port}; ${JSON.stringify(this.binding.from)} -> ${JSON.stringify(this.binding.to)}.`,
          this.binding.kind === 'legacy' ? LEGACY_WARNING : 'Managed admission and verified shutdown remain required.',
          `Worker plan digest: ${request.body.digest}`,
        ].join('\n');
        const approved = await this.confirm(message);
        if (approved !== true) {
          await this.restoreInitial('cancelled');
          this.result = { status: 'cancelled', directory: this.binding.destination, port: this.binding.port };
          body = { approved: false, digest: request.body.digest };
          break;
        }
        await this.verifyTask();
        this.approvedPlan = request.body.digest;
        this.save('approved');
        body = { approved: true, digest: request.body.digest };
        break;
      }
      case 'INSPECT':
        await this.verifyTask();
        body = { record: workerTaskRecord(this.current, this.binding.targetSid), phase: this.phase };
        break;
      case 'HOLD':
        if (!['approved', 'held', 'selected', 'released'].includes(this.phase)) throw new Error('Task hold is not authorized in this phase.');
        if (this.phase === 'approved' || this.phase === 'held') {
          await this.verifyTask();
          this.save('held');
        } else await this.mutate('hold', 'held');
        body = { record: workerTaskRecord(this.current, this.binding.targetSid), holdKind: 'automatic-triggers' };
        break;
      case 'REPOINT':
        if (this.phase !== 'held') throw new Error('Managed task selection requires a verified hold.');
        await this.mutate('repoint', 'selected');
        body = { record: workerTaskRecord(this.current, this.binding.targetSid) };
        break;
      case 'ENABLE':
        if (this.phase !== 'selected') throw new Error('Task release requires the sealed managed launcher.');
        await this.mutate('release', 'released');
        body = { record: workerTaskRecord(this.current, this.binding.targetSid) };
        break;
      case 'RESTORE':
        if (!['authenticated', 'approved', 'held', 'selected', 'released'].includes(this.phase)) throw new Error('Task restoration outcome is uncertain.');
        await this.mutate('restore', 'restored');
        body = { record: workerTaskRecord(this.current, this.binding.targetSid) };
        break;
      case 'RECORDS':
        await this.verifyTask();
        body = { records: [minimalTaskRecord(this.current)] };
        break;
      case 'DONE':
        if (!['released', 'restored'].includes(this.phase) ||
            request.body.directory !== this.binding.destination ||
            request.body.port !== this.binding.port ||
            ![this.binding.to, this.binding.from].includes(request.body.version)) throw new Error('Completion is outside the sealed installation.');
        await this.verifyTask();
        this.result = request.body;
        this.save('completed');
        body = { accepted: true };
        break;
      case 'FAILED':
        if (['authenticated', 'approved'].includes(this.phase)) await this.restoreInitial('restored');
        this.failure = new Error(`Original-account worker failed; ${this.phase === 'restored' ? 'original task restored' : 'explicit recovery required'}.`);
        this.save(this.phase === 'restored' ? 'failed-restored' : 'uncertain');
        body = { accepted: true };
        break;
      default: throw new Error('Unsupported task request.');
    }
    const response = this.signatures.response({
      operationId: this.binding.operationId, digest: this.digest, challenge: this.challenge, peer: this.peer,
      targetSession: this.targetSession,
      sequence: this.sequence, request, stateDigest: this.stateDigest, body,
    });
    this.sequence++;
    return response;
  }

  async run() {
    let authenticated = false;
    try {
      await this.mutate('bootstrap', 'bootstrap');
      await this.verifyTask();
      const launch = await this.task.launch(this.current, this.binding.sessionId);
      this.launchCorrelation = launch.instanceGuid;
      this.peer = peerBinding(await this.channel.awaitWorker());
      this.targetSession = verifyTargetSession(this.channel.workerSession, this.targetSession);
      if (this.peer.ownerSid !== this.binding.targetSid ||
          this.peer.sessionId !== this.binding.sessionId) throw new Error('Worker account/session did not verify.');
      while (!this.result && !this.failure) {
        const packet = await this.channel.receive();
        const response = await this.accept(packet);
        await this.channel.send(response);
        authenticated = Boolean(this.challenge);
      }
      if (this.failure) throw this.failure;
      return this.result;
    } catch (error) {
      let failure = error;
      if (!authenticated && this.phase === 'bootstrap') {
        try { await this.restoreInitial('restored-bootstrap'); }
        catch (restoreError) {
          this.save('uncertain');
          failure = new AggregateError([error, restoreError], restoreError.message);
        }
      } else if (!['completed', 'failed-restored', 'restored', 'cancelled'].includes(this.phase)) this.save('uncertain');
      throw failure;
    } finally {
      this.signatures.key = undefined;
      await this.channel.close();
    }
  }
}
