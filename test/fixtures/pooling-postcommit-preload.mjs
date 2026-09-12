import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { PostCommitFault } from './pooling-postcommit-fault.mjs';

if (!isMainThread &&
    workerData?.kind === 'mcp-pooling-writer') {
  const fault = new PostCommitFault(workerData.configPath, {
    commit: 2, realExpiry: process.env.MCP_TEST_POSTCOMMIT_EXPIRY === '1',
  });
  fault.install();
  const post = parentPort.postMessage;
  parentPort.postMessage = function (message, ...rest) {
    if (fault.placed &&
        message.error) {
      post.call(this, {
        postcommitTestEvidence: true, expiredAfterPlacement: fault.expiredAfterPlacement ?? false,
        code: message.error.code, commitState: message.error.commitState,
        helperResults: fault.helperResults,
      });
    }
    return post.call(this, message, ...rest);
  };
} else if (isMainThread) {
  const emit = Worker.prototype.emit;
  Worker.prototype.emit = function (event, ...args) {
    if (event === 'message' &&
        args[0]?.postcommitTestEvidence) process.send?.(args[0]);
    return emit.call(this, event, ...args);
  };
}
