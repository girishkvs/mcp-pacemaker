export class PoolingConfigError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.name = 'PoolingConfigError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

export function poolingIOError(error) {
  if (error instanceof PoolingConfigError) return error;
  return new PoolingConfigError(500, 'IO_ERROR', 'Unable to access config transaction files.');
}

export function poolingConflict() {
  return new PoolingConfigError(409, 'REVISION_CONFLICT',
    'Config content, file identity, or permissions changed. Reread the config.');
}

export function recoveryError() {
  return new PoolingConfigError(409, 'RECOVERY_REQUIRED',
    'Config transaction state could not be verified. No recovery changes were authorized.');
}
