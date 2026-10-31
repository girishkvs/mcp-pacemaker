// Refusal reasons the native caller observation gives when a caller thread starts or exits while it
// runs, or an exited thread's ID is reused meanwhile. Kept apart from the product's own list so the
// tests check that list instead of reusing it.
export const THREAD_CHURN = Object.freeze(['THREAD_SET_CHANGED', 'HELD_THREAD_CHANGED_OR_EXITED',
  'THREAD_LIVENESS_CHANGED', 'THREAD_SNAPSHOT_METADATA_INVALID', 'THREAD_IDENTITY_CHANGED',
  'CONTEXT_QUERY_FAILED_87']);
