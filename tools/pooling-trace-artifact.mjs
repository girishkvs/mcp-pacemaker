import { PoolingTraceArtifact } from '../test/helpers/pooling-trace-artifact.mjs';

try {
  const [source, destination, ...extra] = process.argv.slice(2);
  if (!source ||
      !destination ||
      extra.length) throw new Error('Expected trace input and output.');
  new PoolingTraceArtifact().publish(source, destination);
  console.log('Validated bounded pooling trace artifact; process tails are unsealed.');
} catch {
  console.error('Pooling trace validation failed; no artifact was published.');
  process.exitCode = 1;
}
