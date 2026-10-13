import { PassThrough } from 'node:stream';

process.env.CI = '0';
process.env.CONTINUOUS_INTEGRATION = '0';
Object.defineProperty(process.stdout, 'isTTY', { value: true });
process.stdout.columns = 120;
process.stdout.rows = 40;
process.stdout.getWindowSize = () => [120, 40];
const input = new PassThrough();
input.isTTY = true;
input.setRawMode = () => input;
input.ref = () => input;
input.unref = () => input;
Object.defineProperty(process, 'stdin', { value: input });
const write = process.stdout.write;
let recycled = false;
let quitting = false;
const deadline = setTimeout(() => { console.error('Owned TUI key exercise timed out.'); process.exit(1); }, 15000);
process.stdout.write = function (chunk, ...args) {
  const result = write.call(this, chunk, ...args);
  const text = String(chunk);
  if (!recycled &&
      text.includes('alpha')) {
    recycled = true;
    setImmediate(() => input.write('r'));
  }
  if (!quitting &&
      (text.includes('recycled alpha') || text.includes('recycle failed'))) {
    quitting = true;
    if (text.includes('recycle failed')) process.exitCode = 1;
    clearTimeout(deadline);
    setImmediate(() => input.write('q'));
  }
  return result;
};
