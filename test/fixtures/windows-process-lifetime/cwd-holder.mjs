// TEST-ONLY working-directory holder. Starts the real packaged lifetime helper while this
// process is inside the owned directory, then leaves that directory itself so the only possible
// remaining holder is the native helper.
import { ensureWindowsProcessLifetime } from '../../../bin/windows-process-lifetime.mjs';

const [owned, elsewhere] = process.argv.slice(2);
process.chdir(owned);
const lifetime = await ensureWindowsProcessLifetime();
process.chdir(elsewhere);
process.send({ type: 'ready', lifetime, cwd: process.cwd() });
setInterval(() => {}, 1000);
