import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MANIFEST_FILE, NOTICE_FILE, verifyArtifacts } from './inventory.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

export async function checkNotices(root = ROOT) {
  verifyArtifacts(root);
  const ui = path.join(root, 'ui');
  const require = createRequire(path.join(ui, 'package.json'));
  let vite;
  try {
    vite = await import(pathToFileURL(require.resolve('vite')).href);
  } catch {
    throw new Error('Exact UI producer dependencies are required; restore with npm --prefix ui ci');
  }
  const previousDirectory = process.cwd();
  let result;
  try {
    process.chdir(ui);
    result = await vite.build({
      root: ui,
      configFile: path.join(ui, 'vite.config.ts'),
      logLevel: 'error',
      build: { write: false },
    });
  } finally {
    process.chdir(previousDirectory);
  }
  if (Array.isArray(result) ||
      !Array.isArray(result.output)) {
    throw new Error('Unexpected Vite build output');
  }
  for (const output of result.output) {
    const bytes = Buffer.from(output.type === 'chunk' ? output.code : output.source);
    const existing = fs.readFileSync(path.join(ui, 'dist', output.fileName));
    if (!bytes.equals(existing)) {
      throw new Error(`Rebuilt UI/notices differ: ${output.fileName}; run npm --prefix ui run build`);
    }
  }
  const files = result.output.map(({ fileName }) => fileName);
  if (!files.includes(NOTICE_FILE) ||
      !files.includes(MANIFEST_FILE)) {
    throw new Error('The UI build did not generate third-party notices');
  }
  return verifyArtifacts(root);
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    const unknownArgument = args.length === 1 && args[0] !== '--artifact-only';
    if (args.length > 1 ||
        unknownArgument) {
      throw new Error('Usage: node tools/third-party-notices/check.mjs [--artifact-only]');
    }
    const manifest = args[0] === '--artifact-only' ? verifyArtifacts(ROOT) : await checkNotices();
    console.log(`Notices verified: ${manifest.packages.length} bundled packages, ${manifest.runtimeNotices.length} runtime supplements, ${manifest.chunks.length} chunks`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
