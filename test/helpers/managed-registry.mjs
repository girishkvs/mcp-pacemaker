import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const retained = fileURLToPath(new URL('../../', import.meta.url));

function archiveDirectory(root) {
  const entries = [];
  const walk = (relative = '') => {
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true })) {
      if (entry.name === 'node_modules' ||
          entry.name === '.bin') continue;
      const path = relative + entry.name;
      if (entry.isDirectory()) { walk(`${path}/`); continue; }
      if (!entry.isFile()) throw new Error('Retained registry fixture cannot pack links.');
      const data = readFileSync(join(root, path));
      const header = Buffer.alloc(512);
      let name = `package/${path}`;
      if (Buffer.byteLength(name) > 100) {
        const slash = name.lastIndexOf('/');
        const prefix = name.slice(0, slash);
        name = name.slice(slash + 1);
        if (Buffer.byteLength(prefix) > 155 ||
            Buffer.byteLength(name) > 100) throw new Error('Retained tar fixture path exceeds ustar limits.');
        header.write(prefix, 345);
      }
      header.write(name);
      header.write('0000644\0', 100);
      header.write('0000000\0', 108);
      header.write('0000000\0', 116);
      header.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
      header.write('00000000000\0', 136);
      header.fill(32, 148, 156);
      header.write('0', 156);
      header.write('ustar\0', 257);
      header.write('00', 263);
      header.write([...header].reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148);
      entries.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
    }
  };
  walk();
  entries.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(entries));
}

export async function retainedRegistry(candidate, version) {
  const lock = JSON.parse(readFileSync(join(retained, 'package-lock.json'), 'utf8'));
  const packages = new Map();
  const archives = new Map();
  const requests = [];
  let base;
  const add = (pkg, bytes) => {
    const id = String(archives.size);
    archives.set(id, bytes);
    packages.set(pkg.name, { pkg, id, integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}` });
  };
  for (const path of Object.keys(lock.packages)) {
    if (!path) continue;
    const root = join(retained, path);
    add(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')), archiveDirectory(root));
  }
  add({ ...JSON.parse(readFileSync(join(retained, 'package.json'), 'utf8')), version }, candidate.bytes);
  const server = createServer((request, response) => {
    requests.push(request.url);
    const path = decodeURIComponent(new URL(request.url, base).pathname.slice(1));
    if (path.startsWith('archives/')) {
      const bytes = archives.get(path.slice('archives/'.length));
      if (!bytes) { response.writeHead(404).end(); return; }
      response.end(bytes);
      return;
    }
    const item = packages.get(path);
    if (!item) { response.writeHead(404).end(); return; }
    const { pkg, id, integrity } = item;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({
      name: pkg.name, 'dist-tags': { latest: pkg.version },
      time: { [pkg.version]: '2020-01-01T00:00:00.000Z' },
      versions: { [pkg.version]: { ...pkg, dist: { tarball: `${base}archives/${id}`, integrity } } },
    }));
  });
  await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
  base = `http://127.0.0.1:${server.address().port}/`;
  return {
    url: base, requests,
    close: () => new Promise(resolveClose => server.close(resolveClose)),
  };
}
