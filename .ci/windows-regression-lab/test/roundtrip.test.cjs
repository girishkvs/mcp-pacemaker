const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const { once } = require('node:events');
const { test } = require('node:test');
const { SessionIdentity, PinnedClient } = require('../identity.cjs');
const { Host } = require('../host.cjs');

test('synthetic script upload, execution and result download use one SSH session', async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-roundtrip-test-'));
  const archive = path.join(parent, 'input.zip');
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$file = Join-Path $env:PRIVATE_RESULTS_DIR 'canary.txt'",
    "Set-Content -LiteralPath $file -Value 'synthetic-private-result'",
    "Compress-Archive -LiteralPath $file -DestinationPath (Join-Path $env:PRIVATE_RESULTS_DIR 'result.zip')",
    "Write-Output 'synthetic-private-stdout'",
    "[Console]::Error.WriteLine('synthetic-private-stderr')",
    'exit 0'
  ].join('\n');
  const made = spawnSync('python', ['-c',
    'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("run.ps1",sys.argv[2]); z.close()',
    archive, script
  ], { encoding: 'utf8' });
  assert.equal(made.status, 0);
  const input = fs.readFileSync(archive);
  const identity = new SessionIdentity();
  const host = new Host({
    hostPrivateKey: identity.host.private,
    clientPublicKey: identity.client.public,
    bundleSha256: crypto.createHash('sha256').update(input).digest('hex')
  }, { ...process.env, RUNNER_TEMP: parent, GITHUB_RUN_ID: '123' });
  const client = new PinnedClient(identity.client.private, identity.hostHash);
  fs.mkdirSync(host.root);
  const command = async (name, bytes) => {
    const channel = await client.open(name);
    const output = [];
    const error = [];
    channel.on('data', chunk => output.push(chunk));
    channel.stderr.on('data', chunk => error.push(chunk));
    const closed = once(channel, 'close');
    if (bytes) {
      channel.end(bytes);
    }
    const [code] = await closed;
    return { code, output: Buffer.concat(output), error: Buffer.concat(error) };
  };
  try {
    const port = await host.server.listen(0);
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    await client.connect(socket);
    assert.equal((await command('upload', input)).code, 0);
    const executed = await command('execute');
    assert.equal(executed.code, 0, executed.error.toString());
    assert.match(executed.output.toString(), /synthetic-private-stdout/);
    assert.match(executed.error.toString(), /synthetic-private-stderr/);
    const repeated = await command('execute');
    assert.equal(repeated.code, 1);
    const downloaded = await command('download');
    assert.equal(downloaded.code, 0);
    assert.equal(downloaded.output.subarray(0, 2).toString(), 'PK');
    assert.equal(host.state, 'downloaded');
    assert.equal((await command('finish')).code, 0);
  } finally {
    client.close();
    host.server.close();
    await host.relay.close();
    identity.discard();
    fs.rmSync(parent, { recursive: true });
  }
});

test('private archive inspection rejects credential material before saving bytes', () => {
  const scanner = path.join(__dirname, '..', 'inspect-private-result.py');
  for (const sensitive of [false, true]) {
    const generated = spawnSync('python', ['-I', '-c',
      'import io,sys,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED); z.writestr("result.txt",sys.argv[1]); z.close(); sys.stdout.buffer.write(b.getvalue())',
      sensitive ? 'synthetic-credential-marker' : 'synthetic-result'
    ]);
    assert.equal(generated.status, 0);
    const metadata = Buffer.from(JSON.stringify({ secrets: ['synthetic-credential-marker'] }));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(metadata.length);
    const checked = spawnSync('python', ['-I', scanner], {
      input: Buffer.concat([length, metadata, generated.stdout]),
      encoding: 'utf8'
    });
    assert.equal(checked.status === 0, !sensitive);
    assert.equal(JSON.parse(checked.stdout).safe, !sensitive);
    assert.equal(checked.stdout.includes('synthetic-credential-marker'), false);
  }
});
