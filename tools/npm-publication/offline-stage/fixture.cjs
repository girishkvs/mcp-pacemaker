'use strict';
const { createHash } = require('node:crypto');
const { gzipSync } = require('node:zlib');
const sha = (bytes, algorithm = 'sha256', encoding = 'hex') =>
  createHash(algorithm).update(bytes).digest(encoding);
const stageId = '11111111-1111-1111-1111-111111111111';
function fixture(version = '1.3.1') {
  const manifest = { name: 'mcp-pacemaker', version,
    description: 'SYNTHETIC OFFLINE FIXTURE — NOT A RELEASE',
    repository: { type: 'git', url: 'git+https://github.com/girishkvs/mcp-pacemaker.git' } };
  const content = Buffer.from(JSON.stringify(manifest));
  const header = Buffer.alloc(512);
  header.write('package/package.json');
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${content.length.toString(8).padStart(11, '0')}\0`, 124);
  header.write('00000000000\0', 136);
  header.fill(32, 148, 156);
  header.write('0', 156);
  header.write('ustar\0', 257);
  header.write('00', 263);
  header.write(`${header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0')}\0 `, 148);
  const bytes = gzipSync(Buffer.concat([header, content,
    Buffer.alloc((512 - content.length % 512) % 512), Buffer.alloc(1024)]));
  const artifact = { sha256: sha(bytes), sha512: sha(bytes, 'sha512'),
    integrity: `sha512-${sha(bytes, 'sha512', 'base64')}` };
  const ref = `refs/tags/v${version}`;
  const record = { schemaVersion: 1, name: manifest.name, version,
    channel: version === '1.3.1' ? 'legacy' : 'latest',
    source: { ref, tagObject: 'a'.repeat(40), commit: 'b'.repeat(40), tree: 'c'.repeat(40) },
    workflow: { ref: `girishkvs/mcp-pacemaker/.github/workflows/npm-publish.yml@${ref}`,
      commit: 'b'.repeat(40), runId: '123', attempt: 1 },
    artifact, status: 'submitted-awaiting-owner-verification', stageId,
    ownerPreflight: { expectedDistTags: { latest: '2.0.0' } },
    authorization: { approver: 'girishkvs', scope: 'stage', approvedAt: 'SYNTHETIC' } };
  const payload = { _type: 'https://in-toto.io/Statement/v1',
    predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: `pkg:npm/mcp-pacemaker@${version}`, digest: { sha512: artifact.sha512 } }],
    predicate: { buildDefinition: {
      buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
      externalParameters: { workflow: {
        ref, repository: 'https://github.com/girishkvs/mcp-pacemaker', path: '.github/workflows/npm-publish.yml',
      } },
      resolvedDependencies: [{ uri: `git+https://github.com/girishkvs/mcp-pacemaker@${ref}`,
        digest: { gitCommit: record.source.commit } }],
      internalParameters: { github: { event_name: 'workflow_dispatch' } },
    }, runDetails: {
      builder: { id: 'https://github.com/actions/runner/github-hosted' },
      metadata: { invocationId: 'https://github.com/girishkvs/mcp-pacemaker/actions/runs/123/attempts/1' },
    } } };
  const bundleFor = payloadBytes => ({
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json', verificationMaterial: { tlogEntries: [] },
    dsseEnvelope: { payloadType: 'application/vnd.in-toto+json', payload: payloadBytes.toString('base64'),
      signatures: [{ keyid: '', sig: 'SYNTHETIC-NOT-A-SIGNATURE' }] },
  });
  const bundle = bundleFor(Buffer.from(JSON.stringify(payload)));
  const data = JSON.stringify(bundle);
  const body = { _id: manifest.name, name: manifest.name, access: 'public',
    'dist-tags': { [record.channel]: version },
    versions: { [version]: { ...manifest,
      dist: { integrity: artifact.integrity, shasum: sha(bytes, 'sha1') } } },
    _attachments: {
      [`mcp-pacemaker-${version}.tgz`]: { content_type: 'application/octet-stream',
        data: bytes.toString('base64'), length: bytes.length },
      [`mcp-pacemaker-${version}.sigstore`]: { content_type: bundle.mediaType, data, length: data.length },
    } };
  return { manifest, bytes, record, body, bundle, bundleFor, payload, sha, stageId };
}
function zip(files) {
  let offset = 0;
  const locals = [];
  const centrals = [];
  for (const [name, data] of files) {
    const path = Buffer.from(name);
    let crc = 0xffffffff;
    for (const byte of data) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(path.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(path.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, path, data);
    centrals.push(central, path);
    offset += local.length + path.length + data.length;
  }
  const localBytes = Buffer.concat(locals);
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(files.size, 8);
  end.writeUInt16LE(files.size, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  return Buffer.concat([localBytes, centralBytes, end]);
}
module.exports = { fixture, zip };
