const crypto = require('node:crypto');
const { Client, Server, utils } = require('ssh2');

class SessionIdentity {
  constructor() {
    this.host = utils.generateKeyPairSync('ed25519');
    this.client = utils.generateKeyPairSync('ed25519');
    const parsed = utils.parseKey(this.host.public);
    if (parsed instanceof Error) {
      throw new Error('HOST_KEY_GENERATION_FAILED');
    }
    this.hostHash = crypto.createHash('sha256').update(parsed.getPublicSSH()).digest('hex');
  }

  discard() {
    this.host = null;
    this.client = null;
  }
}

class SingleSessionServer {
  constructor({ hostKey, clientPublicKey, onCommand, onDisconnected }) {
    this.authorizedKey = utils.parseKey(clientPublicKey);
    if (this.authorizedKey instanceof Error) {
      throw new Error('INVALID_AUTHORIZED_KEY');
    }
    this.authorizedBytes = this.authorizedKey.getPublicSSH();
    this.onCommand = onCommand;
    this.onDisconnected = onDisconnected;
    this.used = false;
    this.listening = false;
    this.connections = new Set();
    this.server = new Server({ hostKeys: [hostKey] }, connection => this.accept(connection));
  }

  accept(connection) {
    this.connections.add(connection);
    connection.on('error', () => connection.end());
    connection.on('close', () => {
      this.connections.delete(connection);
      if (this.active === connection) {
        this.onDisconnected?.();
      }
    });
    connection.on('authentication', context => {
      const eligible = (
        !this.used &&
        context.method === 'publickey' &&
        context.username === 'lab' &&
        context.key.data.length === this.authorizedBytes.length &&
        crypto.timingSafeEqual(context.key.data, this.authorizedBytes)
      );
      if (!eligible) {
        context.reject(['publickey']);
        return;
      }
      if (!context.signature) {
        context.accept();
        return;
      }
      const verified = this.authorizedKey.verify(
        context.blob, context.signature, context.hashAlgo
      );
      if (verified !== true) {
        context.reject(['publickey']);
        return;
      }
      this.used = true;
      context.accept();
    });
    connection.on('ready', () => {
      this.active = connection;
      this.stopListening();
      for (const other of this.connections) {
        if (other !== connection) {
          other.end();
        }
      }
      connection.on('session', accept => {
        const session = accept();
        session.on('exec', (acceptCommand, rejectCommand, info) => {
          if (!['status', 'upload', 'execute', 'download', 'finish'].includes(info.command)) {
            rejectCommand();
            return;
          }
          const channel = acceptCommand();
          Promise.resolve(this.onCommand(info.command, channel)).catch(() => {
            channel.stderr.write('SESSION_COMMAND_FAILED\n');
            channel.exit(1);
            channel.end();
          });
        });
      });
    });
  }

  async listen(port = 2222) {
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(port, '127.0.0.1', () => {
        this.listening = true;
        resolve();
      });
    });
    return this.server.address().port;
  }

  close() {
    for (const connection of this.connections) {
      connection.end();
    }
    this.stopListening();
  }

  stopListening() {
    if (!this.listening) {
      return;
    }
    this.listening = false;
    this.server.close();
  }
}

class PinnedClient {
  constructor(privateKey, hostHash) {
    if (!/^[a-f0-9]{64}$/.test(hostHash)) {
      throw new Error('INVALID_HOST_KEY_PIN');
    }
    this.privateKey = privateKey;
    this.hostHash = hostHash;
    this.client = new Client();
    this.failure = null;
    this.hostKeyMatches = null;
    this.client.on('error', error => {
      this.failure = this.hostKeyMatches === false ?
        new Error('SSH_HOST_KEY_MISMATCH') : error;
      this.socket?.destroy();
    });
    this.connectedOnce = false;
  }

  async connect(socket) {
    if (this.connectedOnce) {
      throw new Error('SESSION_RECONNECT_NOT_PERMITTED');
    }
    this.connectedOnce = true;
    this.socket = socket;
    await new Promise((resolve, reject) => {
      const failed = error => reject(this.failure || error);
      const ready = () => {
        this.client.removeListener('error', failed);
        resolve();
      };
      this.client.once('ready', ready);
      this.client.once('error', failed);
      this.client.connect({
        sock: socket,
        username: 'lab',
        privateKey: this.privateKey,
        hostHash: 'sha256',
        hostVerifier: value => {
          this.hostKeyMatches = value === this.hostHash;
          return this.hostKeyMatches;
        },
        readyTimeout: 20000,
        keepaliveInterval: 10000,
        keepaliveCountMax: 2
      });
    });
  }

  open(command) {
    if (this.failure) {
      return Promise.reject(this.failure);
    }
    if (!['status', 'upload', 'execute', 'download', 'finish'].includes(command)) {
      return Promise.reject(new Error('COMMAND_NOT_PERMITTED'));
    }
    return new Promise((resolve, reject) => {
      this.client.exec(command, (error, channel) => {
        if (error) {
          reject(error);
        } else {
          resolve(channel);
        }
      });
    });
  }

  close() {
    this.client.end();
    this.socket?.destroy();
    this.privateKey = null;
  }
}

module.exports = { SessionIdentity, SingleSessionServer, PinnedClient };
