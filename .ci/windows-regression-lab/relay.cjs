const {
  ManagementApiVersions,
  TunnelManagementHttpClient
} = require('@microsoft/dev-tunnels-management');
const {
  TunnelAccessScopes,
  TunnelProtocol
} = require('@microsoft/dev-tunnels-contracts');
const {
  TunnelRelayTunnelClient,
  TunnelRelayTunnelHost
} = require('@microsoft/dev-tunnels-connections');
const { CancellationTokenSource } = require('vscode-jsonrpc');

const connectionOptions = Object.freeze({
  enableRetry: false,
  enableReconnect: false,
  keepAliveIntervalInSeconds: 10
});

class Relay {
  constructor() {
    this.manager = new TunnelManagementHttpClient(
      { name: 'windows-regression-lab', version: '0.0.0' },
      ManagementApiVersions.Version20230927preview
    );
    this.manager.enableEventsReporting = false;
  }

  validate(tunnel, reference) {
    const correct = (
      tunnel &&
      tunnel.tunnelId === reference.tunnelId &&
      tunnel.clusterId === reference.clusterId &&
      Array.isArray(tunnel.ports) &&
      tunnel.ports.length === 1 &&
      tunnel.ports[0].portNumber === 2222 &&
      tunnel.ports[0].protocol === TunnelProtocol.Auto
    );
    if (!correct) {
      throw new Error('TUNNEL_BINDING_MISMATCH');
    }
    const controls = [tunnel.accessControl, tunnel.ports[0].accessControl];
    if (!Array.isArray(tunnel.accessControl?.entries)) {
      throw new Error('TUNNEL_ACCESS_CONTROL_MISSING');
    }
    for (const control of controls) {
      for (const entry of control?.entries || []) {
        if (entry.isDeny !== true) {
          throw new Error('EXPLICIT_TUNNEL_ACCESS_GRANT_NOT_PERMITTED');
        }
      }
    }
  }

  async read(reference, options, manager = this.manager) {
    try {
      return await manager.getTunnel(reference, options);
    } catch (error) {
      if (error?.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  async get(reference, token) {
    const tunnel = await this.read(reference, {
      accessToken: token,
      includePorts: true,
      includeAccessControl: true
    });
    if (tunnel === null) {
      throw new Error('RELAY_NOT_FOUND');
    }
    this.validate(tunnel, reference);
    return tunnel;
  }

  async host(reference, token) {
    const tunnel = await this.get(reference, token);
    tunnel.accessTokens = { [TunnelAccessScopes.Host]: token };
    this.connection = new TunnelRelayTunnelHost(this.manager);
    this.connection.enableE2EEncryption = true;
    this.connection.forwardConnectionsToLocalPorts = true;
    this.connection.connectionStatusChanged(event => {
      if (event.status === 'disconnected') {
        this.onDisconnected?.();
      }
    });
    await this.connect(tunnel);
  }

  async client(reference, token) {
    const tunnel = await this.get(reference, token);
    tunnel.accessTokens = { [TunnelAccessScopes.Connect]: token };
    this.connection = new TunnelRelayTunnelClient(this.manager);
    this.connection.enableE2EEncryption = true;
    this.connection.acceptLocalConnectionsForForwardedPorts = false;
    this.connection.portForwarding(event => {
      event.cancel = event.portNumber !== 2222;
    });
    await this.connect(tunnel, true);
    const cancellation = new CancellationTokenSource();
    const timer = setTimeout(() => cancellation.cancel(), 30000);
    try {
      await this.connection.waitForForwardedPort(2222, cancellation.token);
      return await this.connection.connectToForwardedPort(2222, cancellation.token);
    } finally {
      clearTimeout(timer);
      cancellation.dispose();
    }
  }

  async connect(tunnel, retryInitialConnection = false) {
    const cancellation = new CancellationTokenSource();
    const timer = setTimeout(() => cancellation.cancel(), 45000);
    try {
      await this.connection.connect(tunnel, {
        ...connectionOptions,
        enableRetry: retryInitialConnection
      }, cancellation.token);
    } finally {
      clearTimeout(timer);
      cancellation.dispose();
    }
  }

  async close() {
    if (this.connection) {
      await this.connection.dispose();
    }
    await this.manager.dispose();
  }
}

module.exports = { Relay, connectionOptions };
