import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';

export function canonicalPort(value) {
  if (typeof value === 'number' &&
      Number.isInteger(value) &&
      value >= 1 &&
      value <= 65535) return value;
  const text = typeof value === 'string' ? value : '';
  const decimal = text.length >= 1 &&
    text.length <= 5 &&
    text[0] !== '0' &&
    [...text].every(character => character >= '0' && character <= '9');
  const port = decimal ? Number(text) : 0;
  if (!decimal ||
      port > 65535) throw new Error('Port must be a canonical decimal integer from 1 to 65535.');
  return port;
}

export function validateSelectedCommand(instance, command, options) {
  const commands = ['mcp-pacemaker', 'status', 'doctor', 'logs', 'top', 'dashboard',
    'prewarm', 'reload', 'start', 'stop', 'upgrade', 'update-check', 'emit', 'plan'];
  if (!commands.includes(command)) {
    throw new Error(`${command} is not supported with --instance. No setup, host wiring or autostart change was made.`);
  }
  if (instance.port === 0 &&
      !['mcp-pacemaker', 'status', 'logs', 'start', 'upgrade', 'update-check'].includes(command)) {
    throw new Error('Selected instance has no verified listener port; no default port was used.');
  }
  if (command === 'upgrade' &&
      !options.to &&
      !options.recover &&
      !options.self) throw new Error('Selected upgrade requires --to, --recover or --self; bare host repair is not instance-scoped.');
  const sxsPort = command === 'upgrade' && options.sxs;
  const port = options.port === undefined ? undefined : canonicalPort(options.port);
  if (options.port !== undefined &&
      !sxsPort &&
      port !== instance.port) throw new Error('--port conflicts with the selected instance.');
  if (options.config !== undefined &&
      realpathSync(resolve(options.config)) !== realpathSync(instance.config)) {
    throw new Error('--config conflicts with the selected instance.');
  }
}
