import { open, lstat } from 'node:fs/promises';
import { constants, watch } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setImmediate as yieldTurn } from 'node:timers/promises';

const CHUNK_BYTES = 64 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;
const ANCHOR_BYTES = 256;

class LogReader {
  constructor(options) {
    this.options = options;
    this.output = options.stdout ?? process.stdout;
    this.diagnostics = options.stderr ?? process.stderr;
    this.controller = new AbortController();
    this.signal = this.controller.signal;
    this.failure = null;
    this.wake = null;
    this.handles = new Set();
    this.outputs = new Map();
    this.finished = false;
    this.since = this.parseSince(options.since);
    this.grep = options.grep?.toLowerCase() ?? '';
    this.path = resolve(dirname(resolve(options.config ?? resolve(homedir(), '.mcp-pacemaker', 'servers.json'))), 'bridge.log');
    this.interval = options.pollIntervalMs ?? 100;
  }

  parseTime(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
    if (!match) return null;
    const [, year, month, day, hour, minute, second, zone] = match;
    const leap = Number(year) % 4 === 0 && (Number(year) % 100 !== 0 || Number(year) % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const invalid = Number(month) < 1 || Number(month) > 12 ||
      Number(day) < 1 || Number(day) > days[Number(month) - 1] ||
      Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59 ||
      (zone !== 'Z' && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59));
    if (invalid) return null;
    const time = Date.parse(value);
    return Number.isFinite(time) ? time : null;
  }

  parseSince(value) {
    if (value === undefined) return null;
    if (typeof value === 'string') {
      const duration = /^(\d+(?:\.\d+)?)([smhd])$/.exec(value);
      if (duration) {
        const units = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
        const time = Date.now() - Number(duration[1]) * units[duration[2]];
        if (Number.isFinite(time) &&
            Math.abs(time) <= 8640000000000000) return time;
      } else {
        const time = this.parseTime(value);
        if (time !== null) return time;
      }
    }
    throw new Error('Invalid --since: use a duration such as 30s, 5m, 2h, 1d, or an ISO timestamp with timezone (YYYY-MM-DDTHH:mm:ss[.sss]Z or ±HH:mm).');
  }

  stop(error) {
    if (error &&
        error.code !== 'EPIPE') this.failure ??= error;
    this.controller.abort();
    this.wake?.();
  }

  outputError(output, error) {
    if (error.code !== 'EPIPE') {
      if (this.finished) {
        if (!output.reportedFailure) {
          const name = output.stream === this.output ? 'stdout' : 'stderr';
          process.emitWarning(`Late ${name} write failure after logs stopped: ${error.code ?? 'Error'}: ${error.message}`, {
            code: 'MCP_PACEMAKER_LOGS_WRITE_ERROR',
          });
        }
      } else {
        this.failure ??= error;
      }
      output.reportedFailure = true;
    }
    this.stop();
  }

  cleanupOutput(output) {
    if (!this.finished ||
        output.pendingWrites !== 0 ||
        output.awaitingError ||
        output.detached) return;
    output.detached = true;
    output.stream.removeListener('error', output.onError);
    output.stream.removeListener('close', output.onClose);
    this.outputs.delete(output.stream);
  }

  attachOutput(stream) {
    const output = {
      stream, pendingWrites: 0, awaitingError: false, errorSeen: false,
      closed: stream.closed, detached: false, reportedFailure: false,
    };
    output.onError = (error) => {
      output.errorSeen = true;
      output.awaitingError = false;
      this.outputError(output, error);
      this.cleanupOutput(output);
    };
    output.onClose = () => {
      output.closed = true;
      output.awaitingError = false;
      this.stop();
      this.cleanupOutput(output);
    };
    this.outputs.set(stream, output);
    stream.on('error', output.onError);
    stream.on('close', output.onClose);
    if (stream.destroyed ||
        stream.writableEnded) this.stop();
  }

  async write(stream, data) {
    if (this.signal.aborted) return;
    const output = this.outputs.get(stream);
    output.pendingWrites++;
    await new Promise((done) => {
      const finish = () => {
        this.signal.removeEventListener('abort', finish);
        done();
      };
      let completed = false;
      const complete = (error, expectsErrorEvent = true) => {
        if (completed) return;
        completed = true;
        output.pendingWrites--;
        if (error) {
          // A failed write callback can precede an asynchronous _destroy/error.
          // Cancellation releases the caller, not our responsibility for that event.
          output.awaitingError = expectsErrorEvent && !output.errorSeen && !output.closed;
          this.outputError(output, error);
        }
        finish();
        this.cleanupOutput(output);
      };
      this.signal.addEventListener('abort', finish, { once: true });
      try {
        stream.write(data, complete);
      } catch (error) {
        complete(error, false);
      }
    });
  }

  fileId(stat) {
    return `${stat.dev}:${stat.ino}:${stat.birthtimeNs}`;
  }

  async identity(path) {
    try {
      const stat = await lstat(path, { bigint: true });
      if (!stat.isFile()) throw new Error(`Log path is not a regular file: ${path}`);
      return this.fileId(stat);
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  async openFile(path) {
    if (await this.identity(path) === null) return null;
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      this.handles.add(handle);
      const stat = await handle.stat({ bigint: true });
      if (!stat.isFile()) throw new Error(`Log path is not a regular file: ${path}`);
      return {
        handle, id: this.fileId(stat), offset: 0,
        pending: Buffer.alloc(0), pendingBytes: 0, anchor: Buffer.alloc(0),
        recordStart: 0, eligible: this.since === null && !this.options.server,
        matched: false,
      };
    } catch (error) {
      if (handle) await this.closeFile({ handle });
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  async closeFile(file) {
    if (!file?.handle) return;
    await file.handle.close();
    this.handles.delete(file.handle);
    file.handle = null;
  }

  async snapshot() {
    // Open current first, then verify its name still refers to that generation. This
    // avoids reading the same file as both .1 and current when startup races a roll.
    while (!this.signal.aborted) {
      const current = await this.openFile(this.path);
      let archive;
      try {
        archive = await this.openFile(`${this.path}.1`);
        if (await this.identity(this.path) === (current?.id ?? null)) {
          if (archive?.id === current?.id) {
            await this.closeFile(archive);
            archive = null;
          }
          return { current, archive };
        }
      } catch (error) {
        await this.closeFile(current);
        await this.closeFile(archive);
        throw error;
      }
      await this.closeFile(current);
      await this.closeFile(archive);
    }
    return { current: null, archive: null };
  }

  async replay(file, start, end) {
    const buffer = Buffer.allocUnsafe(CHUNK_BYTES);
    while (start < end &&
           !this.signal.aborted) {
      const { bytesRead } = await file.handle.read(buffer, 0, Math.min(buffer.length, end - start), start);
      if (!bytesRead) throw new Error('Log was truncated while reading record context; retry logs.');
      await this.write(this.output, buffer.subarray(0, bytesRead));
      start += bytesRead;
    }
  }

  async line(file, buffer, start, end) {
    const text = buffer.toString('utf8');
    if (text.startsWith('[mcp-bridge] ')) {
      const header = /^\[mcp-bridge\] (\S+)(?:[ \t]+([^\r\n]*))?/.exec(text);
      const time = header ? this.parseTime(header[1]) : null;
      const server = /^\[([^\]\r\n]+)\](?:[ \t]|$)/.exec(header?.[2] ?? '')?.[1];
      file.recordStart = start;
      file.matched = false;
      file.eligible = (this.since === null || (time !== null && time >= this.since)) &&
        (!this.options.server || (time !== null && server === this.options.server));
    }
    if (!file.eligible) return;
    if (!this.grep ||
        file.matched) {
      await this.write(this.output, buffer);
    } else if (text.toLowerCase().includes(this.grep)) {
      // Keep offsets rather than buffering a whole stderr record. A match in a
      // continuation replays its header and preceding context once, in bounded chunks.
      await this.replay(file, file.recordStart, end);
      file.matched = true;
    }
  }

  async consume(file, buffer, start) {
    let from = 0;
    while (from < buffer.length &&
           !this.signal.aborted) {
      const newline = buffer.indexOf(10, from);
      const to = newline < 0 ? buffer.length : newline + 1;
      const part = buffer.subarray(from, to);
      file.pendingBytes += part.length;
      if (file.pendingBytes > MAX_LINE_BYTES) {
        throw new Error(`Log line exceeds the ${MAX_LINE_BYTES}-byte safety limit.`);
      }
      if (file.pendingBytes > file.pending.length) {
        const capacity = Math.min(MAX_LINE_BYTES, Math.max(CHUNK_BYTES, file.pendingBytes * 2));
        const pending = Buffer.allocUnsafe(capacity);
        file.pending.copy(pending, 0, 0, file.pendingBytes - part.length);
        file.pending = pending;
      }
      part.copy(file.pending, file.pendingBytes - part.length);
      if (newline >= 0) {
        const line = file.pending.subarray(0, file.pendingBytes);
        const end = start + to;
        await this.line(file, line, end - file.pendingBytes, end);
        file.pendingBytes = 0;
      }
      from = to;
    }
  }

  async reset(file) {
    await this.write(this.diagnostics, `[mcp-pacemaker logs] Log truncated or rewritten: ${this.path}\n`);
    file.offset = 0;
    file.pending = Buffer.alloc(0);
    file.pendingBytes = 0;
    file.anchor = Buffer.alloc(0);
    file.recordStart = 0;
    file.matched = false;
    file.eligible = this.since === null && !this.options.server;
  }

  async drain(file) {
    const stat = await file.handle.stat();
    let changed = stat.size < file.offset;
    if (!changed &&
        file.anchor.length) {
      const anchor = Buffer.alloc(file.anchor.length);
      const { bytesRead } = await file.handle.read(anchor, 0, anchor.length, file.offset - anchor.length);
      changed = bytesRead !== anchor.length || !anchor.equals(file.anchor);
    }
    if (changed) await this.reset(file);
    // Use a size snapshot so a busy writer cannot starve cancellation or rotation.
    while (file.offset < stat.size &&
           !this.signal.aborted) {
      const buffer = Buffer.allocUnsafe(Math.min(CHUNK_BYTES, stat.size - file.offset));
      const { bytesRead } = await file.handle.read(buffer, 0, buffer.length, file.offset);
      if (!bytesRead) break;
      const bytes = buffer.subarray(0, bytesRead);
      await this.consume(file, bytes, file.offset);
      file.offset += bytesRead;
      file.anchor = Buffer.concat([file.anchor, bytes]).subarray(-ANCHOR_BYTES);
    }
  }

  async finish(file) {
    if (file.pendingBytes) {
      const line = file.pending.subarray(0, file.pendingBytes);
      await this.line(file, line, file.offset - file.pendingBytes, file.offset);
      file.pendingBytes = 0;
    }
  }

  async wait() {
    if (this.signal.aborted) return;
    await new Promise((done) => {
      const finish = () => {
        clearTimeout(timer);
        this.signal.removeEventListener('abort', finish);
        this.wake = null;
        done();
      };
      const timer = setTimeout(finish, this.interval);
      this.wake = finish;
      this.signal.addEventListener('abort', finish, { once: true });
    });
  }

  async run() {
    const stop = () => this.stop();
    let watcher;
    let active;
    let archiveId = null;
    let waiting = false;
    for (const stream of new Set([this.output, this.diagnostics])) this.attachOutput(stream);
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    this.options.signal?.addEventListener('abort', stop, { once: true });
    if (this.options.signal?.aborted) stop();
    try {
      if (this.options.follow) {
        try {
          watcher = watch(dirname(this.path), () => this.wake?.());
          watcher.on('error', () => watcher.close());
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      }
      do {
        const snapshot = await this.snapshot();
        if (!active &&
            !snapshot.current &&
            !this.options.follow &&
            !this.signal.aborted) {
          throw new Error(`Log file not found: ${this.path}`);
        }
        if (active) {
          const retained = [snapshot.current, snapshot.archive].find((file) => file?.id === active.id);
          if (retained) {
            active.handle = retained.handle;
            if (retained === snapshot.current) snapshot.current = active;
            else snapshot.archive = active;
            await this.drain(active);
          } else {
            await this.write(this.diagnostics, '[mcp-pacemaker logs] Previous log generation is no longer retained; unread records may have been lost.\n');
            active = null;
          }
        }
        if (snapshot.current?.id !== active?.id) {
          if (active) {
            await this.finish(active);
            archiveId = active.id;
            await this.closeFile(active);
            active = null;
          }
          if (snapshot.archive &&
              snapshot.archive.id !== archiveId) {
            await this.drain(snapshot.archive);
            await this.finish(snapshot.archive);
            archiveId = snapshot.archive.id;
          }
          active = snapshot.current;
          if (active) await this.drain(active);
        } else if (!active &&
                   snapshot.archive &&
                   snapshot.archive.id !== archiveId) {
          await this.drain(snapshot.archive);
          await this.finish(snapshot.archive);
          archiveId = snapshot.archive.id;
        }
        await this.closeFile(snapshot.archive);
        if (!this.options.follow) {
          if (active) await this.finish(active);
          break;
        }
        // In particular on Windows, retaining an open .1 handle can prevent the
        // writer from replacing it at the next roll. Keep cursors, not idle handles.
        await this.closeFile(active);
        if (!snapshot.current) {
          if (!waiting) await this.write(this.diagnostics, `[mcp-pacemaker logs] Waiting for ${this.path} to be created.\n`);
          waiting = true;
        } else {
          waiting = false;
        }
        await this.options.onIdle?.();
        await this.wait();
      } while (!this.signal.aborted);
    } finally {
      watcher?.close();
      await Promise.all([...this.handles].map((handle) => handle.close()));
      this.handles.clear();
      // Drain already-scheduled events, but never wait for a stalled caller-owned
      // write. Its stream guards remain until the callback and error/close settle.
      await yieldTurn();
      this.finished = true;
      for (const output of this.outputs.values()) this.cleanupOutput(output);
      process.removeListener('SIGINT', stop);
      process.removeListener('SIGTERM', stop);
      this.options.signal?.removeEventListener('abort', stop);
    }
    if (this.failure) throw this.failure;
  }
}

/**
 * Dump bridge.log.1 then bridge.log beside config (default ~/.mcp-pacemaker/servers.json).
 * Options: config, follow, since (s/m/h/d duration or strict zoned ISO), server (exact
 * header name), grep (case-insensitive literal substring within any record line).
 * Matching records include all their context. Follow emits complete lines as they
 * arrive; an unfinished line is emitted at EOF only for a finite dump or file rotation.
 * The bridge rotates between records, so each new file starts with fresh context.
 * Memory is bounded: records are replayed by file offset; lines over 1 MiB error
 * explicitly rather than being silently cut. Only retained log generations can be read;
 * if both names have moved past the cursor, follow reports the possible history gap.
 * Embedders may supply stdout/stderr Writable streams, an AbortSignal, pollIntervalMs
 * (default 100), and onIdle (called after a follow scan, before waiting).
 * Resolves on completion, cancellation, or EPIPE; rejects input/filesystem/output errors.
 * Pending writes stay error-protected after cancellation. Later non-EPIPE failures
 * produce a process warning with code MCP_PACEMAKER_LOGS_WRITE_ERROR.
 * Never closes caller-owned output streams or changes process.exitCode.
 */
export async function runLogs(options = {}) {
  for (const name of ['config', 'server', 'grep']) {
    if (options[name] !== undefined &&
        typeof options[name] !== 'string') throw new Error(`Invalid --${name}: expected text.`);
  }
  if (options.config === '' ||
      options.server === '') throw new Error('--config and --server must not be empty.');
  if (options.pollIntervalMs !== undefined &&
      (!Number.isFinite(options.pollIntervalMs) || options.pollIntervalMs < 1 || options.pollIntervalMs > 2147483647)) {
    throw new Error('pollIntervalMs must be between 1 and 2147483647.');
  }
  await new LogReader(options).run();
}
