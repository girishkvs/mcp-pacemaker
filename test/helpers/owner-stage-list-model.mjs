import assert from 'node:assert/strict';
import Module, { createRequire, syncBuiltinESMExports } from 'node:module';
import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Readable } from 'node:stream';
import net from 'node:net';
import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import childProcess from 'node:child_process';
import dns from 'node:dns';
import dgram from 'node:dgram';
import http2 from 'node:http2';

export class OwnerListTestLifecycle {
  budget(commandMs) {
    assert.ok(Number.isSafeInteger(commandMs) &&
      commandMs > 0 &&
      commandMs <= 30_000);
    // Preload/identity capture precedes the product deadline; pipe and process close follows it.
    return { commandMs, startupMs: 10_000, cleanupMs: 5000, watchdogMs: commandMs + 15_000 };
  }
  read(directory, name) {
    const path = join(directory, name);
    if (!existsSync(path)) return null;
    const bytes = readFileSync(path);
    assert.ok(bytes.length <= 2 * 1024 * 1024, `Oversized fixture evidence: ${name}`);
    return JSON.parse(bytes);
  }
  write(directory, name, value) {
    const bytes = Buffer.from(JSON.stringify(value, null, 2));
    assert.ok(bytes.length <= 2 * 1024 * 1024, `Oversized fixture evidence: ${name}`);
    writeFileSync(join(directory, name), bytes);
  }
  windowsCommand(directory, args, deadline) {
    const python = process.env.OWNER_LIST_TEST_PYTHON ?? 'python';
    const probe = childProcess.spawnSync(python, ['-I', '-c', 'import sys; print(sys.executable)'],
      { encoding: 'utf8', timeout: 3000, windowsHide: true });
    assert.equal(probe.error, undefined, 'Windows owner-list fixtures require an existing Python3');
    assert.equal(probe.status, 0, 'Windows owner-list Python probe failed');
    const executable = probe.stdout.trim();
    const script = join(directory, 'owner-list-job.py');
    writeFileSync(script, windowsJobSource);
    return { file: executable, args: ['-I', script, directory, String(deadline), process.execPath, ...args] };
  }
}

// Test-only Windows containment. Assignment happens while the outer Node is suspended.
// The unnamed, non-inherited job handle owns descendants even if either Node stops responding.
const windowsJobSource = String.raw`
import ctypes as c
from ctypes import wintypes as w
import json, os, pathlib, struct, subprocess, sys, time
import _winapi

k = c.WinDLL("kernel32", use_last_error=True)
def api(name, result, *args):
    fn = getattr(k, name)
    fn.restype, fn.argtypes = result, args
    return fn
create = api("CreateJobObjectW", w.HANDLE, c.c_void_p, w.LPCWSTR)
setinfo = api("SetInformationJobObject", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD)
query = api("QueryInformationJobObject", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p)
assign = api("AssignProcessToJobObject", w.BOOL, w.HANDLE, w.HANDLE)
terminate = api("TerminateJobObject", w.BOOL, w.HANDLE, w.UINT)
close = api("CloseHandle", w.BOOL, w.HANDLE)
resume = api("ResumeThread", w.DWORD, w.HANDLE)
open_process = api("OpenProcess", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
membership = api("IsProcessInJob", w.BOOL, w.HANDLE, w.HANDLE, c.POINTER(w.BOOL))
times = api("GetProcessTimes", w.BOOL, w.HANDLE, *([c.POINTER(c.c_ulonglong)] * 4))
wait = api("WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
exit_code = api("GetExitCodeProcess", w.BOOL, w.HANDLE, c.POINTER(w.DWORD))
current_process = api("GetCurrentProcess", w.HANDLE)
image_name = api("QueryFullProcessImageNameW", w.BOOL, w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD))
class Basic(c.Structure):
    _fields_ = [("processTime", c.c_longlong), ("jobTime", c.c_longlong),
        ("flags", w.DWORD), ("minWS", c.c_size_t), ("maxWS", c.c_size_t),
        ("active", w.DWORD), ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
class Extended(c.Structure):
    _fields_ = [("basic", Basic), ("io", c.c_ulonglong * 6),
        ("processMemory", c.c_size_t), ("jobMemory", c.c_size_t),
        ("peakProcess", c.c_size_t), ("peakJob", c.c_size_t)]
def check(ok, name):
    if not ok:
        raise OSError(c.get_last_error(), name)

directory = pathlib.Path(sys.argv[1])
deadline = int(sys.argv[2])
state = {"kind": "owned-windows-test-job", "controllerPid": os.getpid(),
    "pythonVersion": sys.version.split()[0],
    "identities": [], "errors": [], "watchdogReason": None,
    "allClosed": False, "jobHandleClosed": False, "code": None, "signal": None}
handles = {}
job = root_handle = thread = None
assigned = False
def record(name, value):
    data = json.dumps(value).encode("utf-8")
    if len(data) > 65536:
        raise ValueError("job evidence budget")
    target = directory / name
    temporary = directory / (name + ".tmp")
    with open(temporary, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
def live():
    record("job-live.json", state)
def members():
    data = c.create_string_buffer(8 + 32 * c.sizeof(c.c_size_t))
    check(query(job, 3, data, len(data), None), "QueryInformationJobObject")
    assigned_count, count = struct.unpack_from("II", data)
    if assigned_count != count or count > 32:
        raise ValueError("job process-list bound")
    code = "Q" if c.sizeof(c.c_size_t) == 8 else "I"
    return list(struct.unpack_from(code * count, data, 8))
def capture(pid, handle=None):
    if pid in handles:
        return
    handle = handle or open_process(0x100000 | 0x1000, False, pid)
    check(handle, "OpenProcess owned job member")
    try:
        controller_times = [c.c_ulonglong() for _ in range(4)]
        check(times(current_process(), *[c.byref(value) for value in controller_times]), "Controller GetProcessTimes")
        state["controllerCreationFileTime"] = str(controller_times[0].value)
        belongs = w.BOOL()
        check(membership(handle, job, c.byref(belongs)), "IsProcessInJob")
        check(belongs.value, "Not an owned job member")
        values = [c.c_ulonglong() for _ in range(4)]
        check(times(handle, *[c.byref(value) for value in values]), "GetProcessTimes")
        image = c.create_unicode_buffer(32768)
        image_size = w.DWORD(len(image))
        check(image_name(handle, 0, image, c.byref(image_size)), "QueryFullProcessImageName owned member")
        identity = {"pid": pid, "creationFileTime": str(values[0].value),
            "capturedAtMs": time.time_ns() // 1000000, "jobMembershipVerified": True,
            "image": image.value}
        handles[pid] = handle
        state["identities"].append(identity)
        live()
        record("process-identity-" + str(pid) + ".json", identity)
    except BaseException:
        if handle != root_handle:
            close(handle)
        raise
try:
    job = create(None, None)
    check(job, "CreateJobObject")
    limits = Extended()
    limits.basic.flags = 0x2000
    check(setinfo(job, 9, c.byref(limits), c.sizeof(limits)), "SetInformationJobObject KILL_ON_JOB_CLOSE")
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESTDHANDLES
    startup.hStdInput = _winapi.GetStdHandle(-10)
    startup.hStdOutput = _winapi.GetStdHandle(-11)
    startup.hStdError = _winapi.GetStdHandle(-12)
    inherited = [startup.hStdInput, startup.hStdOutput, startup.hStdError]
    for handle in inherited:
        os.set_handle_inheritable(handle, True)
    startup.lpAttributeList = {"handle_list": inherited}
    command = sys.argv[3:]
    root_handle, thread, pid, _ = _winapi.CreateProcess(command[0],
        subprocess.list2cmdline(command), None, None, True, 0x4 | 0x08000000,
        None, os.getcwd(), startup)
    state["outerPid"] = pid
    check(assign(job, root_handle), "AssignProcessToJobObject suspended outer")
    assigned = True
    capture(pid, root_handle)
    check(resume(thread) != 0xffffffff, "ResumeThread")
    check(close(thread), "CloseHandle thread")
    thread = None
    cleanup_deadline = None
    outer_drain_started = None
    control_path = directory / "watchdog-control.json"
    control = json.loads(control_path.read_text()) if control_path.exists() else None
    if control:
        if control != {"kind": "pure-test-lifecycle-control-not-product", "identityCount": 2, "delayMs": 50}:
            raise ValueError("Unexpected lifecycle control")
        state["controlArmed"] = False
    while True:
        active = members()
        for member in active:
            capture(member)
        state["activeProcesses"] = len(active)
        if control and not state["controlArmed"] and (directory / "expected-pids.json").exists():
            expected = json.loads((directory / "expected-pids.json").read_text())
            if expected["outer"] in handles and expected["child"] in handles:
                deadline = min(deadline, time.time_ns() // 1000000 + 50)
                state["controlArmed"] = True
                live()
        if not active:
            break
        outer_closed = wait(root_handle, 0) == 0
        if outer_closed:
            active = members()
            state["activeProcesses"] = len(active)
            if not active:
                break
            if outer_drain_started is None:
                outer_drain_started = time.monotonic()
                state["outerExitActive"] = [{"pid": member, "wait": wait(handles[member], 0),
                    "image": next(row["image"] for row in state["identities"] if row["pid"] == member)}
                    for member in active]
                live()
        stop = (directory / "stop-request.json").exists()
        expired = time.time_ns() // 1000000 >= deadline
        drain_expired = outer_drain_started is not None and time.monotonic() - outer_drain_started >= 5
        if cleanup_deadline is None and (drain_expired or stop or expired):
            state["watchdogReason"] = ("outer-exited-with-live-descendants" if drain_expired
                else "fixture-output-budget" if stop else "fixture-deadline")
            live()
            check(terminate(job, 124), "TerminateJobObject owned members")
            cleanup_deadline = time.monotonic() + 5
        if cleanup_deadline is not None and time.monotonic() >= cleanup_deadline:
            raise TimeoutError("owned job termination did not complete")
        time.sleep(0.01)
    state["waits"] = []
    if outer_drain_started is not None:
        state["outerDrainMs"] = (time.monotonic() - outer_drain_started) * 1000
    close_deadline = cleanup_deadline if cleanup_deadline is not None else time.monotonic() + 5
    for pid, handle in handles.items():
        started_wait = time.monotonic()
        initial = wait(handle, 0)
        final = initial if initial == 0 else wait(handle, max(0, int((close_deadline - time.monotonic()) * 1000)))
        state["waits"].append({"pid": pid, "initial": initial, "final": final,
            "elapsedMs": (time.monotonic() - started_wait) * 1000})
        live()
        check(final == 0, "Owned process close not observed")
    code = w.DWORD()
    check(exit_code(root_handle, c.byref(code)), "GetExitCodeProcess outer")
    state["code"] = code.value
    state["allClosed"] = True
    live()
except BaseException as error:
    state["errors"].append({"type": type(error).__name__, "detail": str(error)[:256]})
finally:
    if job:
        if assigned and not state["allClosed"]:
            if not terminate(job, 124):
                state["errors"].append({"operation": "TerminateJobObject", "winerror": c.get_last_error()})
        if not close(job):
            state["errors"].append({"operation": "CloseHandle job", "winerror": c.get_last_error()})
        else:
            state["jobHandleClosed"] = True
    if root_handle and not assigned:
        _winapi.TerminateProcess(root_handle, 124)
    for handle in set(handles.values()) | ({root_handle} if root_handle else set()) | ({thread} if thread else set()):
        if not close(handle):
            state["errors"].append({"operation": "CloseHandle process/thread", "winerror": c.get_last_error()})
    record("job-result.json", state)
sys.exit(1 if state["errors"] else 0)
`;

const modelPath = process.env.OWNER_LIST_MODEL_FILE;
if (modelPath) {
  const model = JSON.parse(readFileSync(modelPath));
  const output = dirname(modelPath);
  const child = process.argv[1].endsWith('owner-stage-list-child.mjs');
  const calls = [];
  const arrivals = [];
  const denied = [];
  const parsedResponseBytes = [];
  const role = child ? 'child' : 'parent';
  let sequence = 0;
  const phase = (name, data = {}) => {
    assert.ok(++sequence <= 256, 'Fixture phase budget exceeded');
    const bytes = JSON.stringify({ sequence, role, pid: process.pid, ppid: process.ppid,
      at: new Date().toISOString(), uptimeMs: process.uptime() * 1000, phase: name, ...data }) + '\n';
    assert.ok(Buffer.byteLength(bytes) <= 4096, 'Fixture phase record exceeded');
    appendFileSync(join(output, `${role}-phases.jsonl`), bytes);
  };
  phase('preload-start');
  if (process.platform === 'win32') {
    const identityPath = join(output, `process-identity-${process.pid}.json`);
    const identityDeadline = performance.now() + 5000;
    while (!existsSync(identityPath)) {
      assert.ok(performance.now() < identityDeadline, 'Owned job identity was not captured');
      await new Promise(resolveWait => setTimeout(resolveWait, 10));
    }
    const identity = JSON.parse(readFileSync(identityPath));
    assert.equal(identity.pid, process.pid);
    assert.ok(/^[1-9]\d+$/.test(identity.creationFileTime));
    phase('owned-identity-confirmed', identity);
  }
  const responseTexts = new Set(model.responses.map(row => row.raw ?? JSON.stringify(row.body)));
  const originalParse = JSON.parse;
  JSON.parse = (value, ...args) => {
    if (typeof value === 'string' &&
        value.startsWith('{"modelMarker":"owner-list-response"')) parsedResponseBytes.push(Buffer.byteLength(value));
    const response = responseTexts.has(value);
    if (response) phase('response-json-parse-enter', { bytes: Buffer.byteLength(value) });
    const parsed = originalParse(value, ...args);
    if (response) phase('response-json-parse-return');
    return parsed;
  };
  const deny = () => {
    denied.push('native-network');
    phase('native-network-denied');
    throw new Error('TEST: host network denied');
  };
  net.Socket.prototype.connect = net.Server.prototype.listen = deny;
  net.connect = net.createConnection = http.request = http.get = https.request = https.get = tls.connect = deny;
  http2.connect = dgram.createSocket = deny;
  for (const api of [dns, dns.promises]) {
    for (const name of Object.keys(api)) {
      if (/^(lookup|resolve|reverse)/.test(name) &&
          typeof api[name] === 'function') api[name] = deny;
    }
  }
  globalThis.fetch = deny;
  phase('native-network-denial-armed');
  const originalLoad = Module._load;
  if (child) {
    const observedModules = new Set();
    Module._load = function(request, parent, isMain) {
      const observe = !observedModules.has(request) &&
        (request === '@npmcli/config' ||
          request === 'npm-registry-fetch' ||
          request === 'minipass-fetch' ||
          request.endsWith('npm-cli.js'));
      if (observe) {
        observedModules.add(request);
        phase('module-load-enter', { request });
      }
      const value = originalLoad.call(this, request, parent, isMain);
      if (observe) phase('module-load-return', { request });
      if (request !== 'minipass-fetch') return value;
      const modeled = async (req, options) => {
        const arrival = {
          url: req.url, method: req.method, bodyNull: req.body === null,
          authMatched: req.headers?.get('authorization') === `Bearer ${model.token}`,
          retry: options.retry, cache: options.cache, rejectUnauthorized: options.rejectUnauthorized,
        };
        arrivals.push(arrival);
        phase('external-request-arrived', { method: arrival.method, url: arrival.url });
        writeFileSync(join(output, 'external-arrival.json'), JSON.stringify(arrival));
        const url = new URL(req.url);
        assert.equal(url.origin, 'https://registry.npmjs.org');
        assert.equal(url.pathname, '/-/stage');
        assert.equal(req.method, 'GET');
        assert.equal(req.body, null);
        assert.equal(req.headers.get('authorization'), `Bearer ${model.token}`);
        const page = Number(url.searchParams.get('page'));
        assert.equal(page, calls.length);
        assert.equal(options.retry.retries, 0);
        assert.equal(options.cache, 'no-store');
        assert.equal(options.rejectUnauthorized, true);
        calls.push({ url: url.href, method: req.method, authMatchedConfiguredFixture: true,
          retry: options.retry, cache: options.cache, size: options.size,
          rejectUnauthorized: options.rejectUnauthorized, bodyAbsent: req.body === null });
        writeFileSync(join(output, 'physical-requests.json'), JSON.stringify(calls));
        assert.ok(page < model.responses.length, 'Unmodeled external stage page');
        const row = model.responses[page];
        phase('external-response-selected', { page, status: row.status ?? 200,
          rejects: Boolean(row.reject), stalls: Boolean(row.stall) });
        if (row.reject) throw Object.assign(new Error('MODELED_PRIVATE_TOKEN_' + model.token), { code: 'ECONNRESET', type: 'system' });
        if (row.stall) return new Promise(() => {});
        const body = row.raw ?? JSON.stringify(row.body);
        const stream = Readable.from([Buffer.from(body)]);
        return new value.Response(stream, {
          url: url.href, status: row.status ?? 200, headers: row.headers ?? { 'content-type': 'application/json' },
        });
      };
      return Object.assign(modeled, value);
    };
    if (model.fault === 'module-cache') {
      createRequire(process.env.OWNER_LIST_TEST_CLI)('npm-registry-fetch');
    }
    if (model.fault === 'source-binding') {
      const path = process.argv[2];
      const request = JSON.parse(readFileSync(path));
      request.source['owner-stage-list-child.mjs'] = '0'.repeat(64);
      writeFileSync(path, JSON.stringify(request));
    }
    const originalExit = process.exit.bind(process);
    process.exit = code => {
      phase('process-exit-requested', { code: code ?? null });
      if (model.fault === 'exit-after-output') return originalExit(9);
      if (model.fault === 'hang-after-output') {
        setInterval(() => {}, 1000);
        return;
      }
      return originalExit(code);
    };
    process.on('output', (level) => {
      if (level !== 'standard') return;
      phase('sdk-standard-output');
      if (model.fault === 'child-observation-write') {
        mkdirSync(join(model.destination, 'private', 'observation.json'));
      }
      if (model.fault === 'receipt-write') mkdirSync(join(model.destination, 'receipt.json'));
    });
    if (model.fault === 'stdout-overflow') process.stdout.write('x'.repeat(256 * 1024 + 1));
    if (model.fault === 'stderr-overflow') process.stderr.write('x'.repeat(64 * 1024 + 1));
    if (model.stderrBytes) process.stderr.write('x'.repeat(model.stderrBytes));
  } else {
    const fs = createRequire(import.meta.url)('node:fs');
    const open = fs.openSync;
    const close = fs.closeSync;
    const write = fs.writeSync;
    const sync = fs.fsyncSync;
    let faultFd;
    if (['receipt-write-fd', 'receipt-fsync-fd'].includes(model.fault)) {
      fs.openSync = (path, flags, ...rest) => {
        const fd = open(path, flags, ...rest);
        if (/receipt\.json\.\d+\.tmp$/.test(String(path))) {
          faultFd = fd;
          if (model.fault === 'receipt-write-fd') {
            close(fd);
            faultFd = open(path, 'r');
          }
          return faultFd;
        }
        return fd;
      };
      fs.writeSync = (fd, ...args) => {
        try {
          const count = write(fd, ...args);
          if (fd === faultFd &&
              model.fault === 'receipt-fsync-fd') close(fd);
          return count;
        } catch (error) {
          writeFileSync(join(output, 'native-fd-failure.json'), JSON.stringify({
            operation: 'writeSync', code: error.code, readOnlyDescriptor: fd === faultFd,
            actualNativeCall: true, callbackThrewSyntheticError: false,
          }));
          throw error;
        }
      };
      fs.fsyncSync = fd => {
        try { return sync(fd); } catch (error) {
          writeFileSync(join(output, 'native-fd-failure.json'), JSON.stringify({
            operation: 'fsyncSync', code: error.code, closedDescriptor: fd === faultFd,
            actualNativeCall: true, callbackThrewSyntheticError: false,
          }));
          throw error;
        }
      };
    }
    const spawn = childProcess.spawn;
    childProcess.spawn = (file, args, options) => {
      assert.equal(resolve(file), resolve(process.execPath));
      assert.ok(args[0].endsWith('owner-stage-list-child.mjs'));
      const actual = ['--import', pathToFileURL(fileURLToPath(import.meta.url)).href, ...args];
      phase('product-child-spawn-enter');
      const launched = spawn(file, actual, options);
      writeFileSync(join(output, 'actual-child-argv.json'), JSON.stringify({
        file, logicalArgs: args, actualArgs: actual, pid: launched.pid, parentPid: process.pid,
        spawnReturnedAt: new Date().toISOString(),
      }));
      phase('product-child-spawn-return', { childPid: launched.pid });
      launched.once('error', error => phase('product-child-error', { code: error.code ?? null }));
      launched.once('exit', (code, signal) => phase('product-child-exit', { code, signal }));
      launched.once('close', (code, signal) => {
        phase('product-child-close', { code, signal });
        writeFileSync(join(output, 'actual-child-result.json'), JSON.stringify({
          pid: launched.pid, parentPid: process.pid, code, signal,
          oracle: 'Actual ChildProcess close event observed by the parent',
        }));
      });
      if (model.fault === 'child-output-stream') {
        launched.stdout.destroy();
        writeFileSync(join(output, 'actual-child-output-close.json'), JSON.stringify({
          realPipeReaderClosed: launched.stdout.destroyed, callbackThrewSyntheticError: false,
        }));
      }
      let stdoutBytes = 0;
      let prefix = '';
      launched.stdout.on('data', (bytes) => {
        stdoutBytes += bytes.length;
        prefix = (prefix + bytes.toString()).slice(0, 4096);
        writeFileSync(join(output, 'native-child-output.json'), JSON.stringify({
          stdoutBytes, prefix, prefixOnly: true, nonsecretExternalModelOnly: true,
        }));
      });
      return launched;
    };
  }
  syncBuiltinESMExports();
  phase('preload-complete');
  process.on('exit', code => {
    phase('process-exit', { code });
    writeFileSync(join(output, child ? 'child-boundary.json' : 'parent-boundary.json'), JSON.stringify({
      calls, arrivals, denied, parsedResponseBytes, child, configTokenPersisted: false,
      modelOnly: true, actualExit: code,
      exitStatusScope: 'Early preload exit-event argument; not the final OS exit status',
    }));
    if (denied.length) process.exitCode = 1;
  });
}
