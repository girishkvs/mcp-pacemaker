import hashlib
import io
import json
import struct
import sys
import zipfile


def inspect():
    header = sys.stdin.buffer.read(4)
    if len(header) != 4:
        raise ValueError("MISSING_SCAN_HEADER")
    length = struct.unpack(">I", header)[0]
    if length > 65536:
        raise ValueError("SCAN_HEADER_TOO_LARGE")
    metadata = json.loads(sys.stdin.buffer.read(length))
    needles = [value.encode("utf-8") for value in metadata["secrets"] if value]
    needles.extend([
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
    ])
    archive = sys.stdin.buffer.read(64 * 1024 * 1024 + 1)
    if len(archive) > 64 * 1024 * 1024:
        raise ValueError("RESULT_ARCHIVE_TOO_LARGE")
    records = []
    total = 0
    tail_length = max(len(value) for value in needles) - 1
    seen = set()
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        if len(bundle.infolist()) > 256:
            raise ValueError("TOO_MANY_RESULT_ENTRIES")
        for entry in bundle.infolist():
            name = entry.filename.replace("\\", "/")
            parts = name.rstrip("/").split("/")
            invalid = (
                name.startswith("/") or
                ":" in name or
                any(part in ("", ".", "..") for part in parts) or
                name.casefold() in seen
            )
            if invalid:
                raise ValueError("INVALID_RESULT_PATH")
            seen.add(name.casefold())
            mode = (entry.external_attr >> 16) & 0o170000
            if mode not in (0, 0o100000, 0o040000):
                raise ValueError("SPECIAL_RESULT_ENTRY")
            if any(needle in name.encode("utf-8") for needle in needles):
                raise ValueError("CREDENTIAL_IN_RESULT_PATH")
            digest = hashlib.sha256()
            tail = b""
            count = 0
            with bundle.open(entry) as source:
                while chunk := source.read(65536):
                    count += len(chunk)
                    total += len(chunk)
                    if total > 128 * 1024 * 1024:
                        raise ValueError("EXPANDED_RESULT_TOO_LARGE")
                    window = tail + chunk
                    if any(needle in window for needle in needles):
                        raise ValueError("CREDENTIAL_IN_RESULT")
                    digest.update(chunk)
                    tail = window[-tail_length:]
            records.append({"name": name, "bytes": count, "sha256": digest.hexdigest()})
    return {"safe": True, "entries": records, "expandedBytes": total}


try:
    print(json.dumps(inspect()))
except (ValueError, KeyError, zipfile.BadZipFile, OSError):
    print('{"safe":false,"reason":"PRIVATE_RESULT_INSPECTION_FAILED"}')
    sys.exit(1)
