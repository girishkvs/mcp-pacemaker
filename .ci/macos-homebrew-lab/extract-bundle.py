import os
import pathlib
import re
import stat
import sys
import zipfile


def extract(archive, destination):
    destination = pathlib.Path(destination)
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir() or destination.exists():
        raise ValueError("INVALID_EXTRACTION_DESTINATION")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > 128:
            raise ValueError("TOO_MANY_BUNDLE_ENTRIES")
        seen = set()
        total = 0
        checked = []
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            parts = name.rstrip("/").split("/")
            if (any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or
                    part in (".", "..") for part in parts) or
                    name.casefold() in seen):
                raise ValueError("INVALID_BUNDLE_PATH")
            seen.add(name.casefold())
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("LINK_OR_SPECIAL_FILE_IN_BUNDLE")
            total += entry.file_size
            if total > 32 * 1024 * 1024:
                raise ValueError("EXPANDED_BUNDLE_TOO_LARGE")
            checked.append((entry, parts))
        if "run.ps1" not in seen:
            raise ValueError("BUNDLE_ENTRYPOINT_MISSING")
        destination.mkdir(mode=0o700)
        written = 0
        for entry, parts in checked:
            target = destination.joinpath(*parts)
            if entry.is_dir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            count = 0
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output, bundle.open(entry) as source:
                while chunk := source.read(65536):
                    written += len(chunk)
                    count += len(chunk)
                    if written > 32 * 1024 * 1024:
                        raise ValueError("EXPANDED_BUNDLE_TOO_LARGE")
                    output.write(chunk)
            if count != entry.file_size:
                raise ValueError("BUNDLE_ENTRY_LENGTH_MISMATCH")


if __name__ == "__main__":
    try:
        extract(sys.argv[1], sys.argv[2])
    except (ValueError, OSError, zipfile.BadZipFile, IndexError):
        print("PRIVATE_BUNDLE_EXTRACTION_FAILED", file=sys.stderr)
        sys.exit(1)
