"""Core filesystem operations for the Obsidian vault."""

import errno
import fcntl
import fnmatch
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import config


def resolve_vault_path(relative_path: str) -> Path:
    """Resolve a relative path against the vault root, with safety checks.

    Raises ValueError if the path escapes the vault, contains null bytes,
    or touches dotfile/dot-directory components.
    """
    if "\x00" in relative_path:
        raise ValueError("Path contains null bytes")

    # Check for dot-prefixed components (blocks .obsidian, .trash, dotfiles)
    parts = Path(relative_path).parts
    for part in parts:
        if part.startswith("."):
            raise ValueError(
                f"Path component '{part}' starts with '.'; dotfiles and hidden directories are not allowed"
            )

    resolved = (config.VAULT_PATH / relative_path).resolve()
    vault_root = config.VAULT_PATH.resolve()

    if not str(resolved).startswith(str(vault_root) + os.sep) and resolved != vault_root:
        raise ValueError("Path resolves outside the vault root")

    return resolved


def _iso_timestamp(ts: float) -> str:
    """Convert a Unix timestamp to an ISO 8601 string in UTC."""
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def read_file(relative_path: str) -> tuple[str, dict]:
    """Read a file and return (content, metadata).

    Metadata keys: size (int), modified (ISO str), created (ISO str).
    """
    path = resolve_vault_path(relative_path)

    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {relative_path}")

    stat = path.stat()
    content = path.read_text(encoding="utf-8")

    metadata = {
        "size": stat.st_size,
        "modified": _iso_timestamp(stat.st_mtime),
        "created": _iso_timestamp(stat.st_birthtime if hasattr(stat, "st_birthtime") else stat.st_ctime),
    }

    return content, metadata


def write_file_atomic(relative_path: str, content: str, create_dirs: bool = True) -> tuple[bool, int]:
    """Write content to a file atomically.

    Returns (is_new_file, bytes_written). Writes to a tempfile in the same
    directory then replaces the target, so readers never see a partial write.
    """
    encoded = content.encode("utf-8")
    if len(encoded) > config.MAX_CONTENT_SIZE:
        raise ValueError(f"Content size {len(encoded)} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes")

    path = resolve_vault_path(relative_path)
    is_new = not path.exists()

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory, then atomic-replace.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
        os.replace(tmp_path, path)
    except BaseException:
        # Clean up the temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return is_new, len(encoded)


def create_file_exclusive(relative_path: str, content: str, create_dirs: bool = True) -> int:
    """Create a new file with O_CREAT|O_EXCL; never overwrite an existing path.

    Returns bytes_written. Raises FileExistsError if the path already exists
    (including as a symlink when O_NOFOLLOW is available).
    """
    encoded = content.encode("utf-8")
    if len(encoded) > config.MAX_CONTENT_SIZE:
        raise ValueError(f"Content size {len(encoded)} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes")

    path = resolve_vault_path(relative_path)

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        # Symlink at the final component: refuse rather than follow/overwrite.
        if exc.errno == errno.ELOOP:
            raise FileExistsError(f"Path already exists: {relative_path}") from exc
        raise

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise

    return len(encoded)


def append_file(
    relative_path: str,
    content: str,
    *,
    create_if_missing: bool = False,
    create_dirs: bool = True,
) -> tuple[bool, int]:
    """Append bytes with O_APPEND; never replace existing body content.

    Under an advisory fcntl.LOCK_EX on the fd, checks that existing size + chunk
    stays within MAX_CONTENT_SIZE, then writes. Without the lock two parallel
    appends can both pass the limit check. With create_if_missing, opens with
    O_CREAT (no O_TRUNC) so a racing create is preserved. Without it, missing
    paths raise FileNotFoundError.

    Returns (created, size_after) where size_after is the total file size.
    """
    encoded = content.encode("utf-8")
    if len(encoded) > config.MAX_CONTENT_SIZE:
        raise ValueError(f"Content size {len(encoded)} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes")

    path = resolve_vault_path(relative_path)

    # O_RDWR: pod blokadą czytamy ostatni bajt (pread); O_APPEND bez O_TRUNC zostaje.
    flags = os.O_RDWR | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    created = False
    fd: int | None = None
    locked = False
    try:
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                if exc.errno == errno.ELOOP:
                    raise FileExistsError(f"Path already exists: {relative_path}") from exc
                raise
            if not create_if_missing:
                raise FileNotFoundError(f"Not a file: {relative_path}") from exc
            if create_dirs:
                path.parent.mkdir(parents=True, exist_ok=True)
            create_flags = flags | os.O_CREAT
            try:
                fd = os.open(path, create_flags, 0o644)
            except OSError as create_exc:
                if create_exc.errno == errno.ELOOP:
                    raise FileExistsError(f"Path already exists: {relative_path}") from create_exc
                raise
            # O_CREAT bez O_TRUNC: przy wyścigu z create zachowujemy istniejące bajty.
            created = True

        if fd is None:
            raise RuntimeError("append_file: file descriptor not opened")

        # Serializuj fstat + limit + dopisek: bez LOCK_EX dwa appendy mogą obie
        # przejść sprawdzenie MAX_CONTENT_SIZE na tym samym st_size.
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = True

        existing_size = os.fstat(fd).st_size
        if created and existing_size > 0:
            created = False
        sep = b""
        if existing_size > 0 and encoded and not encoded.startswith(b"\n") and not encoded.startswith(b"\r\n"):
            last = os.pread(fd, 1, existing_size - 1)
            if last != b"\n":
                sep = b"\n"
        to_write = sep + encoded
        total = existing_size + len(to_write)
        if total > config.MAX_CONTENT_SIZE:
            raise ValueError(f"Content size {total} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes")

        # Pusta treść (i brak separatora): nie ruszaj pliku.
        if not to_write:
            written = 0
        else:
            written = os.write(fd, to_write)
            if written != len(to_write):
                raise OSError(f"Short append write: {written} of {len(to_write)} bytes")
            os.fsync(fd)
    finally:
        if locked and fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    return created, existing_size + written


def move_path(source: str, destination: str, create_dirs: bool = True) -> bool:
    """Move a file or directory from source to destination.

    Both paths are relative to the vault root. Raises if the destination
    already exists.
    """
    src = resolve_vault_path(source)
    dst = resolve_vault_path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Source does not exist: {source}")

    if dst.exists():
        raise FileExistsError(f"Destination already exists: {destination}")

    if create_dirs:
        dst.parent.mkdir(parents=True, exist_ok=True)

    shutil.move(str(src), str(dst))
    return True


def delete_path(relative_path: str) -> bool:
    """Soft-delete by moving the path into .trash/ at the vault root.

    Refuses to delete non-empty directories.
    """
    path = resolve_vault_path(relative_path)

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {relative_path}")

    if path.is_dir() and any(path.iterdir()):
        raise ValueError(f"Refusing to delete non-empty directory: {relative_path}")

    trash_dir = config.VAULT_PATH.resolve() / ".trash"
    trash_dir.mkdir(exist_ok=True)

    dest = trash_dir / path.name

    # Avoid collisions in .trash by appending a timestamp
    if dest.exists():
        ts = datetime.now(tz=UTC).strftime("%Y%m%d%H%M%S")
        dest = trash_dir / f"{path.stem}_{ts}{path.suffix}"

    shutil.move(str(path), str(dest))
    return True


def list_directory(
    relative_path: str,
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> list[dict]:
    """List directory contents recursively up to *depth* levels.

    Returns a list of dicts with keys: name, path (relative to vault),
    type ("file" or "dir"), size, modified.
    """
    depth = min(depth, config.MAX_LIST_DEPTH)

    root = resolve_vault_path(relative_path)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {relative_path}")

    vault_root = config.VAULT_PATH.resolve()
    results: list[dict] = []

    def _walk(dir_path: Path, current_depth: int) -> None:
        if current_depth > depth:
            return

        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: p.name.lower())
        except PermissionError:
            return

        for entry in entries:
            # Skip excluded directories at every level
            if entry.name in config.EXCLUDED_DIRS:
                continue

            is_dir = entry.is_dir()

            if is_dir and not include_dirs:
                # Still recurse even if we're not listing dirs
                _walk(entry, current_depth + 1)
                continue

            if not is_dir and not include_files:
                continue

            # Apply glob pattern filter
            if pattern and not fnmatch.fnmatch(entry.name, pattern):
                if is_dir:
                    _walk(entry, current_depth + 1)
                continue

            try:
                stat = entry.stat()
            except OSError:
                continue

            rel = str(entry.relative_to(vault_root))

            results.append(
                {
                    "name": entry.name,
                    "path": rel,
                    "type": "dir" if is_dir else "file",
                    "size": stat.st_size,
                    "modified": _iso_timestamp(stat.st_mtime),
                }
            )

            if is_dir:
                _walk(entry, current_depth + 1)

    _walk(root, 1)
    return results
