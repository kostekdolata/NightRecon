"""Read-only candidate collector for disposable, trusted local Git clones.

No checkout, commit, remote fetch, Git filters or task-provided commands. Working
files are opened relative to directory descriptors without following symlinks.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

from .controller import FileEntry, Rejected, _integer, _require, _sha, path_name


MAX_FILE_BYTES = 1048576
MAX_TOTAL_BYTES = 67108864
TRANSIENT_ROOTS = frozenset({".git", ".venv", "venv", "build", "dist", "results", "logs", "workspace", "work"})


def _git(repo: Path, *args: str) -> bytes:
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
                   "GIT_ATTR_NOSYSTEM": "1"}
    command = ["git", "--no-optional-locks", "--no-replace-objects", "-c",
               "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
               "-c", "protocol.allow=never", "-C", str(repo), *args]
    try:
        result = subprocess.run(command, env=environment, capture_output=True,
                                timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Rejected("Git collector unavailable or timed out") from exc
    _require(result.returncode == 0, "Git collection failed; no partial inventory accepted")
    _require(len(result.stdout) <= MAX_TOTAL_BYTES, "Git collector output limit")
    return result.stdout


def _repository(repo: Path) -> Path:
    _require(os.name == "posix", "descriptor-safe inventory collection requires the POSIX controller host")
    repo = Path(repo).absolute()
    _require(not repo.is_symlink() and (repo / ".git").is_dir()
             and not (repo / ".git").is_symlink(), "trusted standalone Git clone required")
    return repo


def read_base(repo: Path, commit: str) -> dict[str, FileEntry]:
    repo = _repository(repo)
    _sha(commit)
    raw = _git(repo, "ls-tree", "-rz", "--full-tree", commit)
    _require(len(raw) <= 4194304, "tree listing limit")
    entries = [entry for entry in raw.split(b"\x00") if entry]
    _require(len(entries) <= 20000, "tree entry limit")
    result = {}
    total = 0
    for entry in entries:
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        try:
            path = name.decode("ascii")
        except UnicodeError as exc:
            raise Rejected("nonportable Git path") from exc
        path_name(path)
        _sha(object_id)
        _require(kind in {"blob", "commit"} and mode in {"100644", "100755", "120000", "160000"},
                 "unsupported tree entry")
        if kind == "commit":
            content = object_id.encode("ascii")
        else:
            size = int(_git(repo, "cat-file", "-s", object_id))
            _integer(size, 0, MAX_FILE_BYTES)
            content = _git(repo, "cat-file", "blob", object_id)
            _require(len(content) == size, "incomplete Git blob")
        total += len(content)
        _require(total <= MAX_TOTAL_BYTES, "base inventory limit")
        result[path] = FileEntry(mode, content)
    return result


def _read_entry(root_fd: int, path: str) -> FileEntry:
    path_name(path)
    parts = path.split("/")
    directory = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        before = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            return FileEntry("120000", os.fsencode(os.readlink(parts[-1], dir_fd=directory)))
        _require(stat.S_ISREG(before.st_mode), "nonregular candidate entry")
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
            _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
                     "candidate must be a private regular file")
            _require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
                     "candidate replaced during collection")
            _integer(opened.st_size, 0, MAX_FILE_BYTES)
            chunks = []
            remaining = MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
            _require(len(content) <= MAX_FILE_BYTES and len(content) == opened.st_size
                     and (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                     == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                     "candidate changed during collection")
            return FileEntry("100755" if opened.st_mode & 0o111 else "100644", content)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def read_working(repo: Path, base: dict[str, FileEntry]) -> dict[str, FileEntry]:
    """Include untracked files even if hidden by a candidate .gitignore.

    Only fixed build/runtime transient roots and cache/egg-info directories are
    excluded for untracked content. Tracked paths remain included regardless.
    Inventory is not atomic: collect only quiescent disposable workspaces, then
    freeze bytes and validate the resulting immutable artifact, not live files.
    """
    repo = _repository(repo)
    names = set()
    root_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    result = {}
    try:
        def walk(directory: int, prefix: str):
            for name in sorted(os.listdir(directory)):
                path = prefix + name
                path_name(path)
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                transient = ((not prefix and name in TRANSIENT_ROOTS)
                             or name == "__pycache__" or name.endswith(".egg-info"))
                if transient:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                    try:
                        walk(child, path + "/")
                    finally:
                        os.close(child)
                else:
                    names.add(path)
                _require(len(names) <= 20000, "working inventory entry limit")

        # The Git metadata directory is deliberately never traversed.
        # Exclude it before portable path checking in walk.
        def collect_root():
            for name in sorted(os.listdir(root_fd)):
                if name == ".git":
                    continue
                path_name(name)
                info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if name in TRANSIENT_ROOTS or name == "__pycache__" or name.endswith(".egg-info"):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                    try:
                        walk(child, name + "/")
                    finally:
                        os.close(child)
                else:
                    names.add(name)

        collect_root()
        names.update(base)
        _require(len(names) <= 20000, "working inventory entry limit")
        total = 0
        for path in sorted(names):
            try:
                entry = _read_entry(root_fd, path)
            except FileNotFoundError:
                if path in base:
                    continue
                raise Rejected("untracked entry disappeared during collection")
            except OSError as exc:
                raise Rejected("unsafe candidate path or collection race") from exc
            total += len(entry.content)
            _require(total <= MAX_TOTAL_BYTES, "working inventory byte limit")
            result[path] = entry
        return result
    finally:
        os.close(root_fd)
