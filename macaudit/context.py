"""Everything a probe may touch: commands, files and environment.

Probes never call subprocess or os directly. They go through a Context, which
is backed either by the live system or by a recorded replay. That single seam
is what makes every check testable with fixtures and what guarantees the tool
stays read-only: neither implementation exposes a write operation.
"""

from __future__ import annotations

import base64
import os
import shlex
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Protocol

DEFAULT_TIMEOUT = 20


@dataclass(frozen=True)
class CommandOutput:
    """Result of running one command. `error` is set when it never ran cleanly."""

    exit_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None  # "not_found", "timeout", "no_recording"

    @property
    def text(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip("\n")


class Runner(Protocol):
    def which(self, tool: str) -> bool: ...

    def run(
        self,
        argv: List[str],
        env: Optional[Mapping[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> CommandOutput: ...


class FileSystem(Protocol):
    def exists(self, path: str) -> bool: ...

    def is_dir(self, path: str) -> bool: ...

    def is_file(self, path: str) -> bool: ...

    def is_symlink(self, path: str) -> bool: ...

    def mode(self, path: str) -> int: ...

    def listdir(self, path: str) -> List[str]: ...

    def read_bytes(self, path: str, limit: int = 65536) -> bytes: ...


class SystemRunner:
    """Runs real commands. Never escalates privileges and never feeds stdin."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = path if path is not None else os.environ.get("PATH", "")

    def which(self, tool: str) -> bool:
        if os.sep in tool:
            return os.access(tool, os.X_OK)
        return shutil.which(tool, path=self._path) is not None

    def run(
        self,
        argv: List[str],
        env: Optional[Mapping[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> CommandOutput:
        full_env = dict(os.environ)
        full_env["LC_ALL"] = "C"
        if env:
            full_env.update(env)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                env=full_env,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            return CommandOutput(exit_code=None, error="not_found")
        except subprocess.TimeoutExpired:
            return CommandOutput(exit_code=None, error="timeout")
        return CommandOutput(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


class RealFileSystem:
    """Read-only view of the local file system."""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def is_symlink(self, path: str) -> bool:
        return os.path.islink(path)

    def mode(self, path: str) -> int:
        return stat.S_IMODE(os.stat(path).st_mode)

    def listdir(self, path: str) -> List[str]:
        return sorted(os.listdir(path))

    def read_bytes(self, path: str, limit: int = 65536) -> bytes:
        with open(path, "rb") as handle:
            return handle.read(limit)


class ReplayRunner:
    """Answers commands from a recording keyed by the shell-quoted argv."""

    def __init__(self, commands: Mapping[str, Mapping[str, Any]], missing_tools: List[str]) -> None:
        self._commands = commands
        self._missing = set(missing_tools)

    def which(self, tool: str) -> bool:
        return tool not in self._missing and os.path.basename(tool) not in self._missing

    def run(
        self,
        argv: List[str],
        env: Optional[Mapping[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> CommandOutput:
        record = self._commands.get(shlex.join(argv))
        if record is None:
            return CommandOutput(exit_code=None, error="no_recording")
        if record.get("error"):
            return CommandOutput(exit_code=None, error=str(record["error"]))
        return CommandOutput(
            exit_code=int(record.get("exit", 0)),
            stdout=str(record.get("stdout", "")),
            stderr=str(record.get("stderr", "")),
        )


@dataclass
class _Entry:
    kind: str  # "file", "dir" or "symlink"
    mode: int
    content: bytes = b""
    target: str = ""


class FakeFileSystem:
    """An in-memory file system described by a fixture."""

    def __init__(self, entries: Mapping[str, Mapping[str, Any]]) -> None:
        self._entries: Dict[str, _Entry] = {"/": _Entry("dir", 0o755)}
        for path, spec in entries.items():
            self._add(path, spec)

    def _add(self, path: str, spec: Mapping[str, Any]) -> None:
        path = os.path.normpath(path)
        parent = os.path.dirname(path)
        while parent not in self._entries:
            self._entries[parent] = _Entry("dir", 0o755)
            parent = os.path.dirname(parent)
        kind = str(spec.get("type", "file"))
        default_mode = "0755" if kind == "dir" else "0644"
        content = b""
        if "content_b64" in spec:
            content = base64.b64decode(str(spec["content_b64"]))
        elif "content" in spec:
            content = str(spec["content"]).encode("utf-8")
        self._entries[path] = _Entry(
            kind=kind,
            mode=int(str(spec.get("mode", default_mode)), 8),
            content=content,
            target=str(spec.get("target", "")),
        )

    def _resolve(self, path: str, depth: int = 0) -> Optional[_Entry]:
        entry = self._entries.get(os.path.normpath(path))
        if entry is not None and entry.kind == "symlink" and depth < 8:
            return self._resolve(entry.target, depth + 1)
        return entry

    def exists(self, path: str) -> bool:
        return self._resolve(path) is not None

    def is_dir(self, path: str) -> bool:
        entry = self._resolve(path)
        return entry is not None and entry.kind == "dir"

    def is_file(self, path: str) -> bool:
        entry = self._resolve(path)
        return entry is not None and entry.kind == "file"

    def is_symlink(self, path: str) -> bool:
        entry = self._entries.get(os.path.normpath(path))
        return entry is not None and entry.kind == "symlink"

    def mode(self, path: str) -> int:
        entry = self._resolve(path)
        if entry is None:
            raise FileNotFoundError(path)
        return entry.mode

    def listdir(self, path: str) -> List[str]:
        base = os.path.normpath(path)
        if not self.is_dir(base):
            raise NotADirectoryError(path)
        return sorted(os.path.basename(p) for p in self._entries if p != base and os.path.dirname(p) == base)

    def read_bytes(self, path: str, limit: int = 65536) -> bytes:
        entry = self._resolve(path)
        if entry is None:
            raise FileNotFoundError(path)
        if entry.kind != "file":
            raise IsADirectoryError(path)
        return entry.content[:limit]


@dataclass
class Context:
    runner: Runner
    fs: FileSystem
    env: Dict[str, str]
    home: str
    euid: int
    generated_at: Optional[str] = None
    host: Dict[str, str] = field(default_factory=dict)
    cache: Dict[str, CommandOutput] = field(default_factory=dict)

    def run_cached(
        self, argv: List[str], env: Optional[Mapping[str, str]] = None, timeout: int = DEFAULT_TIMEOUT
    ) -> CommandOutput:
        """Run a command once per audit. Several checks read the same listing."""

        key = shlex.join(argv) + "\0" + repr(sorted((env or {}).items()))
        if key not in self.cache:
            self.cache[key] = self.runner.run(argv, env=env, timeout=timeout)
        return self.cache[key]


def system_context() -> Context:
    env = dict(os.environ)
    return Context(
        runner=SystemRunner(env.get("PATH", "")),
        fs=RealFileSystem(),
        env=env,
        home=os.path.expanduser("~"),
        euid=os.geteuid(),
    )


def replay_context(data: Mapping[str, Any]) -> Context:
    """Build a context from a replay document (see examples/replay/)."""

    home = str(data.get("home", "/Users/sample"))

    def expand(value: str) -> str:
        return home + value[1:] if value.startswith("~") else value

    env = {k: expand(str(v)) for k, v in dict(data.get("env", {})).items()}
    env.setdefault("HOME", home)
    path_value = env.get("PATH")
    if path_value is not None:
        env["PATH"] = ":".join(expand(p) for p in path_value.split(":"))
    files = {expand(k): v for k, v in dict(data.get("files", {})).items()}
    return Context(
        runner=ReplayRunner(dict(data.get("commands", {})), list(data.get("missing_tools", []))),
        fs=FakeFileSystem(files),
        env=env,
        home=home,
        euid=int(data.get("euid", 501)),
        generated_at=data.get("generated_at"),
        host={k: str(v) for k, v in dict(data.get("host", {})).items()},
    )
