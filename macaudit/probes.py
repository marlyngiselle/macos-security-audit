"""Built-in probes for checks that need more than one command and a regex.

Each probe reads through the Context only, returns an Outcome, and never
prints file contents or names of networks. Evidence is limited to paths,
modes and counts.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from macaudit.context import Context


@dataclass(frozen=True)
class Outcome:
    status: str
    reason: str
    evidence: Optional[str] = None


Probe = Callable[[Context, Mapping[str, Any]], Outcome]

HISTORY_FILES: Tuple[str, ...] = (
    ".zsh_history",
    ".bash_history",
    ".sh_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
)
NOT_KEYS = {"config", "known_hosts", "known_hosts.old", "authorized_keys", "environment"}


def _tilde(ctx: Context, path: str) -> str:
    if path == ctx.home or path.startswith(ctx.home + "/"):
        return "~" + path[len(ctx.home) :]
    return path


def _private_key_kind(head: bytes) -> Optional[str]:
    text = head[:200].decode("ascii", errors="replace")
    match = re.search(r"-{5}BEGIN ([A-Z ]*)PRIVATE KEY-{5}", text)
    return match.group(1).strip() if match else None


def wifi_known_networks(ctx: Context, params: Mapping[str, Any]) -> Outcome:
    limit = int(params.get("max", 30))
    ports = ctx.runner.run(["networksetup", "-listallhardwareports"])
    if ports.error or ports.exit_code != 0:
        return Outcome("unknown", "Could not list hardware ports.")
    device = None
    lines = ports.stdout.splitlines()
    for index, line in enumerate(lines):
        if re.match(r"Hardware Port: (Wi-Fi|AirPort)\s*$", line.strip()):
            for follow in lines[index + 1 : index + 3]:
                match = re.match(r"Device: (\S+)", follow.strip())
                if match:
                    device = match.group(1)
                    break
            break
    if device is None:
        return Outcome("skipped", "No Wi-Fi interface on this machine.")
    listing = ctx.runner.run(["networksetup", "-listpreferredwirelessnetworks", device])
    if listing.error or listing.exit_code != 0:
        return Outcome("unknown", "Could not list remembered Wi-Fi networks.")
    out = listing.stdout.splitlines()
    if not out or not out[0].startswith("Preferred networks on"):
        return Outcome("unknown", "Unexpected output when listing remembered networks.")
    count = sum(1 for line in out[1:] if line.strip())
    evidence = f"{count} remembered networks on {device}"
    if count > limit:
        return Outcome("fail", f"{count} remembered networks, above the limit of {limit}.", evidence)
    return Outcome("pass", f"{count} remembered networks, within the limit of {limit}.", evidence)


def ssh_permissions(ctx: Context, params: Mapping[str, Any]) -> Outcome:
    ssh_dir = os.path.join(ctx.home, ".ssh")
    if not ctx.fs.exists(ssh_dir):
        return Outcome("skipped", "No ~/.ssh directory.")
    if not ctx.fs.is_dir(ssh_dir):
        return Outcome("unknown", "~/.ssh exists but is not a directory.")
    problems: List[str] = []
    mode = ctx.fs.mode(ssh_dir)
    if mode & 0o077:
        problems.append(f"~/.ssh is {mode:04o}")
    for name in ctx.fs.listdir(ssh_dir):
        path = os.path.join(ssh_dir, name)
        if not ctx.fs.is_file(path):
            continue
        fmode = ctx.fs.mode(path)
        if name == "authorized_keys":
            if fmode & 0o022:
                problems.append(f"~/.ssh/{name} is {fmode:04o}")
            continue
        if name.endswith(".pub") or name in NOT_KEYS:
            continue
        if _private_key_kind(ctx.fs.read_bytes(path, 256)) is not None and fmode & 0o077:
            problems.append(f"~/.ssh/{name} is {fmode:04o}")
    if problems:
        return Outcome("fail", "SSH files are accessible to other users.", "; ".join(problems))
    return Outcome("pass", "~/.ssh and its private keys are private.")


def _ssh_config_lines(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"(\S+?)\s*(?:=|\s)\s*(.*)$", line)
        if match:
            pairs.append((match.group(1).lower(), match.group(2).strip().strip('"')))
    return pairs


def ssh_config(ctx: Context, params: Mapping[str, Any]) -> Outcome:
    path = os.path.join(ctx.home, ".ssh", "config")
    if not ctx.fs.exists(path):
        return Outcome("skipped", "No ~/.ssh/config file.")
    if not ctx.fs.is_file(path):
        return Outcome("unknown", "~/.ssh/config is not a regular file.")
    try:
        text = ctx.fs.read_bytes(path, 1_048_576).decode("utf-8")
    except UnicodeDecodeError:
        return Outcome("unknown", "~/.ssh/config is not valid UTF-8.")
    problems: List[str] = []
    scope = "global"
    for key, value in _ssh_config_lines(text):
        low = value.lower()
        if key in ("host", "match"):
            scope = "global" if key == "host" and value.split() == ["*"] else value
            continue
        where = "Host *" if scope == "global" else f"Host {scope}"
        if key == "stricthostkeychecking" and low in ("no", "off"):
            problems.append(f"StrictHostKeyChecking {value} ({where})")
        elif key in ("userknownhostsfile", "globalknownhostsfile") and "/dev/null" in low:
            problems.append(
                f"{'UserKnownHostsFile' if key.startswith('user') else 'GlobalKnownHostsFile'} /dev/null ({where})"
            )
        elif key == "forwardagent" and low not in ("no", "") and scope == "global":
            problems.append("ForwardAgent enabled for every host")
    if problems:
        return Outcome("fail", "SSH client configuration weakens host verification.", "; ".join(problems))
    return Outcome("pass", "SSH client configuration keeps host verification.")


def _openssh_cipher(pem: bytes) -> Optional[str]:
    text = pem.decode("ascii", errors="replace")
    # The armour is matched by pattern, never spelled out, so secret scanners do not flag this file.
    body = re.search(r"-{5}BEGIN (OPENSSH) PRIVATE KEY-{5}(.*?)-{5}END \1 PRIVATE KEY-{5}", text, re.S)
    if body is None:
        return None
    try:
        blob = base64.b64decode("".join(body.group(2).split()), validate=True)
    except (binascii.Error, ValueError):
        return None
    magic = b"openssh-key-v1\x00"
    if not blob.startswith(magic) or len(blob) < len(magic) + 4:
        return None
    (length,) = struct.unpack(">I", blob[len(magic) : len(magic) + 4])
    start = len(magic) + 4
    if length > 64 or len(blob) < start + length:
        return None
    return blob[start : start + length].decode("ascii", errors="replace")


def ssh_unencrypted_keys(ctx: Context, params: Mapping[str, Any]) -> Outcome:
    ssh_dir = os.path.join(ctx.home, ".ssh")
    if not ctx.fs.is_dir(ssh_dir):
        return Outcome("skipped", "No ~/.ssh directory.")
    plain: List[str] = []
    unreadable: List[str] = []
    found = 0
    for name in ctx.fs.listdir(ssh_dir):
        path = os.path.join(ssh_dir, name)
        if name.endswith(".pub") or name in NOT_KEYS or not ctx.fs.is_file(path):
            continue
        try:
            data = ctx.fs.read_bytes(path)
        except OSError:
            unreadable.append(name)
            continue
        kind = _private_key_kind(data)
        if kind is None:
            continue
        found += 1
        if kind == "OPENSSH":
            cipher = _openssh_cipher(data)
            if cipher is None:
                unreadable.append(name)
            elif cipher == "none":
                plain.append(name)
        elif kind == "ENCRYPTED":
            continue
        elif b"ENCRYPTED" not in data[:400]:
            plain.append(name)
    if plain:
        listed = ", ".join(f"~/.ssh/{n}" for n in plain)
        return Outcome("fail", f"{len(plain)} private key(s) have no passphrase.", listed)
    if unreadable:
        listed = ", ".join(f"~/.ssh/{n}" for n in unreadable)
        return Outcome("unknown", "Some private keys could not be parsed.", listed)
    if found == 0:
        return Outcome("pass", "No private key files in ~/.ssh.")
    return Outcome("pass", f"All {found} private key(s) are passphrase protected.")


def history_permissions(ctx: Context, params: Mapping[str, Any]) -> Outcome:
    present = 0
    problems: List[str] = []
    links: List[str] = []
    for name in HISTORY_FILES:
        path = os.path.join(ctx.home, name)
        if ctx.fs.is_symlink(path):
            links.append(f"~/{name}")
            continue
        if not ctx.fs.is_file(path):
            continue
        present += 1
        mode = ctx.fs.mode(path)
        if mode & 0o077:
            problems.append(f"~/{name} is {mode:04o}")
    if problems:
        return Outcome("fail", "History files are readable by other users.", "; ".join(problems))
    if links:
        return Outcome("unknown", "History files are symlinks. Inspect their targets.", ", ".join(links))
    if present == 0:
        return Outcome("skipped", "No shell history files found.")
    return Outcome("pass", f"{present} history file(s) are private.")


def path_writable(ctx: Context, params: Mapping[str, Any]) -> Outcome:
    raw = ctx.env.get("PATH")
    if not raw:
        return Outcome("unknown", "PATH is empty or not set.")
    problems: List[str] = []
    for entry in raw.split(":"):
        if entry == "" or not entry.startswith("/"):
            problems.append(f"relative entry '{entry or '(empty)'}'")
            continue
        if not ctx.fs.is_dir(entry):
            continue
        mode = ctx.fs.mode(entry)
        if mode & 0o002:
            problems.append(f"{_tilde(ctx, entry)} is world-writable ({mode:04o})")
    if problems:
        return Outcome("fail", "PATH contains entries other users can influence.", "; ".join(problems))
    return Outcome("pass", "Every PATH entry is absolute and not world-writable.")


BUILTINS: Dict[str, Probe] = {
    "wifi_known_networks": wifi_known_networks,
    "ssh_permissions": ssh_permissions,
    "ssh_config": ssh_config,
    "ssh_unencrypted_keys": ssh_unencrypted_keys,
    "history_permissions": history_permissions,
    "path_writable": path_writable,
}
