"""Coletores de estado do sistema (Linux) via /proc e stdlib.

Cada coletor retorna um snapshot; o motor compara snapshots consecutivos
para gerar alertas de mudança (novos processos, novas conexões, etc.).
"""

from __future__ import annotations

import hashlib
import os
import pwd
import socket
import struct
from dataclasses import dataclass, field


@dataclass
class Process:
    pid: int
    name: str
    cmdline: str
    uid: int
    user: str


@dataclass
class Connection:
    proto: str
    local: str
    remote: str
    state: str
    inode: str


def list_processes() -> dict[int, Process]:
    procs: dict[int, Process] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        base = f"/proc/{pid}"
        try:
            with open(f"{base}/comm") as f:
                name = f.read().strip()
            with open(f"{base}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("latin-1").strip()
            uid = os.stat(base).st_uid
            user = _uid_name(uid)
        except (OSError, ProcessLookupError):
            continue
        procs[pid] = Process(pid, name, cmdline or name, uid, user)
    return procs


def _uid_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _hex_to_addr(hexaddr: str) -> str:
    ip_hex, port_hex = hexaddr.split(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:  # IPv4
        ip = socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16)))
    else:  # IPv6 (simplificado)
        ip = ip_hex
    return f"{ip}:{port}"


def list_connections() -> list[Connection]:
    conns: list[Connection] = []
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp")):
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local = _hex_to_addr(parts[1])
                remote = _hex_to_addr(parts[2])
            except (ValueError, OSError):
                continue
            state = _TCP_STATES.get(parts[3], parts[3])
            conns.append(Connection(proto, local, remote, state, parts[9]))
    return conns


def logged_users() -> list[str]:
    """Usuários logados via `who`-like parsing de /var/run/utmp (fallback: env)."""
    users: set[str] = set()
    # Abordagem simples e portável: varre processos com terminal (tty).
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        try:
            uid = os.stat(f"/proc/{pid_dir}").st_uid
            with open(f"/proc/{pid_dir}/stat") as f:
                fields = f.read().split()
            tty_nr = int(fields[6])
            if tty_nr != 0 and uid >= 1000:  # sessão interativa de usuário real
                users.add(_uid_name(uid))
        except (OSError, IndexError, ValueError):
            continue
    return sorted(users)


def hash_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def snapshot_files(paths: list[str]) -> dict[str, str]:
    """Hash de arquivos monitorados para checagem de integridade."""
    result: dict[str, str] = {}
    for p in paths:
        if os.path.isfile(p):
            h = hash_file(p)
            if h:
                result[p] = h
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for name in files:
                    fp = os.path.join(root, name)
                    h = hash_file(fp)
                    if h:
                        result[fp] = h
    return result
