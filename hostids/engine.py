"""Motor de detecção: compara snapshots e gera alertas."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import collectors


# Padrões de linha de comando frequentemente suspeitos.
_SUSPICIOUS_CMD = [
    (re.compile(r"\bnc\b.*-e"), "netcat com execução (-e) — possível reverse shell"),
    (re.compile(r"/dev/tcp/"), "redirecionamento /dev/tcp — possível reverse shell"),
    (re.compile(r"bash\s+-i"), "shell interativo bash -i"),
    (re.compile(r"base64\s+-d"), "decode base64 (ofuscação)"),
    (re.compile(r"curl.*\|\s*(ba)?sh"), "curl pipe para shell"),
    (re.compile(r"wget.*\|\s*(ba)?sh"), "wget pipe para shell"),
    (re.compile(r"python.*-c.*socket"), "python com socket inline"),
    (re.compile(r"chmod\s+\+x\s+/tmp"), "tornar executável em /tmp"),
    (re.compile(r"\bnmap\b"), "execução de scanner nmap"),
]


@dataclass
class Alert:
    severity: str      # info | warning | critical
    category: str
    message: str
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def check_new_processes(old: dict, new: dict) -> list[Alert]:
    alerts: list[Alert] = []
    for pid, proc in new.items():
        if pid not in old:
            sev = "info"
            reasons = []
            for rx, desc in _SUSPICIOUS_CMD:
                if rx.search(proc.cmdline):
                    sev = "critical"
                    reasons.append(desc)
            msg = f"Novo processo PID {pid} ({proc.name}) por {proc.user}: {proc.cmdline[:120]}"
            if reasons:
                msg += " | ⚠ " + "; ".join(reasons)
            alerts.append(Alert(sev, "process", msg))
    return alerts


def check_new_connections(old: list, new: list) -> list[Alert]:
    old_keys = {(c.proto, c.local, c.remote) for c in old}
    alerts: list[Alert] = []
    for c in new:
        key = (c.proto, c.local, c.remote)
        if key not in old_keys and c.state in ("ESTABLISHED", "SYN_SENT"):
            remote_ip = c.remote.rsplit(":", 1)[0]
            sev = "warning" if not remote_ip.startswith(("127.", "0.0.0.0", "::")) else "info"
            alerts.append(Alert(sev, "network",
                                f"Nova conexão {c.proto} {c.local} -> {c.remote} [{c.state}]"))
    return alerts


def check_users(old: list, new: list) -> list[Alert]:
    alerts: list[Alert] = []
    for u in set(new) - set(old):
        alerts.append(Alert("warning", "auth", f"Novo usuário logado: {u}"))
    return alerts


def check_file_integrity(old: dict, new: dict) -> list[Alert]:
    alerts: list[Alert] = []
    for path, h in new.items():
        if path in old and old[path] != h:
            alerts.append(Alert("critical", "integrity",
                                f"Arquivo MODIFICADO: {path}"))
    for path in old.keys() - new.keys():
        alerts.append(Alert("critical", "integrity", f"Arquivo REMOVIDO: {path}"))
    for path in new.keys() - old.keys():
        alerts.append(Alert("warning", "integrity", f"Arquivo NOVO: {path}"))
    return alerts


@dataclass
class Snapshot:
    processes: dict
    connections: list
    users: list
    files: dict


def take_snapshot(watch_files: list[str] | None = None) -> Snapshot:
    return Snapshot(
        processes=collectors.list_processes(),
        connections=collectors.list_connections(),
        users=collectors.logged_users(),
        files=collectors.snapshot_files(watch_files or []),
    )


def diff(old: Snapshot, new: Snapshot) -> list[Alert]:
    alerts: list[Alert] = []
    alerts += check_new_processes(old.processes, new.processes)
    alerts += check_new_connections(old.connections, new.connections)
    alerts += check_users(old.users, new.users)
    alerts += check_file_integrity(old.files, new.files)
    return alerts
