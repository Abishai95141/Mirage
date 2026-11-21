"""The decoy's process list (phase 3 spec 3.4): built from the hardware class's own record of
a booted machine and the reference image's record of the services, and from nothing else."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mirage_profiles import hardware, processes
from mirage_profiles.generator import main as mirage_profile

ROOT = Path(__file__).resolve().parents[3]
CLASSES = hardware.HardwareClass.available()


def recorded(class_id: str) -> tuple[str, str, dict]:
    cls = hardware.HardwareClass.load(class_id)
    said = {c["argv"]: c["stdout"] for c in cls.commands()}
    return said["ps -ef"], said["ps aux"], cls.facts


@pytest.mark.parametrize(
    ("args", "comm"),
    [
        ("/sbin/init", "systemd"),
        ("[kworker/0:1H-kblockd]", "kworker/0:1H-kb"),
        ("/lib/systemd/systemd-journald", "systemd-journal"),
        ("sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", "sshd"),
        ("nginx: worker process", "nginx"),
        ("/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait", "unattended-upgr"),
        ("/sbin/agetty -o -p -- \\u --noclear - linux", "agetty"),
        ("-bash", "bash"),
        ("/usr/sbin/mariadbd", "mariadbd"),
    ],
)  # fmt: skip
def test_a_process_s_short_name_is_what_the_kernel_keeps(args, comm):
    assert processes.comm_of(args) == comm


def test_the_recorded_services_are_the_four_and_a_session_s_own():
    services = processes.load_services()
    assert {"sshd", "nginx", "mariadbd", "redis-server", "bash", "ps"} <= set(services)
    assert {s.user for s in services["nginx"]} == {"root", "www-data"}
    assert services["mariadbd"][0].user == "mysql" and services["mariadbd"][0].threads > 1
    assert services["redis-server"][0].user == "redis"
    assert all(s.rss > 0 and s.vsz >= s.rss for group in services.values() for s in group)


@pytest.mark.parametrize("class_id", CLASSES)
def test_the_machine_s_part_is_the_class_s_record_without_what_recording_added(class_id):
    ps_ef, ps_aux, _ = recorded(class_id)
    rows = processes.machine(ps_ef, ps_aux)
    by_pid = {r["pid"]: r for r in rows}
    assert by_pid[1]["args"] == "/sbin/init" and by_pid[1]["comm"] == "systemd"
    assert by_pid[2]["args"] == "[kthreadd]" and by_pid[2]["ppid"] == 0
    shown = " ".join(r["args"] for r in rows)
    for gone in ("ps -ef", "ps aux", "systemd-hostnamed", "systemd-timedated", "udev-worker"):
        assert gone not in shown
    # Every row is in both recordings, word for word: nothing here is written by hand.
    for row in rows:
        assert f" {row['pid']} " in ps_ef and row["args"] in ps_ef
        assert str(row["rss"]) in ps_aux
    assert all(r["start"] in (0, 60) for r in rows)


@pytest.mark.parametrize("class_id", CLASSES)
def test_the_table_has_the_machine_the_profile_s_services_and_no_other(class_id):
    ps_ef, ps_aux, facts = recorded(class_id)
    doc = processes.table(ps_ef, ps_aux, facts["cpus"], facts["memory_kb"], "7")
    rows = doc["processes"]
    pids = [r["pid"] for r in rows]
    assert pids == sorted(pids) and len(set(pids)) == len(pids)
    by_comm: dict[str, list[dict]] = {}
    for r in rows:
        by_comm.setdefault(r["comm"], []).append(r)
    # Stock Cowrie's list has a mysqld, which Debian 12 has not had since MariaDB 10.5.
    assert "mysqld" not in by_comm
    (maria,) = by_comm["mariadbd"]
    assert (maria["user"], maria["ppid"], maria["args"]) == ("mysql", 1, "/usr/sbin/mariadbd")
    (redis,) = by_comm["redis-server"]
    assert redis["user"] == "redis" and redis["args"].startswith("/usr/bin/redis-server ")
    master, *workers = by_comm["nginx"]
    assert master["user"] == "root" and master["ppid"] == 1 and "master process" in master["args"]
    assert len(workers) == facts["cpus"]  # a worker for each of the class's processors
    assert all(w["ppid"] == master["pid"] and w["user"] == "www-data" for w in workers)
    assert [w["pid"] for w in workers] == sorted(w["pid"] for w in workers)
    assert all(w["start"] == master["start"] for w in workers)
    (listener,) = [r for r in by_comm["sshd"] if "[listener]" in r["args"]]
    assert doc["listener_pid"] == listener["pid"] and listener["ppid"] == 1
    assert doc["memory_kb"] == facts["memory_kb"]
    assert set(doc["session"]) == {"sshd", "bash", "ps"}


def test_one_seed_gives_one_table_and_another_seed_other_process_ids():
    ps_ef, ps_aux, facts = recorded(CLASSES[0])
    first = processes.table(ps_ef, ps_aux, facts["cpus"], facts["memory_kb"], "1")
    again = processes.table(ps_ef, ps_aux, facts["cpus"], facts["memory_kb"], "1")
    assert first == again
    seen = {
        tuple(
            r["pid"]
            for r in processes.table(ps_ef, ps_aux, facts["cpus"], facts["memory_kb"], str(seed))[
                "processes"
            ]
            if r["comm"] in ("mariadbd", "redis-server", "nginx")
        )
        for seed in range(12)
    }
    assert len(seen) > 1


@pytest.mark.parametrize("class_id", CLASSES)
def test_every_listening_socket_is_held_by_a_process_of_the_table(class_id):
    ps_ef, ps_aux, facts = recorded(class_id)
    doc = processes.table(
        ps_ef, ps_aux, facts["cpus"], facts["memory_kb"], "7",
        private_ip="10.2.117.32", interface=facts["interface"],
    )  # fmt: skip
    comm_of = {r["pid"]: r["comm"] for r in doc["processes"]}
    listening = doc["sockets"]["listening"]
    for s in listening:
        assert s["pids"] and all(comm_of[pid] == s["comm"] for pid in s["pids"])
        assert "{{" not in s["local"]
    tcp = {(s["local"], s["port"]): s for s in listening if s["netid"] == "tcp"}
    # The four services, on the ports the profile's decoys answer on, and the machine's own.
    assert {port for _, port in tcp} == {22, 53, 80, 3306, 5355, 6379}
    assert tcp[("0.0.0.0", 22)]["pids"] == [doc["listener_pid"]]  # not a session's sshd
    nginx = [r["pid"] for r in doc["processes"] if r["comm"] == "nginx"]
    assert sorted(tcp[("0.0.0.0", 80)]["pids"]) == nginx and len(nginx) == facts["cpus"] + 1
    assert tcp[("0.0.0.0", 80)]["fd"] != tcp[("[::]", 80)]["fd"]
    udp = [s for s in listening if s["netid"] == "udp"]
    assert f"10.2.117.32%{facts['interface']}" in {s["local"] for s in udp}  # the DHCP client
    # As ss lists them: datagram sockets first, and IPv4 before IPv6 within each.
    assert [(s["netid"], s["v6"]) for s in listening] == sorted(
        ((s["netid"], s["v6"]) for s in listening), key=lambda k: (k[0] != "udp", k[1])
    )
    assert doc["sockets"]["total"] > len(listening) and len(doc["sockets"]["raw"]) == 3


def test_the_socket_order_is_the_deployment_s_own_and_nothing_listens_unseen():
    ps_ef, ps_aux, facts = recorded(CLASSES[0])

    def order(seed: str) -> list[tuple[str, str, int]]:
        doc = processes.table(
            ps_ef, ps_aux, facts["cpus"], facts["memory_kb"], seed, private_ip="10.0.0.5",
            interface="ens3",
        )  # fmt: skip
        return [(s["netid"], s["local"], s["port"]) for s in doc["sockets"]["listening"]]

    assert order("1") == order("1")
    assert len({tuple(order(str(seed))) for seed in range(8)}) > 1
    # A process list without the resolver has no resolver sockets: ss never names a
    # process ps does not show.
    rows = [r for r in processes.machine(ps_ef, ps_aux) if r["comm"] != "systemd-resolve"]
    listener = next(r["pid"] for r in rows if r["comm"] == "sshd")
    left = processes.sockets(rows, listener, "10.0.0.5", "ens3", "1")["listening"]
    assert {s["comm"] for s in left} == {"sshd", "systemd-network"}
    # Without an address for the DHCP client's socket, that row is left out, not half-filled.
    bare = processes.sockets(rows, listener, "", "", "1")["listening"]
    assert {s["comm"] for s in bare} == {"sshd"}


def test_a_record_with_no_listener_is_refused():
    ps_ef, ps_aux, facts = recorded(CLASSES[0])
    without = "\n".join(line for line in ps_ef.splitlines() if "[listener]" not in line)
    with pytest.raises(ValueError, match="sshd listener"):
        processes.table(without, ps_aux, facts["cpus"], facts["memory_kb"], "1")


def test_rendering_a_profile_writes_the_table_and_tells_the_decoy_where(tmp_path):
    mirage_profile(
        [
            "render",
            str(ROOT / "decoys/profiles/web-db.yaml"),
            "--seed",
            "42",
            "--out",
            str(tmp_path),
        ]
    )
    doc = json.loads((tmp_path / "cowrie/processes.json").read_text())
    host = json.loads((tmp_path / "host.json").read_text())
    assert doc["version"] == 1 and doc["memory_kb"] == host["hardware"]["memory_kb"]
    workers = [r for r in doc["processes"] if r["args"] == "nginx: worker process"]
    assert len(workers) == host["hardware"]["cpus"]
    cfg = (tmp_path / "cowrie/cowrie.cfg").read_text()
    assert "processes = /cowrie/deployment/processes.json" in cfg
    assert f"internet_facing_ip = {host['private_ip']}" in cfg
