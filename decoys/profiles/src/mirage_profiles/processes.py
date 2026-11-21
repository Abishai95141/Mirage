"""The decoy's process list (phase 3 spec 3.4): what `ps` shows on this deployment.

Stock Cowrie prints one fixed list on every installation, with a `mysqld` no Debian 12 host
has and no Redis. Here the list is built from two records and nothing else:

- **The machine**, from the deployment's hardware class: `ps -ef` and `ps aux` as a real
  Debian 12 guest printed them just after boot (the kernel's threads for that CPU count,
  systemd and its services, the consoles).
- **The services the profile claims**, from the reference image: who runs each and how much
  memory it holds (`reference/processes.tsv`, recorded by `record-processes.sh`). That
  container starts them by hand, so the command line each shows here is the one its
  package's systemd unit gives, as on a host that booted normally. The units are quoted in
  the record.

What is left out of the class's record is what was there only because of the recording: the
commands that made it, and the helpers systemd starts on demand and stops again within a
minute (`systemd-hostnamed`, `systemd-timedated`, `systemd-fsckd`, the udev worker).

The session's own processes (its `sshd`, its shell, the `ps` itself) are added by the decoy
when the command runs, because their numbers belong to the session.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RECORD = Path(__file__).resolve().parents[2] / "reference" / "processes.tsv"
# What listens: the machine's own sockets (one guest's record serves every class), and the
# reference services' (`reference/record-sockets.sh`).
MACHINE_SOCKETS = Path(__file__).resolve().parents[2] / "hardware" / "sockets.tsv"
SERVICE_SOCKETS = Path(__file__).resolve().parents[2] / "reference" / "sockets.tsv"
# In the class's record only because of how and when it was made.
TRANSIENT = (
    "sh -c ps",
    "ps ",
    "/lib/systemd/systemd-hostnamed",
    "/lib/systemd/systemd-timedated",
    "/lib/systemd/systemd-fsckd",
    "(udev-worker)",
)
COMM_MAX = 15  # the kernel keeps 15 characters of a task's name
# What the sshd serving a root login holds (VSZ, RSS in kB). The reference record cannot hold
# it, because that container has no network to log in over: it was read from `ps aux` in a
# live session on the reference host, by the fingerprint suite, on 17 November 2026.
SESSION_SSHD = (16188, 10540)


@dataclass(frozen=True)
class Service:
    """A recorded service process: its figures, and the command line systemd gives it."""

    comm: str
    user: str
    vsz: int
    rss: int
    threads: int
    args: str  # as recorded, started by hand


def comm_of(args: str) -> str:
    """The short name `ps -e` shows for a command line, as the kernel keeps it."""
    if args.startswith("[") and args.endswith("]"):
        return args[1:-1][:COMM_MAX]
    if args == "/sbin/init" or args.startswith("/sbin/init "):
        return "systemd"  # /sbin/init is a link to it, and it names itself
    if args.startswith("("):
        return args.split()[0][:COMM_MAX]
    title = re.match(r"^([A-Za-z0-9_.-]+): ", args)
    if title:
        return title.group(1)[:COMM_MAX]
    words = args.split()
    if words[0].rsplit("/", 1)[-1].startswith("python") and len(words) > 1:
        return words[1].rsplit("/", 1)[-1][:COMM_MAX]  # a script is named after itself
    return words[0].rsplit("/", 1)[-1].lstrip("-")[:COMM_MAX]


def load_services(path: Path = RECORD) -> dict[str, list[Service]]:
    """The recorded service processes by short name, in the order recorded."""
    out: dict[str, list[Service]] = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        user, vsz, rss, threads, _stat, comm, args = line.split("\t", 6)
        out.setdefault(comm, []).append(Service(comm, user, int(vsz), int(rss), int(threads), args))
    return out


def _minutes(clock: str) -> int:
    hours, minutes = clock.split(":")
    return int(hours) * 60 + int(minutes)


def machine(ps_ef: str, ps_aux: str) -> list[dict[str, Any]]:
    """The class's own processes, from its two recordings joined on the process ID."""
    aux = {}
    for line in ps_aux.splitlines()[1:]:
        cols = line.split(None, 10)
        if len(cols) == 11:
            aux[int(cols[1])] = cols
    rows = []
    for line in ps_ef.splitlines()[1:]:
        cols = line.split(None, 7)
        if len(cols) < 8 or int(cols[1]) not in aux:
            continue
        user, pid, ppid, _c, stime, tty, _time, args = cols
        if args.startswith(TRANSIENT):
            continue
        a = aux[int(pid)]
        rows.append(
            {
                "user": user,
                "pid": int(pid),
                "ppid": int(ppid),
                "vsz": int(a[4]),
                "rss": int(a[5]),
                "tty": tty,
                "stat": a[7],
                "clock": stime,
                "args": args,
                "comm": comm_of(args),
            }
        )
    if not rows:
        raise ValueError("the hardware class's process record has no rows")
    booted = _minutes(rows[0]["clock"])
    for row in rows:
        # Seconds after boot, to the minute: all the record's clock shows.
        row["start"] = max(0, (_minutes(row.pop("clock")) - booted) % 1440) * 60
    return rows


def services(
    recorded: dict[str, list[Service]], cpus: int, after: int, seed: str, taken: set[int]
) -> list[dict[str, Any]]:
    """The profile's services as a host that booted normally runs them: started by systemd
    (parent 1) a few seconds into the boot, with the next free process IDs."""
    rng = random.Random(f"processes:{seed}")
    rows: list[dict[str, Any]] = []
    pid = after
    used = set(taken)

    def add(
        comm: str, service: Service, args: str, stat: str, parent: int, start: int, step: int
    ) -> int:
        nonlocal pid
        pid += step
        while pid in used:  # a kernel thread of the class already has it
            pid += 1
        used.add(pid)
        rows.append(
            {
                "user": service.user,
                "pid": pid,
                "ppid": parent,
                "vsz": service.vsz,
                "rss": service.rss,
                "tty": "?",
                "stat": stat,
                "start": start,
                "args": args,
                "comm": comm,
            }
        )
        return pid

    def soon() -> tuple[int, int]:
        """When systemd gets to a service, seconds into the boot, and how many process IDs
        went to other things first."""
        return rng.randint(3, 9), rng.randint(1, 4)

    redis = recorded["redis-server"][0]
    bind = redis.args.split()[-1]  # the address it serves, as its own title says
    add("redis-server", redis, f"/usr/bin/redis-server {bind}", "Ssl", 1, *soon())
    maria = recorded["mariadbd"][0]
    add("mariadbd", maria, "/usr/sbin/mariadbd", "Ssl", 1, *soon())
    master = next(s for s in recorded["nginx"] if "master" in s.args)
    worker = next(s for s in recorded["nginx"] if "worker" in s.args)
    unit = "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"
    started, step = soon()
    parent = add("nginx", master, unit, "Ss", 1, started, step)
    for _ in range(cpus):  # the master forks a worker for each processor, one after another
        add("nginx", worker, "nginx: worker process", "S", parent, started, 1)
    return rows


def load_sockets(path: Path) -> tuple[list[dict[str, Any]], dict[str, list[int]]]:
    """A socket record's rows, and the figures its comment lines give (`# name<TAB>n...`)."""
    rows, figures = [], {}
    for line in path.read_text().splitlines():
        cols = line.split("\t")
        if line.startswith("# ") and len(cols) > 1 and all(c.isdigit() for c in cols[1:]):
            figures[cols[0][2:]] = [int(c) for c in cols[1:]]
        if not line.strip() or line.startswith("#"):
            continue
        netid, state, recv_q, send_q, local, port, peer, _peer_port, comm, fd = cols
        rows.append(
            {
                "netid": netid,
                "state": state,
                "recv_q": int(recv_q),
                "send_q": int(send_q),
                "local": local,
                "port": int(port),
                "peer": peer,
                "comm": comm,
                "fd": int(fd) if fd.isdigit() else None,
            }
        )
    return rows, figures


def sockets(
    rows: list[dict[str, Any]],
    listener: int,
    private_ip: str,
    interface: str,
    seed: str,
    machine: Path = MACHINE_SOCKETS,
    services_record: Path = SERVICE_SOCKETS,
) -> dict[str, Any]:
    """What `ss` shows listening on this deployment: the machine's own sockets and the
    services', each held by the processes of this deployment's list that would hold it.

    A socket whose program is not in the process list is left out: nothing may listen that
    `ps` does not show. The kernel lists sockets in the order of a hash that differs from one
    boot to the next, so the order within a protocol and address family is this deployment's
    own, from its seed."""
    recorded, figures = load_sockets(machine)
    seen = {(r["netid"], r["local"], r["port"]) for r in recorded}
    for row in load_sockets(services_record)[0]:
        if (row["netid"], row["local"], row["port"]) not in seen:  # sshd is in both
            recorded.append(row)
    by_comm: dict[str, list[int]] = {}
    for p in rows:
        by_comm.setdefault(p["comm"], []).append(p["pid"])
    out = []
    for row in recorded:
        # sshd's sessions close the listening socket; every other holder is a fork that kept it.
        pids = [listener] if row["comm"] == "sshd" else by_comm.get(row["comm"], [])
        if not pids:
            continue
        local = row["local"].replace("{{private_ip}}", private_ip)
        local = local.replace("{{interface}}", interface)
        if "{{" in local or local.startswith("%"):
            continue  # a profile without the value the row needs
        out.append({**row, "local": local, "v6": row["local"].startswith("["), "pids": pids})
    rng = random.Random(f"sockets:{seed}")
    ordered = []
    for netid in ("udp", "tcp"):
        for v6 in (False, True):
            group = [r for r in out if r["netid"] == netid and r["v6"] is v6]
            rng.shuffle(group)
            ordered += group
    services_count = sum(1 for r in ordered if (r["netid"], r["local"], r["port"]) not in seen)
    return {
        "listening": ordered,
        # Every socket on the machine, of any kind, as `ss -s` counts them: the recorded
        # machine's, and one more for each socket a service of ours listens on.
        "total": figures.get("sockets_total", [0])[0] + services_count,
        "raw": figures.get("raw", [0, 0, 0]),
    }


def table(
    ps_ef: str,
    ps_aux: str,
    cpus: int,
    memory_kb: int,
    seed: str,
    record: Path = RECORD,
    private_ip: str = "",
    interface: str = "",
) -> dict[str, Any]:
    """Everything the decoy needs to print a process list for this deployment, and the
    sockets those processes listen on."""
    rows = machine(ps_ef, ps_aux)
    listener = next((r["pid"] for r in rows if r["comm"] == "sshd"), None)
    if listener is None:
        raise ValueError("the hardware class's process record has no sshd listener")
    boot_time = [r["pid"] for r in rows if r["start"] == 0 and not r["args"].startswith("[")]
    taken = {r["pid"] for r in rows}
    recorded = load_services(record)
    rows += services(recorded, cpus, max(boot_time), seed, taken)
    rows.sort(key=lambda r: r["pid"])
    if len({r["pid"] for r in rows}) != len(rows):
        raise ValueError("two processes share an ID")
    session = {"sshd": list(SESSION_SSHD)}
    for comm in ("bash", "ps"):
        session[comm] = [recorded[comm][0].vsz, recorded[comm][0].rss]
    return {
        "version": 1,
        "memory_kb": memory_kb,
        "listener_pid": listener,
        "session": session,
        "processes": rows,
        "sockets": sockets(rows, listener, private_ip, interface, seed),
    }
