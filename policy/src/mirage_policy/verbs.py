"""Verb classes: a small fixed mapping from an input's verb to what kind of thing it does.

The raw verb (``uname``, ``CONFIG``, ``SELECT``, ``GET``) has too many values to learn from on
a few thousand lab decisions, so the context carries its class beside it (phase 2 spec 2.5,
"verb class"). The same class picks the message an explored ``fake_error`` is rendered with
(:mod:`mirage_policy.fake_errors`).

The mapping is data, not behaviour: a verb that is not listed is ``other``, and a class means
something only together with the protocol (``read`` on HTTP is a method, on Redis a command).
Change the tables and bump :data:`VERSION`; it is logged with every decision so a model is
never fed classes from a mapping it was not trained on.
"""

from __future__ import annotations

import re

from mirage_schema.policy import DecideRequest, Protocol

VERSION = "1"
OTHER = "other"

# A leading ``NAME=value`` word is an assignment, not the command (the Cowrie gate sends the
# expanded simple command, assignments included: mirage_gate._is_known skips them the same way).
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _table(classes: dict[str, str]) -> dict[str, str]:
    """{class: "verb verb ..."} -> {verb: class}; a verb listed twice is a mistake."""
    out: dict[str, str] = {}
    for cls, verbs in classes.items():
        for verb in verbs.split():
            if verb in out:
                raise ValueError(f"verb {verb!r} is in two classes: {out[verb]} and {cls}")
            out[verb] = cls
    return out


# Shell commands, by the base name of the command word. Case-sensitive, as a shell is.
_SSH = _table(
    {
        "file_read": (
            "cat head tail less more grep egrep fgrep zcat ls dir find locate stat file wc"
            " strings od xxd hexdump md5sum sha1sum sha256sum sha512sum readlink du diff tac"
            " awk sed cut sort uniq"
        ),
        "file_write": (
            "rm mv cp mkdir rmdir touch chmod chown chgrp chattr ln dd tee truncate shred tar"
            " gzip gunzip bzip2 unzip zip install mktemp vi vim nano"
        ),
        "network": (
            "wget curl ping ping6 nc ncat netcat telnet ssh scp sftp ftp tftp rsync nmap dig"
            " nslookup host ip ifconfig route netstat ss iptables ip6tables nft arp traceroute"
            " socat"
        ),
        "package": "apt apt-get apt-cache aptitude dpkg yum dnf rpm apk opkg pip pip3 npm gem snap",
        "process": (
            "ps top htop kill killall pkill pgrep pidof nohup nice renice crontab at systemctl"
            " service timeout watch screen tmux strace lsof setsid"
        ),
        "system_info": (
            "uname whoami id w who last lastlog hostname hostnamectl uptime free lscpu nproc"
            " lsb_release dmesg env printenv date arch lsblk df mount lspci lsusb getconf which"
            " whereis sysctl"
        ),
        "privilege": (
            "sudo su passwd chpasswd useradd adduser usermod userdel groupadd visudo ssh-keygen"
        ),
        "interpreter": (
            "sh bash dash ash zsh busybox python python2 python3 perl php ruby node lua gcc cc make"
        ),
        "shell_builtin": (
            "cd echo export unset set alias unalias source . exec eval read ulimit umask history"
            " type command exit logout wait jobs fg bg test [ true false : pwd printf shopt trap"
            " hash declare local return shift"
        ),
    }
)

# HTTP methods (upper case).
_HTTP = _table({"read": "GET HEAD OPTIONS", "write": "POST PUT PATCH DELETE"})

# Redis commands (upper case, as DecideRequest.verb() gives them).
_REDIS = _table(
    {
        "read": (
            "GET MGET GETRANGE STRLEN KEYS SCAN EXISTS TYPE TTL PTTL RANDOMKEY DBSIZE INFO DUMP"
            " OBJECT MEMORY HGET HMGET HGETALL HKEYS HVALS HLEN HSCAN LRANGE LLEN LINDEX SMEMBERS"
            " SCARD SISMEMBER SSCAN ZRANGE ZCARD ZSCORE ZSCAN TIME LASTSAVE"
        ),
        "write": (
            "SET SETNX SETEX PSETEX MSET GETSET APPEND INCR INCRBY DECR DECRBY DEL UNLINK EXPIRE"
            " PEXPIRE PERSIST RENAME RENAMENX MOVE COPY RESTORE HSET HMSET HDEL LPUSH RPUSH LPOP"
            " RPOP LSET SADD SREM ZADD ZREM FLUSHALL FLUSHDB PUBLISH"
        ),
        "admin": (
            "CONFIG SAVE BGSAVE BGREWRITEAOF SLAVEOF REPLICAOF MODULE DEBUG SHUTDOWN CLIENT"
            " MONITOR ACL COMMAND CLUSTER SYNC PSYNC MIGRATE SLOWLOG LATENCY FAILOVER SWAPDB"
        ),
        "script": "EVAL EVALSHA EVAL_RO EVALSHA_RO SCRIPT FUNCTION FCALL FCALL_RO",
        "session": (
            "AUTH HELLO PING ECHO SELECT QUIT RESET MULTI EXEC DISCARD WATCH UNWATCH SUBSCRIBE"
            " UNSUBSCRIBE PSUBSCRIBE PUNSUBSCRIBE WAIT"
        ),
    }
)

# The first word of a SQL statement (upper case), or the wire command when there is no SQL.
_MYSQL = _table(
    {
        "read": "SELECT SHOW DESCRIBE DESC EXPLAIN",
        "write": "INSERT UPDATE DELETE REPLACE LOAD TRUNCATE CALL",
        "schema": "CREATE DROP ALTER RENAME",
        "admin": (
            "GRANT REVOKE SET FLUSH KILL INSTALL UNINSTALL RESET PURGE CHANGE SHUTDOWN ANALYZE"
            " OPTIMIZE REPAIR CHECK"
        ),
        "session": (
            "USE BEGIN START COMMIT ROLLBACK SAVEPOINT COM_PING COM_QUIT COM_INIT_DB COM_FIELD_LIST"
        ),
    }
)

_TABLES: dict[Protocol, dict[str, str]] = {
    Protocol.SSH: _SSH,
    Protocol.HTTP: _HTTP,
    Protocol.REDIS: _REDIS,
    Protocol.MYSQL: _MYSQL,
}

# Every class a protocol can produce, ``other`` included: the vocabulary of the ``verb_class``
# context feature. Tests pin it, and the fake-error table is validated against it.
VERB_CLASSES: dict[Protocol, tuple[str, ...]] = {
    protocol: (*dict.fromkeys(table.values()), OTHER) for protocol, table in _TABLES.items()
}


def command_words(argv: list[str] | None) -> list[str]:
    """A shell command's words with the leading assignments removed: ``[command, *args]``."""
    words = list(argv or [])
    while words and _ASSIGNMENT.match(words[0]):
        words.pop(0)
    return words


def verb_key(req: DecideRequest) -> str:
    """The verb as the tables spell it: the command's base name for a shell (so ``/bin/cat``
    and ``X=1 cat`` are ``cat``), upper case for everything else. Empty when there is none."""
    if req.protocol is Protocol.SSH:
        words = command_words(req.argv)
        return words[0].rsplit("/", 1)[-1] if words else ""
    return (req.verb() or "").upper()


def verb_class(req: DecideRequest) -> str:
    """The class of this request's verb; ``other`` for a verb the tables do not list."""
    return _TABLES[req.protocol].get(verb_key(req), OTHER)
