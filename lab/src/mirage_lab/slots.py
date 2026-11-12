"""Values for template slots, drawn per simulated actor.

Everything generated here is inert by construction: hosts come from the address ranges and
names reserved for documentation (RFC 5737, RFC 2606), so nothing a scenario types can name a
real machine, and file contents are random bytes.
"""

from __future__ import annotations

import random
import string

DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")  # TEST-NET-1/2/3
DOC_TLDS = ("example", "test", "invalid")
DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/root", "/opt")
EXTS = ("", "", ".sh", ".bin", ".dat", ".txt", ".tmp")
USERS = ("admin", "svc", "deploy", "backup", "ops", "sys", "web", "dev")
_ALNUM = string.ascii_lowercase + string.digits


class Slots:
    """One actor's slot values. A name keeps its value for the actor's whole scenario, so a
    file downloaded in one step is the file made executable in the next."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.values: dict[str, str] = {}
        self._kinds = {
            "ip": self._ip,
            "host": self._host,
            "domain": self._domain,
            "url": self._url,
            "file": self._file,
            "dir": self._dir,
            "path": self._path,
            "hex": self._hex,
            "port": self._port,
            "user": self._user,
            "num": self._num,
            "word": self._word,
        }

    @classmethod
    def names(cls) -> frozenset[str]:
        return frozenset(cls(random.Random(0))._kinds)

    def get(self, name: str) -> str:
        if name not in self.values:
            self.values[name] = self._kinds[name.rstrip("0123456789")]()
        return self.values[name]

    def fill(self, names: list[str], given: dict[str, str]) -> dict[str, str]:
        return {n: given.get(n) or self.get(n) for n in names}

    def _word(self, lo: int = 5, hi: int = 9) -> str:
        first = self.rng.choice(string.ascii_lowercase)
        return first + "".join(self.rng.choices(_ALNUM, k=self.rng.randint(lo, hi) - 1))

    def _ip(self) -> str:
        return f"{self.rng.choice(DOC_NETS)}.{self.rng.randint(1, 254)}"

    def _domain(self) -> str:
        return f"{self._word(4, 8)}.{self.rng.choice(DOC_TLDS)}"

    def _host(self) -> str:
        return self._ip() if self.rng.random() < 0.6 else self._domain()

    def _file(self) -> str:
        return self._word() + self.rng.choice(EXTS)

    def _dir(self) -> str:
        return self.rng.choice(DIRS)

    def _path(self) -> str:
        return f"{self._dir()}/{self._file()}"

    def _url(self) -> str:
        return f"http://{self._host()}/{self._file()}"

    def _hex(self) -> str:
        return "".join(self.rng.choices("0123456789abcdef", k=self.rng.choice((8, 16, 32))))

    def _port(self) -> str:
        return str(
            self.rng.choice((80, 443, 3333, 4444, 8080, 8443, self.rng.randint(1025, 65000)))
        )

    def _user(self) -> str:
        return self.rng.choice(USERS)

    def _num(self) -> str:
        return str(self.rng.randint(1, 9999))

    def payload(self, size: int) -> bytes:
        """An "uploaded file": random bytes, nothing more."""
        return self.rng.randbytes(size)
