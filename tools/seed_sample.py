"""Seed data (work package 0.6): sample the public Cowrie corpus and replay it through the stack.

The corpus is "Deployment of 160 Cowrie SSH honeypot instances across four distinct
configurations", Zenodo record 21260400, CC BY 4.0 (28.7 GB). Its raw logs sit in one 19 GB
zip. Zip archives keep their directory at the end, so with HTTP range requests this reads the
directory and one member without downloading the archive. Only data_all.zip is touched;
transferred_files.zip holds captured attacker files and is never fetched.

    uv run python tools/seed_sample.py list
    uv run python tools/seed_sample.py sample MEMBER --lines 20000      # -> data/seed/
    uv run python tools/seed_sample.py replay data/seed/FILE.json   # -> raw.honeypot.cowrie.zenodo21260400

Member names in the archive start with "../" (path traversal if extracted naively). This tool
never extracts by member name; samples are written under data/seed/ by base name only.

Attribution: the dataset's authors, Zenodo doi:10.5281/zenodo.21260400, CC BY 4.0.
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import io
import json
import zipfile
from pathlib import Path

import httpx

URL = "https://zenodo.org/records/21260400/files/data_all.zip?download=1"
OUT = Path("data/seed")
SUBJECT = "raw.honeypot.cowrie.zenodo21260400"


class HTTPRangeFile(io.RawIOBase):
    """A read-only, seekable file over HTTP range requests, with a read-ahead buffer."""

    def __init__(self, url: str, block: int = 1 << 20) -> None:
        self._http = httpx.Client(follow_redirects=True, timeout=60)
        self.url = url
        self.size = int(self._http.head(url).headers["content-length"])
        self.pos = 0
        self.block = block
        self._buf_start, self._buf = 0, b""
        self.fetched = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.pos, io.SEEK_END: self.size}[whence]
        self.pos = max(0, min(self.size, base + offset))
        return self.pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""
        end = self.pos + n
        if not (self._buf_start <= self.pos and end <= self._buf_start + len(self._buf)):
            want_end = min(self.size, max(end, self.pos + self.block)) - 1
            r = self._http.get(self.url, headers={"Range": f"bytes={self.pos}-{want_end}"})
            if r.status_code != 206:
                raise RuntimeError(f"server ignored the range request ({r.status_code})")
            self._buf_start, self._buf = self.pos, r.content
            self.fetched += len(r.content)
        off = self.pos - self._buf_start
        data = self._buf[off : off + n]
        self.pos += len(data)
        return data

    def readinto(self, b) -> int:  # type: ignore[override]
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


def _archive() -> tuple[HTTPRangeFile, zipfile.ZipFile]:
    f = HTTPRangeFile(URL)
    return f, zipfile.ZipFile(f)


def cmd_list(_args: argparse.Namespace) -> None:
    f, z = _archive()
    infos = z.infolist()
    print(f"{len(infos)} members; directory read with {f.fetched / 1e6:.1f} MB transferred")
    for info in sorted(infos, key=lambda i: i.file_size)[:40]:
        print(
            f"{info.file_size / 1e6:10.1f} MB  {info.compress_size / 1e6:8.1f} MB packed  {info.filename}"
        )


def cmd_sample(args: argparse.Namespace) -> None:
    f, z = _archive()
    info = z.getinfo(args.member)
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / (Path(args.member).name.removesuffix(".gz") + ".sample.json")
    kept = 0
    with z.open(info) as raw, dest.open("w") as out:
        stream = gzip.GzipFile(fileobj=raw) if args.member.endswith(".gz") else raw
        for line in io.TextIOWrapper(stream, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "eventid" in rec:
                out.write(json.dumps(rec) + "\n")
                kept += 1
            if kept >= args.lines:
                break
    print(f"wrote {kept} records to {dest} ({f.fetched / 1e6:.1f} MB transferred)")


async def _replay(path: Path, url: str) -> None:
    import nats

    nc = await nats.connect(url)
    js = nc.jetstream()
    n = 0
    with path.open() as fh:
        for line in fh:
            await js.publish(SUBJECT, line.strip().encode())
            n += 1
    await nc.drain()
    print(f"published {n} records to {SUBJECT}")


def cmd_replay(args: argparse.Namespace) -> None:
    asyncio.run(_replay(Path(args.file), args.nats))


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    s = sub.add_parser("sample")
    s.add_argument("member")
    s.add_argument("--lines", type=int, default=20000)
    s.set_defaults(fn=cmd_sample)
    r = sub.add_parser("replay")
    r.add_argument("file")
    r.add_argument("--nats", default="nats://127.0.0.1:4222")
    r.set_defaults(fn=cmd_replay)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
