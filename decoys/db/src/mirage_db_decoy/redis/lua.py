"""EVAL without Lua: a tokenizer finds what Redis 7.0's sandbox would reject.

Nothing here runs a script. The commonest probes (CVE-2022-0543's ``package.loadlib``,
``os.execute``, ``io.popen``) read a global the sandbox does not have, and Redis 7.0 fails
them with a fixed message naming the variable and the script's SHA-1, which we can reproduce.
"""

from __future__ import annotations

import re

from mirage_db_decoy.redis.resp import Error, err

KEYWORDS = frozenset(
    [
        "and",
        "break",
        "do",
        "else",
        "elseif",
        "end",
        "false",
        "for",
        "function",
        "goto",
        "if",
        "in",
        "local",
        "nil",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "true",
        "until",
        "while",
    ]
)
# Globals of Redis 7.0's eval environment (Lua 5.1 base minus dofile/loadfile, the loaded
# libraries, the Redis API and the script arguments).
GLOBALS = frozenset(
    [
        "assert",
        "collectgarbage",
        "error",
        "gcinfo",
        "getfenv",
        "getmetatable",
        "ipairs",
        "load",
        "loadstring",
        "next",
        "pairs",
        "pcall",
        "print",
        "rawequal",
        "rawget",
        "rawset",
        "select",
        "setfenv",
        "setmetatable",
        "tonumber",
        "tostring",
        "type",
        "unpack",
        "xpcall",
        "newproxy",
        "coroutine",
        "_G",
        "_VERSION",
        "table",
        "string",
        "math",
        "debug",
        "cjson",
        "struct",
        "cmsgpack",
        "bit",
        "redis",
        "KEYS",
        "ARGV",
        "self",
    ]
)

_TOKEN = re.compile(
    r"""(?P<nl>\n)|(?P<ws>[ \t\r\f\v]+)
    |(?P<long>(?:--)?\[(?P<eq>=*)\[)
    |(?P<comment>--[^\n]*)
    |(?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
    |(?P<name>[A-Za-z_][A-Za-z0-9_]*)
    |(?P<num>0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
    |(?P<op>\.\.\.|\.\.|==|~=|<=|>=|::|[-+*/%^\#<>=(){}\[\];:,.])
    |(?P<other>.)""",
    re.X | re.S,
)


def tokens(src: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    pos, line = 0, 1
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if m is None:  # unterminated string: Lua would refuse to compile; stop here
            break
        kind = m.lastgroup or "other"
        if kind == "long":
            close = "]" + m.group("eq") + "]"
            end = src.find(close, m.end())
            end = len(src) if end < 0 else end + len(close)
            line += src.count("\n", pos, end)
            pos = end
            continue
        if kind == "str":
            line += m.group().count("\n")
        elif kind == "nl":
            line += 1
        elif kind not in ("ws", "comment"):
            out.append((kind, m.group(), line))
        pos = m.end()
    return out


def first_missing_global(src: str) -> tuple[str, int] | None:
    """The first name read that is neither local nor a sandbox global, with its line."""
    toks = tokens(src)
    declared: set[str] = set()
    mode = None  # "decl" after local/for, "fname" after function, "params" inside (...)
    depth = 0
    for i, (kind, val, line) in enumerate(toks):
        prev = toks[i - 1][1] if i else ""
        nxt = toks[i + 1][1] if i + 1 < len(toks) else ""
        if kind == "op":
            depth += {"{": 1, "}": -1}.get(val, 0)
            if mode == "fname" and val == "(":
                mode = "params"
            elif mode == "params":
                mode = None if val == ")" else mode
            elif not (mode == "fname" and val in ".:") and not (mode == "decl" and val == ","):
                mode = None
            continue
        if kind != "name":
            mode = None
            continue
        if val in ("local", "for", "function"):
            mode = "fname" if val == "function" else "decl"
            continue
        if val in KEYWORDS:
            mode = None
            continue
        if mode:
            if not (mode == "fname" and prev in (".", ":")):
                declared.add(val)
            continue
        if prev in (".", ":", "goto", "::") or (nxt == "=" and depth and prev in ("{", ",", ";")):
            continue
        if val not in declared and val not in GLOBALS:
            return val, line
    return None


_RETURN = re.compile(
    r"\s*return\s+(?:(?P<num>-?\d+(?:\.\d+)?)|'(?P<sq>[^'\\]*)'|\"(?P<dq>[^\"\\]*)\""
    r"|(?P<arr>KEYS|ARGV)\[(?P<idx>\d+)\]|(?P<kw>nil|true|false))\s*;?\s*",
    re.S,
)


def evaluate(script: bytes, keys: list[bytes], args: list[bytes]) -> object:
    """The reply Redis 7.0 gives for ``script``, as far as static reading can tell."""
    import hashlib

    sha = hashlib.sha1(script).hexdigest()  # noqa: S324 - Redis names scripts by SHA-1
    src = script.decode("utf-8", errors="replace")
    missing = first_missing_global(src)
    if missing:
        name, line = missing
        return err(
            f"user_script:{line}: Script attempted to access nonexistent global variable "
            f"'{name}' script: {sha}, on @user_script:{line}."
        )
    if not src.strip():
        return None
    m = _RETURN.fullmatch(src)
    if m:
        if m["num"]:
            return int(float(m["num"]))
        if m["sq"] is not None or m["dq"] is not None:
            return (m["sq"] if m["sq"] is not None else m["dq"]).encode()
        if m["arr"]:
            seq = keys if m["arr"] == "KEYS" else args
            i = int(m["idx"])
            return seq[i - 1] if 0 < i <= len(seq) else None
        return 1 if m["kw"] == "true" else None
    # Anything that needs a real interpreter (redis.call included) gets the error Redis
    # gives for a command it cannot run from a script. A known gap.
    return Error(
        b"ERR Unknown Redis command called from script script: %s, on @user_script:1."
        % sha.encode()
    )
