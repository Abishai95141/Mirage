"""Reading a model's answer as it arrives (docs/06-phase-3-spec.md, decisions R8 and R9).

The model writes one JSON object whose first field is ``stdout``:

    {"stdout": "...", "stderr": "...", "exit_code": 0, "ops": [...]}

Waiting for the whole object would mean seconds of silence before a long listing. So the
``stdout`` string is decoded while it is still being written, and each line is handed on as
soon as it is complete. The rest of the object, short and needed whole, is read at the end.
"""

from __future__ import annotations

import json
from typing import Any

_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class Malformed(ValueError):
    """The text is not the object asked for."""


class Stream:
    """Feed it the answer's text in pieces. ``lines()`` gives the complete lines of stdout
    decoded so far that have not been given yet; ``finish()`` gives the whole answer."""

    def __init__(self) -> None:
        self._text = ""
        self._pos = 0  # how far the stdout string has been decoded
        self._state = "before"  # before, inside, after
        self._pending = ""  # decoded stdout not yet given out as a line
        self.stdout = ""  # all of stdout decoded so far

    def feed(self, piece: str) -> None:
        self._text += piece
        if self._state == "before":
            self._find_start()
        if self._state == "inside":
            self._decode()

    def _find_start(self) -> None:
        text = self._text.lstrip()
        offset = len(self._text) - len(text)
        opening = '{"stdout":'
        compact = "".join(text.split())  # the key may be written with blanks around it
        if len(compact) < len(opening):
            if not opening.startswith(compact):
                raise Malformed("the answer does not start with stdout")
            return
        if not compact.startswith(opening):
            raise Malformed("the answer does not start with stdout")
        colon = text.index(":", text.index('"stdout"'))
        rest = text[colon + 1 :]
        stripped = rest.lstrip()
        if not stripped:
            return
        if stripped[0] != '"':
            raise Malformed("stdout is not a string")
        self._pos = offset + colon + 1 + (len(rest) - len(stripped)) + 1
        self._state = "inside"

    def _decode(self) -> None:
        text, i, out = self._text, self._pos, []
        while i < len(text):
            c = text[i]
            if c == '"':
                self._state = "after"
                i += 1
                break
            if c == "\\":
                if i + 1 >= len(text):
                    break  # the escape is not all here yet
                e = text[i + 1]
                if e == "u":
                    if i + 6 > len(text):
                        break
                    try:
                        code = int(text[i + 2 : i + 6], 16)
                    except ValueError as exc:
                        raise Malformed("a bad \\u escape in stdout") from exc
                    if 0xDC00 <= code < 0xE000:
                        raise Malformed("half a surrogate pair in stdout")
                    if 0xD800 <= code < 0xDC00:  # the first half of a pair: wait for both
                        following = text[i + 6 : i + 8]
                        if following != "\\u"[: len(following)]:
                            raise Malformed("half a surrogate pair in stdout")
                        if i + 12 > len(text):
                            break
                        try:
                            low = int(text[i + 8 : i + 12], 16)
                        except ValueError as exc:
                            raise Malformed("a bad \\u escape in stdout") from exc
                        if not 0xDC00 <= low < 0xE000:
                            raise Malformed("half a surrogate pair in stdout")
                        out.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
                        i += 12
                        continue
                    out.append(chr(code))
                    i += 6
                    continue
                if e not in _ESCAPES:
                    raise Malformed("a bad escape in stdout")
                out.append(_ESCAPES[e])
                i += 2
                continue
            if c < " ":
                raise Malformed("a raw control character in stdout")
            out.append(c)
            i += 1
        self._pos = i
        decoded = "".join(out)
        self.stdout += decoded
        self._pending += decoded

    def lines(self) -> list[str]:
        """The complete lines decoded since the last call, without their newlines."""
        if "\n" not in self._pending:
            return []
        *whole, self._pending = self._pending.split("\n")
        return whole

    @property
    def size(self) -> int:
        """Characters of the answer received so far, stdout or not."""
        return len(self._text)

    def stdout_closed(self) -> bool:
        return self._state == "after"

    def last(self) -> str:
        """What is left of stdout after its last newline: a final line that does not end in
        one. Only meaningful once stdout is closed."""
        rest, self._pending = self._pending, ""
        return rest

    def finish(self) -> dict[str, Any]:
        """The whole answer, checked: the four fields and nothing else. Raises ``Malformed``."""
        try:
            doc = json.loads(self._text)
        except ValueError as exc:
            raise Malformed("the answer is not a JSON object") from exc
        if not isinstance(doc, dict):
            raise Malformed("the answer is not a JSON object")
        extra = set(doc) - {"stdout", "stderr", "exit_code", "ops"}
        if extra:
            raise Malformed(f"the answer has fields it was not asked for: {sorted(extra)}")
        stdout, stderr = doc.get("stdout", ""), doc.get("stderr", "")
        code, ops = doc.get("exit_code", 0), doc.get("ops", [])
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            raise Malformed("stdout and stderr are strings")
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
            raise Malformed("exit_code is a number from 0 to 255")
        if not isinstance(ops, list):
            raise Malformed("ops is a list")
        return {"stdout": stdout, "stderr": stderr, "exit_code": code, "ops": ops}
