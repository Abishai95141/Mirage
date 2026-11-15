"""The fake-error table: what an explored ``fake_error`` says, per protocol and verb.

The exploring policy chooses an action; when that action is ``fake_error`` and the matched rule
did not write one, the decoy still needs an output and a code that look like an error of its
protocol (phase 2 spec 2.5). They come from ``rulesets/fake_errors.yaml``, which documents the
format and what each decoy does with the two fields.

Like a rule file, a table that does not validate stops the service from starting: each
protocol's limits (an HTTP status, a MySQL error number, a Redis text without its ``ERR``) are
checked here, at load, so a bad entry can never reach a decoy.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mirage_policy.verbs import VERB_CLASSES, command_words, verb_key
from mirage_schema.policy import MAX_OUTPUT_BYTES, DecideRequest, Protocol

_PLACEHOLDER = re.compile(r"\{([a-z_]*)\}")
# What a placeholder may be, and where. ``arg`` and ``shell`` exist only for a shell command.
_ALWAYS = frozenset({"verb", "verb_lower"})
_SSH_ONLY = frozenset({"arg", "shell"})
# A default must always render, so it may not depend on the command having an argument.
_NOT_IN_DEFAULT = frozenset({"arg"})


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output: str = ""
    exit_code: int | None = None

    def placeholders(self) -> set[str]:
        return set(_PLACEHOLDER.findall(self.output))

    def fill(self, values: dict[str, str]) -> str | None:
        """The output with its placeholders filled, or None when one has no value."""
        if any(not values.get(name) for name in self.placeholders()):
            return None
        return _PLACEHOLDER.sub(lambda m: values[m.group(1)], self.output)


class ProtocolTable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: Entry
    classes: dict[str, Entry] = Field(default_factory=dict)
    verbs: dict[str, Entry] = Field(default_factory=dict)

    def entries(self) -> list[tuple[str, Entry]]:
        named = [(f"classes.{k}", e) for k, e in self.classes.items()]
        named += [(f"verbs.{k}", e) for k, e in self.verbs.items()]
        return [("default", self.default), *named]


def _check(protocol: Protocol, where: str, entry: Entry) -> None:
    """One entry against what its decoy can render (see the YAML file's header)."""
    at = f"{protocol.value}.{where}"
    out, code = entry.output, entry.exit_code
    if len(out.encode()) > MAX_OUTPUT_BYTES:
        raise ValueError(f"{at}: output over {MAX_OUTPUT_BYTES} bytes")
    allowed = _ALWAYS | (_SSH_ONLY if protocol is Protocol.SSH else frozenset())
    if where == "default":
        allowed = allowed - _NOT_IN_DEFAULT
    if unknown := entry.placeholders() - allowed:
        raise ValueError(f"{at}: placeholder(s) {sorted(unknown)} not available here")
    if protocol is Protocol.SSH:
        # Cowrie gate, _apply: output to stderr as it is, exit_code becomes $?.
        if code is None or not 1 <= code <= 255:
            raise ValueError(f"{at}: exit_code must be an exit status, 1..255")
        if out and not out.endswith("\n"):
            raise ValueError(f"{at}: a stderr line must end with a newline")
    elif protocol is Protocol.HTTP:
        # http handler.py, decide: the status is clamped to 400..599; empty output is the
        # profile's own error page.
        if code is None or not 400 <= code <= 599:
            raise ValueError(f"{at}: exit_code must be an HTTP status, 400..599")
    elif protocol is Protocol.REDIS:
        # redis handler.py, command: reply is "-ERR " + output.strip(); exit_code is unused.
        if code is not None:
            raise ValueError(f"{at}: Redis has no error code; leave exit_code out")
        if not out or out != out.strip() or "\n" in out or "\r" in out:
            raise ValueError(f"{at}: output must be one line of text, with nothing around it")
        if out.startswith("ERR "):
            raise ValueError(f"{at}: the decoy adds 'ERR ' itself; write only what follows it")
    else:
        # mysql handler.py, commands: err_packet(code, output) with SQLSTATE HY000; the code
        # is two bytes on the wire.
        if code is None or not 1000 <= code <= 65535:
            raise ValueError(f"{at}: exit_code must be a MariaDB error number, 1000..65535")
        if not out or "\n" in out:
            raise ValueError(f"{at}: output must be the one-line error message")


class TableFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1, le=1)
    ssh: ProtocolTable
    http: ProtocolTable
    redis: ProtocolTable
    mysql: ProtocolTable

    @model_validator(mode="after")
    def _fits_each_decoy(self) -> TableFile:
        for protocol in Protocol:
            table: ProtocolTable = getattr(self, protocol.value)
            if unknown := set(table.classes) - set(VERB_CLASSES[protocol]):
                raise ValueError(f"{protocol.value}: unknown verb class(es) {sorted(unknown)}")
            # verb_key() upper-cases every verb but a shell's: another spelling never matches.
            lower = [v for v in table.verbs if v != v.upper()]
            if protocol is not Protocol.SSH and lower:
                raise ValueError(f"{protocol.value}: verbs must be upper case: {sorted(lower)}")
            for where, entry in table.entries():
                _check(protocol, where, entry)
        return self


def _values(req: DecideRequest) -> dict[str, str]:
    """What the placeholders stand for in this request. A missing one is left out."""
    if req.protocol is not Protocol.SSH:
        verb = req.verb() or ""
        return {"verb": verb, "verb_lower": verb.lower()}
    words = command_words(req.argv)
    verb = words[0] if words else ""
    # The last operand: tools name the file they failed on, and options are not files.
    arg = next((w for w in reversed(words[1:]) if w and not w.startswith("-")), "")
    # sshd runs an exec request as "bash -c", which names itself differently in its errors.
    shell = "bash: line 1" if req.interactive is False else "-bash"
    return {"verb": verb, "verb_lower": verb.lower(), "arg": arg, "shell": shell}


class FakeErrors:
    """The loaded table. ``version`` is a hash of the file, logged with each decision."""

    def __init__(self, tables: dict[Protocol, ProtocolTable], version: str) -> None:
        self._tables = tables
        self.version = version

    @classmethod
    def load(cls, path: Path) -> FakeErrors:
        text = path.read_bytes()
        parsed = TableFile.model_validate(yaml.safe_load(text))
        tables = {p: getattr(parsed, p.value) for p in Protocol}
        return cls(tables, hashlib.sha256(text).hexdigest()[:12])

    def render(self, req: DecideRequest, verb_class: str) -> tuple[str, int | None]:
        """``(output, exit_code)`` for a fake error answering this request: the verb's own
        entry, else its class's, else the protocol's default."""
        table = self._tables[req.protocol]
        values = _values(req)
        for entry in (table.verbs.get(verb_key(req)), table.classes.get(verb_class)):
            if entry is not None and (output := entry.fill(values)) is not None:
                return output, entry.exit_code
        # The default always answers: a placeholder with no value (no verb at all) is empty.
        default = table.default
        output = _PLACEHOLDER.sub(lambda m: values.get(m.group(1), ""), default.output)
        return output, default.exit_code
