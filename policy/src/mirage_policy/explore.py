"""The bandit's context, action mask and exploring policy (phase 2 spec, 2.5 and Q6).

On ordinary traffic the rules decide and the bandit only shadows: it logs the action
probabilities it would have chosen, so a policy can be evaluated off-policy later. In the lab's
explore address range it acts: it samples an action and logs the exact probability of what it
took. Both need the same two things -- a context computed from the requests the service sees
(Q12: in-process, no network call), and an action mask that removes what is not allowed.

The policy here is epsilon-greedy over the rule's action: a well-defined default whose
propensities make off-policy evaluation possible before any model is trained. A model trained
from the explore logs shadows it through :mod:`mirage_policy.shadow`.

Per-session context lives in a bounded in-memory map. A single service process owns it; lab
runs are low volume, and nothing here is durable state.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import random
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mirage_policy.verbs import verb_class
from mirage_schema.policy import Action, DecideRequest, Protocol, Tier
from mirage_schema.techniques import Engine

# RFC 2544, never routed; the runner's explore runs dial from here (spec Q6, lab net section).
EXPLORE_NET = ipaddress.ip_network("198.19.0.0/16")
EPSILON = 0.3
MAX_SESSIONS = 4096  # bound the context map
IDLE_RESET_S = 1800  # a session untouched this long is treated as new

ACTIONS = (Action.ALLOW, Action.DELAY, Action.FAKE_SUCCESS, Action.FAKE_ERROR, Action.TERMINATE)

# The actions each decoy honours, from reading its handler (15 November 2026). Every decoy
# applies all five, so no protocol loses an action as a whole; the table exists so that the
# day a decoy cannot express one, the mask is one line here and a test notices.
#   ssh    decoys/ssh/patches/0001-MIRAGE-policy-gate-spike-S1.patch, mirage_gate.py _apply()
#          (patch lines 306-337): delay re-runs the command after delay_ms, allow runs it,
#          terminate ends the session, fake_success writes output to stdout with status 0,
#          fake_error writes it to stderr with status exit_code.
#   http   decoys/http/src/mirage_http_decoy/handler.py:234-298 (finish, decide): delay
#          sleeps then serves, terminate closes without a response, fake_success is a 200 with
#          the output, fake_error a 4xx/5xx with the output or the profile's own error page.
#   redis  decoys/db/src/mirage_db_decoy/redis/handler.py:250-262 (command): delay sleeps
#          then emulates, terminate closes, fake_success is +OK or the output as a bulk
#          string, fake_error is "-ERR <output>".
#   mysql  decoys/db/src/mirage_db_decoy/mysql/handler.py:205-218 (commands): delay sleeps
#          then emulates, terminate closes without a reply, fake_success is an OK packet,
#          fake_error an ERR packet with exit_code and the output.
EXPRESSIBLE: dict[Protocol, frozenset[Action]] = {
    Protocol.SSH: frozenset(ACTIONS),
    Protocol.HTTP: frozenset(ACTIONS),
    Protocol.REDIS: frozenset(ACTIONS),
    Protocol.MYSQL: frozenset(ACTIONS),
}


def is_gopher_line(req: DecideRequest) -> bool:
    """A Redis input whose first word is ``Host:`` (an HTTP request sent to Redis)."""
    return req.protocol is Protocol.REDIS and bool(req.argv) and req.argv[0].lower() == "host:"


def expressible(req: DecideRequest) -> frozenset[Action]:
    """The actions the decoy can actually carry out for this input."""
    if is_gopher_line(req):
        # redis/handler.py:223-241: the gopher path asks the gate, then ignores the answer.
        # It swallows every queued reply and the connection closes, whatever was decided, so
        # any action but allow would be logged as taken and never happen.
        return frozenset({Action.ALLOW})
    return EXPRESSIBLE[req.protocol]


def is_first_input(req: DecideRequest, inputs_so_far: int = 0) -> bool:
    """Whether this is the session's first input. The decoy's own ``seq`` decides when it is
    sent (every current decoy numbers from 1). A request without one falls back to the
    service's count for the session, so a client that never sends ``seq`` is first once, not
    for ever. With neither a ``seq`` nor a session ID there is nothing to count, and every
    such request is treated as a first input."""
    if req.seq is not None:
        return req.seq <= 1
    return inputs_so_far == 0


def allowed_actions(
    req: DecideRequest, inputs_so_far: int = 0, escalated: bool = False
) -> list[Action]:
    """The mask (spec 2.5): never terminate on the first input of a session, and never an
    action the decoy cannot express for this input. ``inputs_so_far`` is the service's own
    count of the session's earlier inputs (the context feature of that name). In a session
    that has been escalated (phase 3 spec 3.3) a faked answer would contradict the real shell
    behind it, so only allow, delay and terminate are left."""
    can = expressible(req)
    first = is_first_input(req, inputs_so_far)
    faked = (Action.FAKE_SUCCESS, Action.FAKE_ERROR)
    return [
        a
        for a in ACTIONS
        if a in can and not (a is Action.TERMINATE and first) and not (escalated and a in faked)
    ]


# Bump when a context feature is added, removed or changes meaning; logged with each decision.
# 2: verb_class, rule_action and seen_before_in_session added; seen_before became per process.
# 3: phase 3's additions (spec 3.3): tier, actor_class and actor_confidence, the responder
#    budget left, token_planted, previous_action, had_non_allow, rule_action_v2.
CONTEXT_VERSION = "3"
# What the policy may grant in generated output (spec 3.2b). The responder counts what is
# really spent and enforces its own limits. The policy asks nothing of anyone: it counts
# what the decoy reports as spent (``respond_spent`` in the request), and for a decoy that
# reports nothing, what it has granted, which is never less. It stops granting at the limit.
#
# Until 18 November 2026 it counted grants for every decoy. A grant is the answer's ceiling
# (400 tokens); the median answer uses 50 and a cached one none, so a session was cut off
# from the responder after seven answers, and the programs that had just worked could "not
# be executed" (found by the consistency probes: the next login was given a working one).
SESSION_TOKEN_BUDGET = 3_000
SOURCE_TOKEN_BUDGET = 15_000  # per source address, per day
SOURCE_BUDGET_CAP = 16384  # source addresses remembered for the day's budget
ESCALATE_MIN_INPUTS = 3  # a default (spec 3.3): never before the session's third input
# Where a simulated actor comes from (the lab's ranges, RFC 2544). `escalate` is for these
# alone until the exposure checklist says otherwise.
LAB_NET = ipaddress.ip_network("198.18.0.0/15")
SESSION_SEEN_CAP = 512  # most recent distinct inputs remembered per session (bounds memory)
PROCESS_SEEN_CAP = 65536  # most recently seen distinct inputs remembered by the process


@dataclass
class SessionState:
    count: int = 0
    last_ts: float = 0.0
    last_tactic: str | None = None
    # Phase 3: what the policy has done in this session so far.
    respond_granted: int = 0  # output tokens granted to `respond` decisions
    respond_spent: int | None = None  # what the decoy last reported as really used; None: nothing
    token_planted: bool = False
    previous_action: str | None = None
    had_non_allow: bool = False
    escalated: bool = False
    # A bounded ring of recent input digests; the only feature is "have I seen this before",
    # and an unbounded set would let one long session grow the service to OOM.
    seen_in_session: deque[bytes] = field(default_factory=lambda: deque(maxlen=SESSION_SEEN_CAP))


class Context:
    """The policy's features, updated as requests arrive: per-session state, and the inputs
    the whole process has seen. Both are bounded and evict the least recently used entry, so a
    long-lived session that is still talking keeps its state however many short ones come and
    go around it."""

    def __init__(
        self,
        now: Callable[[], float] = time.monotonic,
        max_sessions: int = MAX_SESSIONS,
        process_seen_cap: int = PROCESS_SEEN_CAP,
    ) -> None:
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()
        self._seen_in_process: OrderedDict[bytes, None] = OrderedDict()
        # Source address -> (day number, tokens granted that day), least recently used first.
        self._granted_today: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._clock = time.time
        self._now = now
        self._max_sessions = max_sessions
        self._process_seen_cap = process_seen_cap

    def _state(self, session_id: str | None) -> SessionState:
        if not session_id:
            return SessionState()
        st = self._sessions.get(session_id)
        if st is None or self._now() - st.last_ts > IDLE_RESET_S:
            st = SessionState()
            self._sessions[session_id] = st
        # Most recently used last; eviction takes from the front.
        self._sessions.move_to_end(session_id)
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)
        return st

    def session_budget_left(self, st: SessionState) -> int:
        used = st.respond_granted if st.respond_spent is None else st.respond_spent
        return max(0, SESSION_TOKEN_BUDGET - used)

    def _charge_source(self, ip: str | None, tokens: int) -> None:
        if not ip or tokens <= 0:
            return
        today = int(self._clock() // 86400)
        day, so_far = self._granted_today.get(ip, (today, 0))
        self._granted_today[ip] = (today, tokens + (so_far if day == today else 0))
        self._granted_today.move_to_end(ip)
        while len(self._granted_today) > SOURCE_BUDGET_CAP:
            self._granted_today.popitem(last=False)

    def _spent(self, req: DecideRequest, st: SessionState) -> None:
        """Take in what the decoy says the session's answers have used. The count only grows:
        a smaller number than before is a decoy that restarted its count, and is ignored."""
        if req.respond_spent is None or not req.session_id:
            return
        before = st.respond_spent or 0
        if st.respond_spent is None or req.respond_spent > before:
            st.respond_spent = max(before, req.respond_spent)
            self._charge_source(req.src.ip, st.respond_spent - before)

    def source_budget_left(self, ip: str | None) -> int:
        if not ip:
            return SOURCE_TOKEN_BUDGET
        day, granted = self._granted_today.get(ip, (0, 0))
        if day != int(self._clock() // 86400):
            granted = 0
        return max(0, SOURCE_TOKEN_BUDGET - granted)

    def grant(self, req: DecideRequest, wanted: int) -> int:
        """The output tokens a `respond` may have, out of what was asked: no more than the
        session and its source still have. Zero means the answer cannot be granted."""
        st = self._sessions.get(req.session_id or "")
        left = self.source_budget_left(req.src.ip)
        if st is not None:
            left = min(left, self.session_budget_left(st))
        return max(0, min(wanted, left))

    def record(self, req: DecideRequest, action: Action, granted: int = 0) -> None:
        """Fold the decision that was sent into the session's state, for the decisions after
        it. A request with no session ID has no state to fold into."""
        st = self._sessions.get(req.session_id or "")
        if st is None or st.respond_spent is None:
            # A decoy that does not say what was spent is charged what it was granted.
            self._charge_source(req.src.ip, granted)
        if st is None:
            return
        st.previous_action = action.value
        st.respond_granted += granted
        if action is Action.PLANT_TOKEN:
            st.token_planted = True
        if action is Action.ESCALATE:
            st.escalated = True
        if action not in (Action.ALLOW, Action.PLANT_TOKEN):
            # plant_token runs the command as allow does: the attacker is given no other answer.
            st.had_non_allow = True

    def escalated(self, session_id: str | None) -> bool:
        st = self._sessions.get(session_id or "")
        return bool(st and st.escalated)

    def _seen_by_process(self, digest: bytes) -> bool:
        """Whether the process has seen this input, remembering it for next time."""
        seen = digest in self._seen_in_process
        self._seen_in_process[digest] = None
        self._seen_in_process.move_to_end(digest)
        while len(self._seen_in_process) > self._process_seen_cap:
            self._seen_in_process.popitem(last=False)
        return seen

    def observe(self, req: DecideRequest, tactic: str | None) -> dict:
        """Compute the context for this request and fold it into the session's state. The
        features are documented, with their types, in :mod:`mirage_policy.shadow`."""
        now = self._now()
        st = self._state(req.session_id)
        self._spent(req, st)  # before the budget that is left is put in the context
        # The protocol is part of the input: "GET /" is one thing to nginx, another to Redis.
        text = f"{req.protocol.value}\0{req.input_text()}".encode()
        digest = hashlib.blake2b(text, digest_size=16).digest()
        features = {
            "protocol": req.protocol.value,
            "verb": req.verb() or "",
            "verb_class": verb_class(req),
            "known": bool(req.known),
            "inputs_so_far": st.count,
            "seconds_since_last": round(now - st.last_ts, 3) if st.count else None,
            "last_tactic": st.last_tactic,
            # The spec's feature (Q12): seen before in this process, in any session.
            "seen_before": self._seen_by_process(digest),
            "seen_before_in_session": digest in st.seen_in_session,
            # Phase 3 (context version 3).
            "tier": req.tier.value if req.tier else None,
            # The classifier's answer for the session, once the policy process scores it
            # itself (decision R15, built with the bandit's context in step 6).
            "actor_class": None,
            "actor_confidence": None,
            "respond_budget_left": budget_bucket(
                min(self.session_budget_left(st), self.source_budget_left(req.src.ip)),
                SESSION_TOKEN_BUDGET,
            ),
            "token_planted": st.token_planted,
            "previous_action": st.previous_action,
            "had_non_allow": st.had_non_allow,
        }
        st.count += 1
        st.last_ts = now
        st.seen_in_session.append(digest)
        if tactic:
            st.last_tactic = tactic
        return features


def budget_bucket(left: int, whole: int) -> str:
    """How much of a budget is left, as the context says it: none, low (a quarter or less),
    part, or full."""
    if left <= 0:
        return "none"
    if left >= whole:
        return "full"
    return "low" if left * 4 <= whole else "part"


def is_lab_source(req: DecideRequest) -> bool:
    try:
        return bool(req.src.ip) and ipaddress.ip_address(req.src.ip) in LAB_NET
    except ValueError:
        return False


def v2_allowed(
    req: DecideRequest,
    features: dict,
    context: Context,
    *,
    reserve: bool = False,
    host_ready: bool = False,
) -> list[Action]:
    """The actions of contract v2 the mask leaves for this request (spec 3.3), in a fixed
    order. Never one the decoy did not list in ``supports``.

    ``reserve`` says whether an unplanted token is held for this deployment; ``host_ready``
    whether this host's sandbox tests have passed, a flag a person sets. `escalate` is in
    this list for the rules alone: it is never offered to an exploring or a learned policy.
    """
    if context.escalated(req.session_id):
        return []  # a real shell is answering: nothing may be faked beside it
    out = []
    if (
        Action.RESPOND in req.supports
        and req.tier is Tier.NONE
        and features.get("respond_budget_left") != "none"
    ):
        out.append(Action.RESPOND)
    if Action.PLANT_TOKEN in req.supports and reserve and not features.get("token_planted"):
        out.append(Action.PLANT_TOKEN)
    if (
        Action.ESCALATE in req.supports
        and host_ready
        and int(features.get("inputs_so_far") or 0) + 1 >= ESCALATE_MIN_INPUTS
        and features.get("actor_class") != "scanner"
        and is_lab_source(req)
    ):
        out.append(Action.ESCALATE)
    return out


def is_explore(req: DecideRequest, enabled: bool) -> bool:
    """True only when exploration is switched on and the source is in the lab explore range."""
    if not enabled:
        return False
    ip = req.src.ip
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in EXPLORE_NET
    except ValueError:
        return False


@dataclass
class Choice:
    action: Action
    propensity: float  # probability the acting policy gave the chosen action
    probs: dict[str, float]  # probability of every allowed action


class BanditPolicy:
    """Epsilon-greedy over the rule's action (v0): the exploring policy that acts in the lab's
    explore range, and what the shadow falls back to when no trained model is loaded."""

    version = "0"

    def __init__(self, epsilon: float = EPSILON) -> None:
        self.epsilon = epsilon
        self.name = f"epsilon-greedy-v0(eps={epsilon})"

    def probs(self, allowed: list[Action], rule_action: Action) -> dict[Action, float]:
        base = rule_action if rule_action in allowed else allowed[0]
        n = len(allowed)
        p = {a: self.epsilon / n for a in allowed}
        p[base] += 1.0 - self.epsilon
        return p

    def sample(self, allowed: list[Action], rule_action: Action, rng: random.Random) -> Choice:
        p = self.probs(allowed, rule_action)
        r, cumulative = rng.random(), 0.0
        chosen = allowed[-1]
        for action, prob in p.items():
            cumulative += prob
            if r <= cumulative:
                chosen = action
                break
        return Choice(chosen, p[chosen], {a.value: round(pr, 6) for a, pr in p.items()})


def explore_enabled() -> bool:
    return os.environ.get("POLICY_EXPLORE", "").lower() == "lab"


class TacticRules:
    """The ``last_tactic`` context feature (spec Q12), read in-process from the tagger's rule
    files. It wraps the shared :class:`mirage_schema.techniques.Engine` so the policy and the
    tagger agree on rule semantics (all_of vs any_of, confidence ordering); the engine depends
    only on pyyaml, so the policy image stays free of the heavy intel libraries."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @classmethod
    def load(cls, directory: Path | None) -> TacticRules:
        if directory and directory.is_dir():
            return cls(Engine.load(directory))
        return cls(Engine([], []))

    def tactic(self, protocol: str, text: str) -> str | None:
        return self._engine.last_tactic(protocol, text)

    @classmethod
    def from_env(cls) -> TacticRules:
        path = os.environ.get("POLICY_TECHNIQUE_RULES")
        return cls.load(Path(path) if path else None)
