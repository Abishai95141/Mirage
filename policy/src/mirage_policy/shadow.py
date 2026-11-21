"""The shadow policy: a second policy that is asked about every decision and never acts.

Its answer -- a probability for every allowed action -- is logged beside what the acting policy
did, so the two can be compared offline (phase 2 spec 2.5). The shadow is meant to be a model
trained from the explore logs and loaded from a file at start-up. This module is the seam for
it: the interface a loaded model must offer, the loader, and the fallback used when there is no
model. It implements no model and imports no model library.

**The interface.** One method::

    probabilities(context, allowed) -> {action: probability}

``allowed`` is the action mask's result for this input, in the service's fixed order; the
answer must give every allowed action a probability in [0, 1], give nothing else a
probability, and sum to 1. ``context`` is exactly the ``context`` object of the decision
record, so a model is served the features it was trained on:

=========================  ============  ==================================================
name                       type          meaning
=========================  ============  ==================================================
``protocol``               str           ``ssh``, ``http``, ``redis`` or ``mysql``
``verb``                   str           the raw verb (argv[0], Redis command, SQL verb,
                                         HTTP method); ``""`` when the input has none
``verb_class``             str           its class, from the fixed vocabulary
                                         ``mirage_policy.verbs.VERB_CLASSES[protocol]``
``known``                  bool          the decoy's emulator knows the input
``inputs_so_far``          int           inputs of this session the service saw before
                                         this one (0 on the first)
``seconds_since_last``     float | None  seconds since the session's previous input;
                                         None on the first
``last_tactic``            str | None    ATT&CK tactic ID (``TA0007``) of the latest
                                         earlier input of the session that a tagger rule
                                         matched; None if none did
``seen_before``            bool          this input (protocol and text) was seen before in
                                         this process, in any session; bounded memory
``seen_before_in_session`` bool          the same, within this session only
``rule_action``            str           the action the rules chose for this input, as
                                         one of contract v1's five: an action of v2 shows
                                         here as ``allow``, what the decoy would have done
                                         unasked
``rule_action_v2``         str | None    that action of contract v2 (``respond``,
                                         ``plant_token``, ``escalate``); None for a v1 one
``tier``                   str | None    what the decoy has for this input: ``emulated``,
                                         ``rendered`` or ``none``; None from a decoy that
                                         does not say
``actor_class``            str | None    the classifier's answer for the session so far;
                                         None until the policy process scores it (R15)
``actor_confidence``       float | None  the probability it gave that class
``respond_budget_left``    str           how much generated output the session and its
                                         source may still be granted: ``full``, ``part``,
                                         ``low`` (a quarter or less) or ``none``
``token_planted``          bool          the policy has planted a token in this session
``previous_action``        str | None    the action sent for the session's previous input
``had_non_allow``          bool          an earlier input of the session was answered
                                         with something other than ``allow``
=========================  ============  ==================================================

``context_version`` in the decision record (:data:`mirage_policy.explore.CONTEXT_VERSION`)
changes whenever a name, a type or a meaning in this table does.

**The contract.** ``probabilities`` runs inside the request, before the decoy is answered, and
the decoys give the whole exchange 50 ms: it must return in well under a millisecond, hold no
lock, and touch neither the network nor the disk. It must not sample or keep state between
calls: the shadow never acts, and the same input must give the same answer. If it raises or
returns something that is not a distribution over ``allowed``, that decision is logged with the
fallback's answer and its name, never with the model's.

**Loading.** ``POLICY_SHADOW_MODEL`` names the model file. A loader for its format is
registered by file suffix (:func:`register_loader`); it opens the file read-only and returns
an object with the method above and two strings, ``name`` and ``version``
(:func:`file_version` gives a version tied to the file's bytes). With no file, an unreadable
file, an unknown format or a loader that fails, the service logs the reason once and shadows
with :class:`FallbackShadow`, whose name says what it is, so a decision record never claims a
trained model that was not there.

To add a format: write a module whose import calls ``register_loader(".ext", load)``, and
import that module in :mod:`mirage_policy.app` (beside this one), so the loader is registered
before ``create_app`` reads the setting. Nothing else changes.
"""

from __future__ import annotations

import hashlib
import logging
import math
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from mirage_schema.policy import Action

log = logging.getLogger("mirage.policy.shadow")

FALLBACK_NAME = "shadow-fallback(epsilon-greedy)"

ContextValue = str | int | float | bool | None


@runtime_checkable
class ShadowPolicy(Protocol):
    """A policy that can be shadowed: see the module docstring for the contract."""

    name: str
    version: str

    def probabilities(
        self, context: Mapping[str, ContextValue], allowed: Sequence[Action]
    ) -> Mapping[Action, float]:
        """The probability this policy gives each allowed action in this context."""
        ...


class _RuleCentred(Protocol):
    """What the fallback needs of the service's own policy (explore.BanditPolicy)."""

    name: str

    def probs(self, allowed: list[Action], rule_action: Action) -> dict[Action, float]: ...


class FallbackShadow:
    """The shadow used when no trained model is loaded: the service's own epsilon-greedy
    policy around the rules' action. Its name is fixed and explicit; ``version`` carries the
    wrapped policy's name and ``reason`` why the fallback is in use."""

    name = FALLBACK_NAME

    def __init__(self, policy: _RuleCentred, reason: str) -> None:
        self._policy = policy
        self.version = policy.name
        self.reason = reason

    def probabilities(
        self, context: Mapping[str, ContextValue], allowed: Sequence[Action]
    ) -> Mapping[Action, float]:
        return self._policy.probs(list(allowed), Action(str(context["rule_action"])))


# A loader turns a model file into a ShadowPolicy. It must open the file read-only.
Loader = Callable[[Path], ShadowPolicy]
_LOADERS: dict[str, Loader] = {}


def register_loader(suffix: str, loader: Loader) -> None:
    """Make ``loader`` the reader of model files ending in ``suffix`` (``".vw"``)."""
    if not suffix.startswith("."):
        raise ValueError(f"a suffix starts with a dot: {suffix!r}")
    _LOADERS[suffix.lower()] = loader


def file_version(path: Path) -> str:
    """A version for a model file: the first 12 hex digits of its SHA-256."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()[:12]


def load_shadow(
    path: Path | None, policy: _RuleCentred, loaders: Mapping[str, Loader] | None = None
) -> ShadowPolicy:
    """The shadow policy for this process: the model at ``path`` if it loads, else the
    fallback around ``policy``. Called once at start-up; a fallback is logged once, here."""
    loaders = _LOADERS if loaders is None else loaders
    if path is None:
        reason = "no model configured (POLICY_SHADOW_MODEL is not set)"
    else:
        reason = _why_not(path, loaders)
        if reason is None:
            try:
                model = loaders[path.suffix.lower()](path)
            except Exception as exc:  # a loader is foreign code; any failure means fallback
                reason = f"the loader failed on {path.name}: {type(exc).__name__}: {exc}"[:300]
            else:
                if _usable(model):
                    log.info("shadow policy %s (%s) from %s", model.name, model.version, path)
                    return model
                reason = f"the loader for {path.suffix} did not return a shadow policy"
    log.warning("no trained shadow policy: %s; shadowing with %s", reason, FALLBACK_NAME)
    return FallbackShadow(policy, reason)


def _why_not(path: Path, loaders: Mapping[str, Loader]) -> str | None:
    """Why the file cannot be handed to a loader, or None when it can."""
    try:
        with path.open("rb") as f:  # read-only, and only to learn that it can be read
            f.read(1)
    except OSError as exc:
        return f"cannot read {path}: {exc.strerror or type(exc).__name__}"
    if path.suffix.lower() not in loaders:
        return f"no loader is registered for {path.suffix or 'a file without a suffix'!r}"
    return None


def _usable(model: object) -> bool:
    return (
        isinstance(model, ShadowPolicy)
        and isinstance(model.name, str)
        and isinstance(model.version, str)
        and model.name != FALLBACK_NAME
    )


def distribution(
    probs: Mapping[Action, float] | object, allowed: Sequence[Action]
) -> dict[str, float] | None:
    """A shadow policy's answer as the decision record stores it (``{action: probability}``
    in mask order, rounded), or None when it is not a distribution over ``allowed``."""
    if not isinstance(probs, Mapping) or len(probs) != len(allowed):
        return None
    out: dict[str, float] = {}
    for action in allowed:
        p = probs.get(action)
        if isinstance(p, bool) or not isinstance(p, int | float) or not math.isfinite(p):
            return None
        if not 0.0 <= p <= 1.0:
            return None
        out[action.value] = round(float(p), 6)
    if abs(sum(float(probs[a]) for a in allowed) - 1.0) > 1e-6:
        return None
    return out
