"""Sink policy language: YAML (``safe_load``) validated into typed rules and compiled predicates.

Example (``policies/default.yaml``)::

    version: 1
    sinks:
      send_email:
        to:
          require:
            any_of:
              - integrity: user
              - member_of: contacts
          on_fail: deny
        body:
          require:
            any_of:
              - argument_integrity: {argument: to, level: user}
              - readers_include: to
          on_fail: declassify

Predicates (exactly one key per mapping):

- ``integrity: <level>``: the argument's effective label has at least this integrity;
- ``argument_integrity: {argument, level}``: *another* argument of the same call has at least
  this integrity (e.g. "the user chose the recipient");
- ``pc_integrity: <level>``: the program-counter label has at least this integrity;
- ``member_of: <collection>``: the plain value (a string or a list of strings) is a member of a
  trusted collection provided by the environment (``contacts``, ``payees``);
- ``readers_include: <argument>``: the argument's readers include every principal named by
  ``<argument>`` (confidential data may flow only to its readers);
- ``matches: <regex>``: the plain string fully matches the pattern;
- ``max_length: <n>``: the plain string has at most ``n`` characters;
- ``any_of`` / ``all_of``: lists of predicates.

A rule keyed ``"$pc"`` instead of an argument name applies to the call as a whole (typically
``pc_integrity``), so a sink reached through a branch or loop that depends on untrusted data can
be escalated even when every argument is a plan constant.

``on_fail`` is ``deny`` (stop the run) or ``declassify`` (hold the call for a human decision).
Sinks without an entry, and sinks whose entry names arguments the tool does not have, fail
validation at startup, which makes the service report not-ready.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from taint_flow_agent.dsl.interpreter import PendingCall
from taint_flow_agent.ifc.labels import Integrity, Label
from taint_flow_agent.ifc.values import Plain, to_plain

__all__ = [
    "CONTEXT_ARGUMENT",
    "ArgumentRule",
    "CompiledRule",
    "EvaluationContext",
    "OnFail",
    "Policy",
    "PolicyDocument",
    "PolicyError",
    "PredicateSpec",
    "SinkPolicy",
    "Verdict",
    "load_policy",
    "load_policy_text",
]

OnFail = Literal["deny", "declassify"]
CONTEXT_ARGUMENT = "$pc"
IntegrityName = Literal["user", "trusted_tool", "untrusted"]
_MAX_POLICY_BYTES = 256_000
_MAX_PATTERN_LENGTH = 200


class PolicyError(ValueError):
    """The policy file is missing, malformed or inconsistent with the registered tools."""


class ArgumentIntegrity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    argument: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    level: IntegrityName


class PredicateSpec(BaseModel):
    """One predicate: exactly one of the fields is set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    integrity: IntegrityName | None = None
    argument_integrity: ArgumentIntegrity | None = None
    pc_integrity: IntegrityName | None = None
    member_of: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,31}$")
    readers_include: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,31}$")
    matches: str | None = Field(default=None, min_length=1, max_length=_MAX_PATTERN_LENGTH)
    max_length: int | None = Field(default=None, ge=0, le=1_000_000)
    any_of: list[PredicateSpec] | None = Field(default=None, min_length=1, max_length=16)
    all_of: list[PredicateSpec] | None = Field(default=None, min_length=1, max_length=16)

    @model_validator(mode="after")
    def _exactly_one(self) -> PredicateSpec:
        chosen = [name for name in type(self).model_fields if getattr(self, name) is not None]
        if len(chosen) != 1:
            raise ValueError("a predicate must set exactly one key")
        if self.matches is not None:
            try:
                re.compile(self.matches)
            except re.error as exc:
                raise ValueError("matches: invalid regular expression") from exc
        return self

    @property
    def kind(self) -> str:
        return next(name for name in type(self).model_fields if getattr(self, name) is not None)


class ArgumentRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    require: PredicateSpec
    on_fail: OnFail = "deny"


class SinkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    arguments: dict[str, ArgumentRule] = Field(min_length=1, max_length=32)

    @model_validator(mode="before")
    @classmethod
    def _flatten(cls, value: Any) -> Any:
        # ``send_email: {to: {...}, body: {...}}`` reads better than an ``arguments:`` level.
        if isinstance(value, dict) and "arguments" not in value:
            return {"arguments": value}
        return value


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1]
    default: Literal["deny"] = "deny"
    sinks: dict[str, SinkPolicy] = Field(max_length=256)


@final
@dataclass(frozen=True, slots=True)
class Verdict:
    ok: bool
    reason: str


@final
@dataclass(frozen=True, slots=True)
class EvaluationContext:
    call: PendingCall
    membership: Callable[[str], frozenset[str]]

    def label_of(self, argument: str) -> Label | None:
        return self.call.arg_labels.get(argument)

    def plain_of(self, argument: str) -> Plain:
        value = self.call.args.get(argument)
        return None if value is None else to_plain(value)


Predicate = Callable[[EvaluationContext, str], Verdict]


def _principals(value: Plain) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [str(item) for item in value]
    return []


def _level(name: IntegrityName) -> Integrity:
    return Integrity.parse(name)


def _required[T](value: T | None, kind: str) -> T:
    """Narrow the one field ``PredicateSpec.kind`` named. ``None`` here means the model changed."""
    if value is None:  # pragma: no cover - kind is derived from the field that is set
        raise PolicyError(f"predicate of kind {kind!r} has no {kind} value")
    return value


def _compile(spec: PredicateSpec) -> Predicate:  # noqa: PLR0911, PLR0915
    kind = spec.kind
    if kind == "integrity":
        required = _level(_required(spec.integrity, "integrity"))

        def integrity(ctx: EvaluationContext, argument: str) -> Verdict:
            label = ctx.label_of(argument)
            if label is None:
                return Verdict(False, f"{argument} is missing")
            ok = label.integrity >= required
            return Verdict(ok, f"{argument} integrity is {label.integrity.name.lower()}")

        return integrity
    if kind == "argument_integrity":
        pair = _required(spec.argument_integrity, "argument_integrity")
        other, required = pair.argument, _level(pair.level)

        def argument_integrity(ctx: EvaluationContext, argument: str) -> Verdict:
            label = ctx.label_of(other)
            if label is None:
                return Verdict(False, f"{other} is missing")
            ok = label.integrity >= required
            return Verdict(ok, f"{other} integrity is {label.integrity.name.lower()}")

        return argument_integrity
    if kind == "pc_integrity":
        required = _level(_required(spec.pc_integrity, "pc_integrity"))

        def pc_integrity(ctx: EvaluationContext, argument: str) -> Verdict:
            ok = ctx.call.pc.integrity >= required
            return Verdict(ok, f"pc integrity is {ctx.call.pc.integrity.name.lower()}")

        return pc_integrity
    if kind == "member_of":
        collection = _required(spec.member_of, "member_of")

        def member_of(ctx: EvaluationContext, argument: str) -> Verdict:
            principals = _principals(ctx.plain_of(argument))
            if not principals:
                return Verdict(False, f"{argument} is not a string or list of strings")
            members = ctx.membership(collection)
            missing = [p for p in principals if p not in members]
            if missing:
                return Verdict(False, f"{argument} has {len(missing)} value(s) not in {collection}")
            return Verdict(True, f"{argument} is in {collection}")

        return member_of
    if kind == "readers_include":
        other = _required(spec.readers_include, "readers_include")

        def readers_include(ctx: EvaluationContext, argument: str) -> Verdict:
            label = ctx.label_of(argument)
            if label is None:
                return Verdict(False, f"{argument} is missing")
            principals = _principals(ctx.plain_of(other))
            if not principals:
                return Verdict(False, f"{other} names no principal")
            if label.readers.includes_all(principals):
                return Verdict(True, f"{argument} may be read by {other}")
            return Verdict(False, f"{argument} may not be read by every principal in {other}")

        return readers_include
    if kind == "matches":
        pattern = re.compile(_required(spec.matches, "matches"))

        def matches(ctx: EvaluationContext, argument: str) -> Verdict:
            value = ctx.plain_of(argument)
            ok = isinstance(value, str) and pattern.fullmatch(value) is not None
            return Verdict(ok, f"{argument} {'matches' if ok else 'does not match'} the pattern")

        return matches
    if kind == "max_length":
        limit = _required(spec.max_length, "max_length")

        def max_length(ctx: EvaluationContext, argument: str) -> Verdict:
            value = ctx.plain_of(argument)
            ok = isinstance(value, str) and len(value) <= limit
            return Verdict(ok, f"{argument} length {'within' if ok else 'over'} {limit}")

        return max_length
    if kind == "any_of":
        options = [_compile(item) for item in _required(spec.any_of, "any_of")]

        def any_of(ctx: EvaluationContext, argument: str) -> Verdict:
            reasons = []
            for option in options:
                verdict = option(ctx, argument)
                if verdict.ok:
                    return verdict
                reasons.append(verdict.reason)
            return Verdict(False, "none of: " + "; ".join(reasons))

        return any_of
    parts = [_compile(item) for item in _required(spec.all_of, "all_of")]

    def all_of(ctx: EvaluationContext, argument: str) -> Verdict:
        reasons = []
        for part in parts:
            verdict = part(ctx, argument)
            if not verdict.ok:
                return verdict
            reasons.append(verdict.reason)
        return Verdict(True, "all of: " + "; ".join(reasons))

    return all_of


@final
@dataclass(frozen=True, slots=True)
class CompiledRule:
    sink: str
    argument: str
    on_fail: OnFail
    predicate: Predicate
    spec: PredicateSpec

    @property
    def name(self) -> str:
        return f"{self.sink}.{self.argument}"

    def evaluate(self, ctx: EvaluationContext) -> Verdict:
        return self.predicate(ctx, self.argument)


@final
class Policy:
    """A validated policy document with compiled per-argument rules."""

    def __init__(self, document: PolicyDocument, *, source: str = "<inline>") -> None:
        self.document = document
        self.source = source
        self._rules: dict[str, tuple[CompiledRule, ...]] = {
            sink: tuple(
                CompiledRule(
                    sink=sink,
                    argument=argument,
                    on_fail=rule.on_fail,
                    predicate=_compile(rule.require),
                    spec=rule.require,
                )
                for argument, rule in entry.arguments.items()
            )
            for sink, entry in document.sinks.items()
        }

    @property
    def sinks(self) -> tuple[str, ...]:
        return tuple(sorted(self._rules))

    def without_context_rules(self) -> Policy:
        """The same policy minus every ``$pc`` rule (used to test propagation rules alone)."""
        sinks = {
            sink: SinkPolicy(
                arguments={
                    argument: rule
                    for argument, rule in entry.arguments.items()
                    if argument != CONTEXT_ARGUMENT
                }
            )
            for sink, entry in self.document.sinks.items()
        }
        document = PolicyDocument(version=1, default="deny", sinks=sinks)
        return Policy(document, source=f"{self.source} (pc-blind)")

    def rules_for(self, sink: str) -> tuple[CompiledRule, ...] | None:
        return self._rules.get(sink)

    def validate_against(
        self, sinks: Mapping[str, tuple[str, ...]], *, collections: Mapping[str, Any] | None = None
    ) -> list[str]:
        """Problems: sinks without a policy, rules naming unknown arguments or collections."""
        problems: list[str] = []
        for sink in sorted(sinks):
            if sink not in self._rules:
                problems.append(f"sink {sink} has no policy entry (deny by default)")
        for sink, rules in self._rules.items():
            if sink not in sinks:
                problems.append(f"policy names unknown sink {sink}")
                continue
            parameters = set(sinks[sink])
            for rule in rules:
                if rule.argument != CONTEXT_ARGUMENT and rule.argument not in parameters:
                    problems.append(f"{rule.name}: unknown argument")
                for referenced in _referenced_arguments(rule.spec):
                    if referenced not in parameters:
                        problems.append(f"{rule.name}: refers to unknown argument {referenced}")
                if collections is not None:
                    for collection in _referenced_collections(rule.spec):
                        if collection not in collections:
                            problems.append(f"{rule.name}: unknown collection {collection}")
        return problems


def _referenced_arguments(spec: PredicateSpec) -> set[str]:
    found: set[str] = set()
    if spec.argument_integrity is not None:
        found.add(spec.argument_integrity.argument)
    if spec.readers_include is not None:
        found.add(spec.readers_include)
    for group in (spec.any_of or []) + (spec.all_of or []):
        found |= _referenced_arguments(group)
    return found


def _referenced_collections(spec: PredicateSpec) -> set[str]:
    found: set[str] = set()
    if spec.member_of is not None:
        found.add(spec.member_of)
    for group in (spec.any_of or []) + (spec.all_of or []):
        found |= _referenced_collections(group)
    return found


def load_policy_text(text: str, *, source: str = "<inline>") -> Policy:
    if len(text.encode("utf-8")) > _MAX_POLICY_BYTES:
        raise PolicyError(f"{source}: policy file is too large")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: invalid YAML ({type(exc).__name__})") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: policy must be a mapping")
    try:
        document = PolicyDocument.model_validate(data)
    except ValidationError as exc:
        locations = sorted({".".join(str(p) for p in err["loc"]) for err in exc.errors()})
        raise PolicyError(f"{source}: invalid policy at {', '.join(locations) or '$'}") from exc
    return Policy(document, source=source)


def load_policy(path: Path) -> Policy:
    if not path.is_file():
        raise PolicyError(f"policy file {path.name} not found")
    return load_policy_text(path.read_text(encoding="utf-8"), source=path.name)
