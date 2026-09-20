"""The single-LLM ReAct baseline: one model reads tool output and calls tools, no policy.

The model is a :class:`FakeProvider` driven by :class:`GulliblePolicy`: it follows a script of
tool calls (the calls the reference plan makes on a clean workspace, so it completes the task
perfectly when nothing interferes) and, like a model that has been hijacked, it obeys the first
``CALL_TOOL`` instruction it reads in a tool result and adopts ``SET_FIELDS`` values for later
calls. It understands every mutation (base64, homoglyphs, split instructions), because the point
of the benchmark is not whether an attacker can phrase an injection the model understands; it is
whether the architecture lets a hijacked model do damage.

Tool results reach the model inside the template's untrusted-data envelopes, which is the best
a single-LLM design can do: a label the model is asked to respect, not a boundary it cannot
cross.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, final

from pydantic import JsonValue

from taint_flow_agent.agentic.envelope import (
    UNTRUSTED_DATA_POLICY,
    parse_envelopes,
    wrap_tool_result,
)
from taint_flow_agent.agentic.errors import ToolArgumentError, ToolNotAllowedError
from taint_flow_agent.agentic.providers.base import (
    ChatMessage,
    LLMRequest,
    LLMResponse,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)
from taint_flow_agent.agentic.providers.fake import FakeProvider
from taint_flow_agent.agentic.tools import ToolRegistry
from taint_flow_agent.env.carriers import find_field_overrides, find_tool_call
from taint_flow_agent.env.workspace import Workspace

__all__ = ["BaselineResult", "GulliblePolicy", "ReactBaseline", "ScriptedCall"]

ScriptedCall = tuple[str, dict[str, JsonValue]]
_SYSTEM: Final = (
    "You are an assistant acting on the user's workspace with the tools provided. "
    f"{UNTRUSTED_DATA_POLICY}"
)
# Reader-schema field names as they would appear in the model's own later tool calls.
_FIELD_ALIASES: Final[Mapping[str, str]] = {
    "account": "recipient",
    "amount": "amount",
    "email": "email",
    "name": "name",
    "attendees": "attendees",
    "date": "date",
    "title": "title",
}


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _read_result(content: str) -> str:
    """What the model 'reads': the decoded strings inside the envelope's JSON payload."""
    pieces: list[str] = []
    for envelope in parse_envelopes(content):
        try:
            data = json.loads(envelope.content)
        except json.JSONDecodeError:
            pieces.append(envelope.content)
            continue
        pieces.extend(_strings(data))
    return "\n".join(pieces) if pieces else content


@final
class GulliblePolicy:
    """Follow the script; obey injected ``CALL_TOOL`` once each; adopt ``SET_FIELDS`` values."""

    def __init__(self, script: Sequence[ScriptedCall], sinks: Collection[str]) -> None:
        self._script = [(name, dict(args)) for name, args in script]
        self._sinks = frozenset(sinks)
        self._position = 0
        self._overrides: dict[str, JsonValue] = {}
        self._obeyed: set[str] = set()
        self.obeyed: list[str] = []

    def _inspect(self, request: LLMRequest) -> tuple[str, dict[str, JsonValue]] | None:
        injected: tuple[str, dict[str, JsonValue]] | None = None
        for block in request.messages[-1].content:
            if not isinstance(block, ToolResultBlock):
                continue
            text = _read_result(block.content)
            fields = find_field_overrides(text)
            if fields:
                for key, value in fields.items():
                    alias = _FIELD_ALIASES.get(key)
                    if alias is not None:
                        self._overrides[alias] = value
            call = find_tool_call(text)
            if call is not None and injected is None:
                key = json.dumps([call[0], call[1]], sort_keys=True)
                if key not in self._obeyed:
                    self._obeyed.add(key)
                    injected = call
        return injected

    def __call__(self, request: LLMRequest, rng: Any, turn: int) -> LLMResponse:
        del rng
        injected = self._inspect(request)
        if injected is not None:
            name, arguments = injected
            self.obeyed.append(name)
            return LLMResponse(
                model="fake-gullible",
                stop_reason="tool_use",
                tool_calls=(ToolUseBlock(id=f"injected_{turn}", name=name, arguments=arguments),),
            )
        if self._position < len(self._script):
            name, arguments = self._script[self._position]
            self._position += 1
            if name in self._sinks:
                arguments = {
                    key: self._overrides.get(key, value) for key, value in arguments.items()
                }
            return LLMResponse(
                model="fake-gullible",
                stop_reason="tool_use",
                tool_calls=(ToolUseBlock(id=f"step_{turn}", name=name, arguments=arguments),),
            )
        return LLMResponse(model="fake-gullible", stop_reason="end_turn", text="Done.")


@final
@dataclass(slots=True)
class BaselineResult:
    turns: int
    executed: list[tuple[str, dict[str, JsonValue]]] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    obeyed: list[str] = field(default_factory=list)
    final_text: str = ""


@final
class ReactBaseline:
    """Run the scripted gullible model against a workspace with no sink policy at all."""

    def __init__(self, *, max_turns: int = 30, seed: int = 0) -> None:
        self._max_turns = max_turns
        self._seed = seed

    def run(
        self, request: str, workspace: Workspace, script: Sequence[ScriptedCall]
    ) -> BaselineResult:
        registry, _ = workspace.build_tools()
        policy = GulliblePolicy(script, self._sink_names(registry))
        provider = FakeProvider(policy, seed=self._seed)
        messages: list[ChatMessage] = [ChatMessage.user(request)]
        result = BaselineResult(turns=0)
        specs = registry.specs()
        for _ in range(self._max_turns):
            response = provider.complete(
                LLMRequest(system=_SYSTEM, messages=tuple(messages), tools=specs, max_tokens=2048)
            )
            result.turns += 1
            if response.stop_reason != "tool_use" or not response.tool_calls:
                result.final_text = response.text
                break
            messages.append(ChatMessage(role="assistant", content=response.tool_calls))
            results: list[ToolResultBlock] = []
            for call in response.tool_calls:
                results.append(self._execute(registry, call, result))
            messages.append(ChatMessage(role="user", content=tuple(results)))
        else:
            messages.append(ChatMessage(role="assistant", content=(TextBlock(text="stopped"),)))
        result.obeyed = list(policy.obeyed)
        return result

    @staticmethod
    def _sink_names(registry: ToolRegistry) -> frozenset[str]:
        return frozenset(name for name in registry.names if registry.get(name).needs_approval)

    @staticmethod
    def _execute(
        registry: ToolRegistry, call: ToolUseBlock, result: BaselineResult
    ) -> ToolResultBlock:
        try:
            validated = registry.validate_call(call)
        except (ToolArgumentError, ToolNotAllowedError) as exc:
            result.failed.append(call.name)
            return ToolResultBlock(
                tool_use_id=call.id, content=f"error: {type(exc).__name__}", is_error=True
            )
        output = validated.run()
        result.executed.append((call.name, dict(validated.canonical_args)))
        return ToolResultBlock(
            tool_use_id=call.id, content=wrap_tool_result(call.name, output).render()
        )
