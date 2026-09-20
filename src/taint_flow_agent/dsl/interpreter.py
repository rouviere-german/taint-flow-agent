"""Label-propagating interpreter for parsed plans.

Every value is a :class:`Labeled` and every operation joins labels, so a value's label is always
at least the join of everything it was computed from (explicit flows). Control flow is tracked
with a program-counter label ``pc``: the test of an ``if`` and the collection of a ``for`` raise
``pc`` for the statements they guard, and ``pc`` is joined into assignments and into the
arguments of every tool call made under it (implicit flows). After a branch or loop, variables
assigned on the path that did *not* run are raised to ``pc`` as well, so the absence of an
assignment cannot launder a label (the classic no-sensitive-upgrade leak).

The propagation rules are named flags on :class:`PropagationRules`. Production always uses
``PropagationRules.all()``; the mutation benchmark switches rules off one at a time and checks
that an attack case catches every mutant.

Tools and the quarantined reader are injected through the :class:`ToolTable` and
:class:`Reader` protocols. The interpreter itself never executes anything but the syntax tree:
no ``eval``, no ``exec``, no attribute access on Python objects.
"""

from __future__ import annotations

import ast
import dataclasses
import math
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, NamedTuple, Protocol, final

from opentelemetry import trace
from opentelemetry.trace import Tracer

from taint_flow_agent.dsl.builtins import BUILTINS
from taint_flow_agent.dsl.errors import PlanError, PlanLimitError, PlanRuntimeError
from taint_flow_agent.dsl.grammar import Limits, Plan, assigned_names, describe_node
from taint_flow_agent.dsl.provenance import ProvenanceGraph
from taint_flow_agent.ifc.labels import BOTTOM, Integrity, Label, join_all
from taint_flow_agent.ifc.values import Labeled, Plain, effective_label, from_plain, to_plain

__all__ = [
    "READER_FUNCTION",
    "CallDeniedError",
    "CallHeldError",
    "Denial",
    "ExecutionResult",
    "HeldCall",
    "Interpreter",
    "PendingCall",
    "PropagationRules",
    "Reader",
    "RunStatus",
    "StatementObserver",
    "ToolCallRecord",
    "ToolOutcome",
    "ToolTable",
]

READER_FUNCTION = "query_quarantined"
RunStatus = Literal["completed", "denied", "held", "error", "limit"]
_INTEGRITY_CEILING_FOR_READER = Integrity.TRUSTED_TOOL


@final
@dataclass(frozen=True, slots=True)
class PropagationRules:
    """Label propagation rules. Each one is independently necessary (see bench/bench_mutation)."""

    assign_joins_pc: bool = True
    branch_raises_pc: bool = True
    loop_raises_pc: bool = True
    control_flow_upgrades_assigned: bool = True
    call_args_join_pc: bool = True
    index_joins_container: bool = True
    operator_joins_operands: bool = True
    compare_joins_operands: bool = True
    boolop_joins_operands: bool = True
    fstring_joins_parts: bool = True
    builtin_joins_args: bool = True
    container_joins_elements: bool = True
    tool_result_joins_args: bool = True
    tool_result_labeled_by_source: bool = True
    reader_output_joins_input: bool = True

    @classmethod
    def all(cls) -> PropagationRules:
        return cls()

    @classmethod
    def names(cls) -> tuple[str, ...]:
        return tuple(f.name for f in dataclasses.fields(cls))

    def without(self, name: str) -> PropagationRules:
        if name not in self.names():
            raise ValueError(f"unknown propagation rule {name!r}")
        return dataclasses.replace(self, **{name: False})

    @property
    def disabled(self) -> tuple[str, ...]:
        return tuple(name for name in self.names() if not getattr(self, name))


@final
@dataclass(frozen=True, slots=True)
class PendingCall:
    """A tool call the interpreter wants to make, with labels ready for the policy engine."""

    name: str
    args: Mapping[str, Labeled[Any]]
    arg_labels: Mapping[str, Label]
    pc: Label
    statement: int
    arg_nodes: Mapping[str, int]
    call_node: int
    is_sink: bool

    def plain_args(self) -> dict[str, Plain]:
        return {name: to_plain(value) for name, value in self.args.items()}


@final
@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    name: str
    statement: int
    args: dict[str, Plain]
    arg_labels: dict[str, dict[str, Any]]
    pc: dict[str, Any]
    outcome: Literal["executed", "denied", "held", "error"]
    call_hash: str
    is_sink: bool
    rule: str | None = None
    result_label: dict[str, Any] | None = None


@final
@dataclass(frozen=True, slots=True)
class Denial:
    sink: str
    argument: str
    rule: str
    reason: str
    call_hash: str
    statement: int
    provenance_path: tuple[str, ...]
    provenance_depth: int


@final
@dataclass(frozen=True, slots=True)
class HeldCall:
    sink: str
    argument: str
    rule: str
    call_hash: str
    request_id: str
    statement: int
    provenance_path: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class ToolOutcome:
    value: Labeled[Any]
    record: ToolCallRecord


class CallDeniedError(PlanError):
    """A sink call violated policy; the run stops here (fail closed)."""

    def __init__(self, denial: Denial, record: ToolCallRecord) -> None:
        super().__init__(f"{denial.sink}.{denial.argument} denied by rule {denial.rule}")
        self.denial = denial
        self.record = record


class CallHeldError(PlanError):
    """A sink call is waiting for human declassification; the run stops here."""

    def __init__(self, held: HeldCall, record: ToolCallRecord) -> None:
        super().__init__(f"{held.sink}.{held.argument} held for declassification")
        self.held = held
        self.record = record


class ToolTable(Protocol):
    """Registered tools as seen by the interpreter."""

    def names(self) -> Collection[str]: ...

    def is_sink(self, name: str) -> bool: ...

    def parameters(self, name: str) -> tuple[str, ...]: ...

    def invoke(self, call: PendingCall, provenance: ProvenanceGraph) -> ToolOutcome:
        """Validate, check policy, execute and label. Raises CallDeniedError / CallHeldError."""
        ...


class Reader(Protocol):
    """The quarantined reader: schema-validated extraction over untrusted data, no tools."""

    def schemas(self) -> Collection[str]: ...

    def query(self, schema: str, data: Plain, instruction: str | None) -> Plain: ...


class StatementObserver(Protocol):
    def __call__(
        self,
        *,
        statement: int,
        kind: str,
        description: str,
        pc: Label,
        assigned: str | None,
        label: Label | None,
    ) -> None: ...


@final
@dataclass(slots=True)
class ExecutionResult:
    status: RunStatus
    statements: int
    steps: int
    calls: list[ToolCallRecord]
    provenance: ProvenanceGraph
    env: dict[str, Labeled[Any]]
    denial: Denial | None = None
    held: HeldCall | None = None
    error: str | None = None
    reader_queries: int = 0

    @property
    def executed_calls(self) -> list[ToolCallRecord]:
        return [c for c in self.calls if c.outcome == "executed"]

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "statements": self.statements,
            "steps": self.steps,
            "executed": [c.name for c in self.executed_calls],
            "denied": None
            if self.denial is None
            else {"sink": self.denial.sink, "rule": self.denial.rule},
            "held": None if self.held is None else {"sink": self.held.sink},
            "error": self.error,
            "reader_queries": self.reader_queries,
        }


class _Eval(NamedTuple):
    value: Labeled[Any]
    deps: frozenset[int]


@dataclass(slots=True)
class _State:
    env: dict[str, tuple[Labeled[Any], int]]
    pc: list[tuple[Label, int | None]] = field(default_factory=lambda: [(BOTTOM, None)])
    steps: int = 0
    statements: int = 0
    reader_queries: int = 0
    calls: list[ToolCallRecord] = field(default_factory=list)
    provenance: ProvenanceGraph = field(default_factory=ProvenanceGraph)
    deadline: float = 0.0

    @property
    def pc_label(self) -> Label:
        return self.pc[-1][0]

    @property
    def pc_nodes(self) -> frozenset[int]:
        return frozenset(node for _, node in self.pc if node is not None)


def _node[T: ast.AST](value: object, expected: type[T]) -> T:
    """Narrow a syntax node the parser already guaranteed.

    ``parse_plan`` refuses anything else long before the interpreter sees it, so a mismatch is a
    bug in this package, not hostile input. It raises (rather than asserting) so the check still
    holds when Python runs with ``-O``.
    """
    if not isinstance(value, expected):  # pragma: no cover - guaranteed by parse_plan
        raise PlanRuntimeError(f"internal error: expected {expected.__name__} in the plan tree")
    return value


@final
class Interpreter:
    def __init__(
        self,
        tools: ToolTable,
        reader: Reader | None = None,
        *,
        limits: Limits | None = None,
        rules: PropagationRules | None = None,
        tracer: Tracer | None = None,
        observer: StatementObserver | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._tools = tools
        self._reader = reader
        self._limits = limits or Limits()
        self._rules = rules or PropagationRules.all()
        self._tracer = tracer or trace.get_tracer("taint_flow_agent.dsl")
        self._observer = observer
        self._clock = clock
        names = set(tools.names()) | set(BUILTINS)
        if reader is not None:
            names.add(READER_FUNCTION)
        overlap = set(tools.names()) & (set(BUILTINS) | {READER_FUNCTION})
        if overlap:
            raise ValueError(f"tool names collide with builtins: {sorted(overlap)}")
        self._known = frozenset(names)

    @property
    def known_functions(self) -> frozenset[str]:
        """Names a plan may call: registered tools, builtins and the quarantined reader."""
        return self._known

    @property
    def rules(self) -> PropagationRules:
        return self._rules

    @property
    def limits(self) -> Limits:
        return self._limits

    # ----------------------------------------------------------------------------- execution

    def run(
        self, plan: Plan, *, initial: Mapping[str, Labeled[Any]] | None = None
    ) -> ExecutionResult:
        state = _State(env={}, deadline=self._clock() + self._limits.timeout_seconds)
        for name, value in (initial or {}).items():
            node = state.provenance.add("user_request", f"input {name}", effective_label(value))
            state.env[name] = (value, node)
        status: RunStatus = "completed"
        denial: Denial | None = None
        held: HeldCall | None = None
        error: str | None = None
        try:
            self._exec_block(plan.body, state)
        except CallDeniedError as exc:
            status, denial = "denied", exc.denial
        except CallHeldError as exc:
            status, held = "held", exc.held
        except PlanLimitError as exc:
            status, error = "limit", str(exc)
        except PlanRuntimeError as exc:
            status, error = "error", str(exc)
        except (OverflowError, RecursionError) as exc:
            status, error = "limit", f"{type(exc).__name__} while executing the plan"
        return ExecutionResult(
            status=status,
            statements=state.statements,
            steps=state.steps,
            calls=state.calls,
            provenance=state.provenance,
            env={name: value for name, (value, _) in state.env.items()},
            denial=denial,
            held=held,
            error=error,
            reader_queries=state.reader_queries,
        )

    def _tick(self, state: _State, statement: int | None = None) -> None:
        state.steps += 1
        if state.steps > self._limits.max_steps:
            raise PlanLimitError("steps", self._limits.max_steps, statement=statement)
        if self._clock() > state.deadline:
            raise PlanLimitError("wall-clock", self._limits.timeout_seconds, statement=statement)

    def _exec_block(self, statements: Sequence[ast.stmt], state: _State) -> None:
        for statement in statements:
            self._exec_statement(statement, state)

    def _exec_statement(self, statement: ast.stmt, state: _State) -> None:
        index = state.statements
        state.statements += 1
        self._tick(state, index)
        description = describe_node(statement)
        kind = type(statement).__name__.lower()
        with self._tracer.start_as_current_span("plan.statement") as span:
            span.set_attribute("plan.statement", index)
            span.set_attribute("plan.kind", kind)
            span.set_attribute("plan.pc.integrity", state.pc_label.integrity.name.lower())
            assigned: str | None = None
            label: Label | None = None
            try:
                assigned, label = self._dispatch(statement, state, index)
            except PlanRuntimeError as exc:
                # Attach the statement index in place: re-wrapping would erase the subclass and
                # downgrade a PlanLimitError (status "limit") into a plain error.
                if exc.statement is None:
                    exc.statement = index
                raise
            if label is not None:
                span.set_attribute("plan.label.integrity", label.integrity.name.lower())
                span.set_attribute("plan.label.sources", len(label.sources))
            if self._observer is not None:
                self._observer(
                    statement=index,
                    kind=kind,
                    description=description,
                    pc=state.pc_label,
                    assigned=assigned,
                    label=label,
                )

    def _dispatch(
        self, statement: ast.stmt, state: _State, index: int
    ) -> tuple[str | None, Label | None]:
        if isinstance(statement, ast.Assign):
            return self._exec_assign(statement, state, index)
        if isinstance(statement, ast.Expr):
            self._eval(statement.value, state, index)
        elif isinstance(statement, ast.If):
            self._exec_if(statement, state, index)
        elif isinstance(statement, ast.For):
            self._exec_for(statement, state, index)
        else:  # pragma: no cover - the parser only admits the four kinds above
            raise PlanRuntimeError(
                f"unsupported statement {type(statement).__name__}", statement=index
            )
        return None, None

    def _bind(
        self,
        name: str,
        value: Labeled[Any],
        deps: frozenset[int],
        state: _State,
        index: int,
        *,
        kind: str = "variable",
    ) -> Label:
        label = value.label
        if self._rules.assign_joins_pc:
            label = label.join(state.pc_label)
        bound = Labeled(value.value, label)
        node = state.provenance.add(
            kind,
            name,
            self._effective(bound),
            statement=index,
            depends_on=deps | state.pc_nodes,
        )
        state.env[name] = (bound, node)
        return label

    def _exec_assign(self, statement: ast.Assign, state: _State, index: int) -> tuple[str, Label]:
        target = _node(statement.targets[0], ast.Name)
        value, deps = self._eval(statement.value, state, index)
        return target.id, self._bind(target.id, value, deps, state, index)

    def _upgrade_assigned(
        self, names: frozenset[str], pc: Label, node: int | None, state: _State, index: int
    ) -> None:
        """Raise variables assigned on the path that did not run to the guard's pc."""
        if not self._rules.control_flow_upgrades_assigned:
            return
        for name in sorted(names):
            entry = state.env.get(name)
            if entry is None:
                continue
            current, old_node = entry
            upgraded = current.joined_with(pc)
            if upgraded.label == current.label:
                continue
            new_node = state.provenance.add(
                "variable",
                f"{name} (raised after control flow)",
                self._effective(upgraded),
                statement=index,
                depends_on=frozenset({old_node} | ({node} if node is not None else set())),
            )
            state.env[name] = (upgraded, new_node)

    def _exec_if(self, statement: ast.If, state: _State, index: int) -> None:
        test, deps = self._eval(statement.test, state, index)
        guard = self._effective(test)
        raised = state.pc_label.join(guard) if self._rules.branch_raises_pc else state.pc_label
        node = state.provenance.add(
            "branch", describe_node(statement), guard, statement=index, depends_on=deps
        )
        taken = self._truthy(test)
        state.pc.append((raised, node))
        try:
            self._exec_block(statement.body if taken else statement.orelse, state)
        finally:
            state.pc.pop()
        skipped = statement.orelse if taken else statement.body
        self._upgrade_assigned(assigned_names(skipped), raised, node, state, index)

    def _exec_for(self, statement: ast.For, state: _State, index: int) -> None:
        target = _node(statement.target, ast.Name)
        iterable, deps = self._eval(statement.iter, state, index)
        if not isinstance(iterable.value, tuple):
            raise PlanRuntimeError("for loops iterate over lists only", statement=index)
        items = iterable.value
        if len(items) > self._limits.max_collection_size:
            raise PlanLimitError(
                "collection size", self._limits.max_collection_size, statement=index
            )
        guard = iterable.label
        raised = state.pc_label.join(guard) if self._rules.loop_raises_pc else state.pc_label
        node = state.provenance.add(
            "loop", describe_node(statement), guard, statement=index, depends_on=deps
        )
        state.pc.append((raised, node))
        try:
            for position, item in enumerate(items):
                if position >= self._limits.max_loop_iterations:
                    raise PlanLimitError(
                        "loop iterations", self._limits.max_loop_iterations, statement=index
                    )
                self._tick(state, index)
                element = self._element(item, iterable)
                self._bind(target.id, element, deps | {node}, state, index, kind="loop_variable")
                self._exec_block(statement.body, state)
        finally:
            state.pc.pop()
        if not items:
            self._upgrade_assigned(
                assigned_names(statement.body) | {target.id}, raised, node, state, index
            )

    # ---------------------------------------------------------------------------- expressions

    def _effective(self, value: Labeled[Any]) -> Label:
        return effective_label(value) if self._rules.container_joins_elements else value.label

    def _element(self, item: Labeled[Any], container: Labeled[Any]) -> Labeled[Any]:
        if self._rules.index_joins_container:
            return item.joined_with(container.label)
        return item

    @staticmethod
    def _truthy(value: Labeled[Any]) -> bool:
        inner = value.value
        if isinstance(inner, (tuple, Mapping, str)):
            return len(inner) > 0
        return bool(inner)

    def _eval(self, node: ast.expr, state: _State, index: int) -> _Eval:  # noqa: PLR0911
        if isinstance(node, ast.Constant):
            return _Eval(Labeled(node.value, Label.user("plan")), frozenset())
        if isinstance(node, ast.Name):
            entry = state.env.get(node.id)
            if entry is None:
                raise PlanRuntimeError(f"name {node.id!r} is not defined", statement=index)
            return _Eval(entry[0], frozenset({entry[1]}))
        if isinstance(node, ast.List):
            return self._eval_list(node, state, index)
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, state, index)
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(node, state, index)
        if isinstance(node, ast.Call):
            return self._eval_call(node, state, index)
        if isinstance(node, ast.Compare):
            return self._eval_compare(node, state, index)
        if isinstance(node, ast.BoolOp):
            return self._eval_boolop(node, state, index)
        if isinstance(node, ast.UnaryOp):
            return self._eval_unary(node, state, index)
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node, state, index)
        if isinstance(node, ast.JoinedStr):
            return self._eval_fstring(node, state, index)
        raise PlanRuntimeError(  # pragma: no cover - excluded by the parser
            f"unsupported expression {type(node).__name__}", statement=index
        )

    def _eval_list(self, node: ast.List, state: _State, index: int) -> _Eval:
        items: list[Labeled[Any]] = []
        deps: set[int] = set()
        for element in node.elts:
            value, element_deps = self._eval(element, state, index)
            items.append(value)
            deps |= element_deps
        return _Eval(Labeled(tuple(items), Label.user("plan")), frozenset(deps))

    def _eval_dict(self, node: ast.Dict, state: _State, index: int) -> _Eval:
        mapping: dict[str, Labeled[Any]] = {}
        deps: set[int] = set()
        for key, value_node in zip(node.keys, node.values, strict=True):
            constant = _node(key, ast.Constant)
            value, value_deps = self._eval(value_node, state, index)
            mapping[str(constant.value)] = value
            deps |= value_deps
        return _Eval(Labeled(mapping, Label.user("plan")), frozenset(deps))

    def _eval_subscript(self, node: ast.Subscript, state: _State, index: int) -> _Eval:
        container, deps = self._eval(node.value, state, index)
        key, key_deps = self._eval(node.slice, state, index)
        inner = container.value
        if isinstance(inner, Mapping):
            if not isinstance(key.value, str):
                raise PlanRuntimeError("dict keys must be strings", statement=index)
            if key.value not in inner:
                raise PlanRuntimeError("missing dict key", statement=index)
            selected = inner[key.value]
        elif isinstance(inner, tuple):
            if isinstance(key.value, bool) or not isinstance(key.value, int):
                raise PlanRuntimeError("list indexes must be integers", statement=index)
            if not -len(inner) <= key.value < len(inner):
                raise PlanRuntimeError("list index out of range", statement=index)
            selected = inner[key.value]
        else:
            raise PlanRuntimeError("only lists and dicts can be indexed", statement=index)
        result = self._element(selected, container)
        if self._rules.index_joins_container:
            result = result.joined_with(self._effective(key))
        return _Eval(result, deps | key_deps)

    def _eval_compare(self, node: ast.Compare, state: _State, index: int) -> _Eval:
        left, left_deps = self._eval(node.left, state, index)
        right, right_deps = self._eval(node.comparators[0], state, index)
        operator = node.ops[0]
        a, b = to_plain(left), to_plain(right)
        try:
            if isinstance(operator, ast.Eq):
                outcome = a == b
            elif isinstance(operator, ast.NotEq):
                outcome = a != b
            elif isinstance(operator, (ast.In, ast.NotIn)):
                outcome = self._membership(a, b, index)
                if isinstance(operator, ast.NotIn):
                    outcome = not outcome
            else:
                outcome = self._ordered(a, b, operator, index)
        except TypeError as exc:
            raise PlanRuntimeError(
                "comparison between incompatible types", statement=index
            ) from exc
        label = BOTTOM
        if self._rules.compare_joins_operands:
            label = self._effective(left).join(self._effective(right))
        return _Eval(Labeled(outcome, label), left_deps | right_deps)

    @staticmethod
    def _membership(a: Plain, b: Plain, index: int) -> bool:
        if isinstance(b, str):
            if not isinstance(a, str):
                raise PlanRuntimeError("'in' on a string needs a string", statement=index)
            return a in b
        if isinstance(b, list):
            return a in b
        if isinstance(b, dict):
            return isinstance(a, str) and a in b
        raise PlanRuntimeError("'in' needs a list, dict or string", statement=index)

    @staticmethod
    def _ordered(a: Plain, b: Plain, operator: ast.cmpop, index: int) -> bool:
        if isinstance(a, str) and isinstance(b, str):
            left: float | str = a
            right: float | str = b
        elif all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (a, b)):
            left = float(a) if isinstance(a, (int, float)) else 0.0
            right = float(b) if isinstance(b, (int, float)) else 0.0
        else:
            raise PlanRuntimeError("ordering needs two numbers or two strings", statement=index)
        if isinstance(operator, ast.Lt):
            return left < right  # type: ignore[operator]
        if isinstance(operator, ast.LtE):
            return left <= right  # type: ignore[operator]
        if isinstance(operator, ast.Gt):
            return left > right  # type: ignore[operator]
        return left >= right  # type: ignore[operator]

    def _eval_boolop(self, node: ast.BoolOp, state: _State, index: int) -> _Eval:
        deps: set[int] = set()
        labels: list[Label] = []
        result: Labeled[Any] | None = None
        is_and = isinstance(node.op, ast.And)
        for value_node in node.values:
            value, value_deps = self._eval(value_node, state, index)
            deps |= value_deps
            labels.append(self._effective(value))
            result = value
            truthy = self._truthy(value)
            if (is_and and not truthy) or (not is_and and truthy):
                break
        if result is None:  # pragma: no cover - the grammar gives every BoolOp two operands
            raise PlanRuntimeError("boolean operator without operands", statement=index)
        label = join_all(labels) if self._rules.boolop_joins_operands else BOTTOM
        return _Eval(Labeled(result.value, result.label.join(label)), frozenset(deps))

    def _eval_unary(self, node: ast.UnaryOp, state: _State, index: int) -> _Eval:
        operand, deps = self._eval(node.operand, state, index)
        label = self._effective(operand) if self._rules.operator_joins_operands else BOTTOM
        if isinstance(node.op, ast.Not):
            return _Eval(Labeled(not self._truthy(operand), label), deps)
        inner = operand.value
        if isinstance(inner, bool) or not isinstance(inner, (int, float)):
            raise PlanRuntimeError("unary minus needs a number", statement=index)
        return _Eval(Labeled(-inner, label), deps)

    def _eval_binop(self, node: ast.BinOp, state: _State, index: int) -> _Eval:
        left, left_deps = self._eval(node.left, state, index)
        right, right_deps = self._eval(node.right, state, index)
        a, b = left.value, right.value
        deps = left_deps | right_deps
        if isinstance(node.op, ast.Add) and isinstance(a, tuple) and isinstance(b, tuple):
            if len(a) + len(b) > self._limits.max_collection_size:
                raise PlanLimitError(
                    "collection size", self._limits.max_collection_size, statement=index
                )
            label = left.label.join(right.label) if self._rules.operator_joins_operands else BOTTOM
            return _Eval(Labeled(a + b, label), deps)
        if isinstance(node.op, ast.Add) and isinstance(a, str) and isinstance(b, str):
            if len(a) + len(b) > self._limits.max_value_chars:
                raise PlanLimitError("value size", self._limits.max_value_chars, statement=index)
            outcome: Plain = a + b
        else:
            outcome = self._arithmetic(node.op, a, b, index)
        label = BOTTOM
        if self._rules.operator_joins_operands:
            label = self._effective(left).join(self._effective(right))
        return _Eval(Labeled(outcome, label), deps)

    @staticmethod
    def _arithmetic(operator: ast.operator, a: Any, b: Any, index: int) -> int | float:
        if (
            isinstance(a, bool)
            or isinstance(b, bool)
            or not isinstance(a, (int, float))
            or not isinstance(b, (int, float))
        ):
            raise PlanRuntimeError(
                "operator needs two numbers, two strings or two lists", statement=index
            )
        if isinstance(operator, ast.Add):
            outcome = a + b
        elif isinstance(operator, ast.Sub):
            outcome = a - b
        else:
            outcome = a * b
        if isinstance(outcome, float) and not math.isfinite(outcome):
            raise PlanRuntimeError("arithmetic overflow", statement=index)
        if isinstance(outcome, int) and abs(outcome) > 10**18:
            raise PlanRuntimeError("integer too large", statement=index)
        return outcome

    def _eval_fstring(self, node: ast.JoinedStr, state: _State, index: int) -> _Eval:
        pieces: list[str] = []
        deps: set[int] = set()
        labels: list[Label] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                pieces.append(str(part.value))
                continue
            formatted = _node(part, ast.FormattedValue)
            value, part_deps = self._eval(formatted.value, state, index)
            deps |= part_deps
            labels.append(self._effective(value))
            inner = value.value
            if inner is None or isinstance(inner, (bool, int, float, str)):
                pieces.append(str(inner))
            else:
                raise PlanRuntimeError("f-strings can only format scalars", statement=index)
        text = "".join(pieces)
        if len(text) > self._limits.max_value_chars:
            raise PlanLimitError("value size", self._limits.max_value_chars, statement=index)
        label = join_all(labels) if self._rules.fstring_joins_parts else BOTTOM
        return _Eval(Labeled(text, label), frozenset(deps))

    # ---------------------------------------------------------------------------------- calls

    def _eval_call(self, node: ast.Call, state: _State, index: int) -> _Eval:
        name = _node(node.func, ast.Name).id
        positional: list[_Eval] = [self._eval(arg, state, index) for arg in node.args]
        keywords: dict[str, _Eval] = {}
        for keyword in node.keywords:
            if keyword.arg is None:  # pragma: no cover - ** unpacking is rejected at parse
                raise PlanRuntimeError("keyword argument without a name", statement=index)
            keywords[keyword.arg] = self._eval(keyword.value, state, index)
        if name in BUILTINS:
            if keywords:
                raise PlanRuntimeError(f"{name}() takes positional arguments only", statement=index)
            return self._call_builtin(name, positional)
        if name == READER_FUNCTION:
            return self._call_reader(positional, keywords, state, index)
        return self._call_tool(name, positional, keywords, state, index)

    def _call_builtin(self, name: str, positional: list[_Eval]) -> _Eval:
        result = BUILTINS[name]([item.value for item in positional])
        deps = frozenset().union(*(item.deps for item in positional)) if positional else frozenset()
        if self._rules.builtin_joins_args:
            result = result.joined_with(
                join_all(self._effective(item.value) for item in positional)
            )
        return _Eval(result, deps)

    def _call_reader(
        self, positional: list[_Eval], keywords: dict[str, _Eval], state: _State, index: int
    ) -> _Eval:
        if self._reader is None:
            raise PlanRuntimeError("no quarantined reader is configured", statement=index)
        if len(positional) != 2 or set(keywords) - {"instruction"}:
            raise PlanRuntimeError(
                f"{READER_FUNCTION}(schema, data, instruction=...) takes a schema and data",
                statement=index,
            )
        schema, data = positional[0].value, positional[1].value
        if not isinstance(schema.value, str) or schema.label.integrity is not Integrity.USER:
            raise PlanRuntimeError("the reader schema must be a plan constant", statement=index)
        if schema.value not in self._reader.schemas():
            raise PlanRuntimeError(f"unknown reader schema {schema.value!r}", statement=index)
        instruction: str | None = None
        if "instruction" in keywords:
            hint = keywords["instruction"].value
            if not isinstance(hint.value, str) or hint.label.integrity is not Integrity.USER:
                raise PlanRuntimeError(
                    "the reader instruction must be a plan constant", statement=index
                )
            instruction = hint.value
        state.reader_queries += 1
        self._tick(state, index)
        input_label = self._effective(data).join(state.pc_label)
        deps = positional[1].deps | state.pc_nodes
        query_node = state.provenance.add(
            "reader_query",
            f"{READER_FUNCTION}({schema.value})",
            input_label,
            statement=index,
            depends_on=deps,
        )
        output = self._reader.query(schema.value, to_plain(data), instruction)
        source = f"reader#{state.reader_queries}"
        if self._rules.reader_output_joins_input:
            label = input_label.with_integrity_at_most(_INTEGRITY_CEILING_FOR_READER)
        else:
            label = Label(_INTEGRITY_CEILING_FOR_READER)
        label = label.with_sources(source)
        value = from_plain(output, label)
        output_node = state.provenance.add(
            "reader_output", source, label, statement=index, depends_on={query_node}
        )
        return _Eval(value, frozenset({output_node}))

    def _call_tool(
        self,
        name: str,
        positional: list[_Eval],
        keywords: dict[str, _Eval],
        state: _State,
        index: int,
    ) -> _Eval:
        parameters = self._tools.parameters(name)
        if len(positional) > len(parameters):
            raise PlanRuntimeError(f"too many positional arguments for {name}", statement=index)
        bound: dict[str, _Eval] = dict(zip(parameters, positional, strict=False))
        for key, item in keywords.items():
            if key in bound:
                raise PlanRuntimeError(f"argument {key!r} given twice for {name}", statement=index)
            bound[key] = item
        is_sink = self._tools.is_sink(name)
        pc = state.pc_label
        arg_labels: dict[str, Label] = {}
        arg_nodes: dict[str, int] = {}
        all_deps: set[int] = set()
        for key, item in bound.items():
            label = self._effective(item.value)
            if self._rules.call_args_join_pc:
                label = label.join(pc)
            arg_labels[key] = label
            all_deps |= item.deps
            arg_nodes[key] = state.provenance.add(
                "sink_argument" if is_sink else "argument",
                f"{name}.{key}",
                label,
                statement=index,
                depends_on=item.deps | state.pc_nodes,
            )
        call_node = state.provenance.add(
            "sink_call" if is_sink else "tool_call",
            f"{name}(...)",
            join_all(arg_labels.values()).join(pc),
            statement=index,
            depends_on=set(arg_nodes.values()) | state.pc_nodes,
        )
        self._tick(state, index)
        call = PendingCall(
            name=name,
            args={key: item.value for key, item in bound.items()},
            arg_labels=arg_labels,
            pc=pc,
            statement=index,
            arg_nodes=arg_nodes,
            call_node=call_node,
            is_sink=is_sink,
        )
        try:
            outcome = self._tools.invoke(call, state.provenance)
        except (CallDeniedError, CallHeldError) as exc:
            state.calls.append(exc.record)
            raise
        state.calls.append(outcome.record)
        value = outcome.value
        if not self._rules.tool_result_labeled_by_source:
            value = from_plain(to_plain(value), BOTTOM)
        joined = join_all(arg_labels.values()).join(pc)
        if self._rules.tool_result_joins_args:
            value = value.joined_with(joined)
        result_node = state.provenance.add(
            "tool_result",
            f"result of {name}",
            self._effective(value),
            statement=index,
            depends_on={call_node},
        )
        return _Eval(value, frozenset({result_node}))
