"""Label propagation through the interpreter: explicit flows, implicit flows, limits, errors."""

from __future__ import annotations

import ast
from collections.abc import Collection, Mapping
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from taint_flow_agent.dsl.errors import PlanError
from taint_flow_agent.dsl.grammar import Limits, Plan, parse_plan
from taint_flow_agent.dsl.interpreter import (
    CallDeniedError,
    CallHeldError,
    Denial,
    ExecutionResult,
    HeldCall,
    Interpreter,
    PendingCall,
    PropagationRules,
    ToolCallRecord,
    ToolOutcome,
)
from taint_flow_agent.dsl.provenance import ProvenanceGraph
from taint_flow_agent.ifc.labels import BOTTOM, Integrity, Label, Readers, join_all
from taint_flow_agent.ifc.values import Labeled, Plain, effective_label, from_plain, to_plain

pytestmark = pytest.mark.unit

UNTRUSTED = Label.untrusted("email:1", readers=Readers.of({"me", "dana"}))
TRUSTED = Label.trusted_tool("tool:contacts", readers=Readers.of({"me"}))


class FakeTable:
    """A tool table whose sinks deny *protected* arguments below ``required`` integrity.

    Like the real policy, only the arguments that decide where an effect lands are protected
    (``to``, ``amount``); free-text bodies may carry untrusted content.
    """

    def __init__(
        self,
        *,
        required: Integrity = Integrity.USER,
        hold: bool = False,
        protected: Collection[str] = ("to", "amount"),
    ) -> None:
        self.required = required
        self.hold = hold
        self.protected = frozenset(protected)
        self.calls: list[PendingCall] = []
        self.results: dict[str, Plain] = {
            "fetch": {"body": "untrusted text", "n": 3, "items": ["a", "b"]},
            "lookup": {"account": "ACC-1"},
        }
        self.labels = {"fetch": UNTRUSTED, "lookup": TRUSTED}

    def names(self) -> Collection[str]:
        return ("fetch", "lookup", "send", "pay")

    def is_sink(self, name: str) -> bool:
        return name in {"send", "pay"}

    def parameters(self, name: str) -> tuple[str, ...]:
        return {"fetch": ("id",), "lookup": ("name",), "send": ("to", "body"), "pay": ("amount",)}[
            name
        ]

    def _record(self, call: PendingCall, outcome: str) -> ToolCallRecord:
        return ToolCallRecord(
            name=call.name,
            statement=call.statement,
            args=call.plain_args(),
            arg_labels={k: v.summary() for k, v in call.arg_labels.items()},
            pc=call.pc.summary(),
            outcome=outcome,  # type: ignore[arg-type]
            call_hash="0" * 64,
            is_sink=call.is_sink,
        )

    def invoke(self, call: PendingCall, provenance: ProvenanceGraph) -> ToolOutcome:
        self.calls.append(call)
        if call.is_sink:
            for argument, label in call.arg_labels.items():
                if argument in self.protected and label.integrity < self.required:
                    path = tuple(provenance.render_path(call.arg_nodes[argument]))
                    if self.hold:
                        held = HeldCall(
                            call.name, argument, "rule", "0" * 64, "req-1", call.statement, path
                        )
                        raise CallHeldError(held, self._record(call, "held"))
                    denial = Denial(
                        call.name,
                        argument,
                        "rule",
                        "low integrity",
                        "0" * 64,
                        call.statement,
                        path,
                        provenance.depth(call.arg_nodes[argument]),
                    )
                    raise CallDeniedError(denial, self._record(call, "denied"))
            return ToolOutcome(
                from_plain({"ok": True}, Label.trusted_tool(f"tool:{call.name}")),
                self._record(call, "executed"),
            )
        return ToolOutcome(
            from_plain(self.results[call.name], self.labels[call.name]),
            self._record(call, "executed"),
        )


class FakeReader:
    def __init__(self) -> None:
        self.queries: list[tuple[str, Plain, str | None]] = []

    def schemas(self) -> Collection[str]:
        return ("invoice",)

    def query(self, schema: str, data: Plain, instruction: str | None) -> Plain:
        self.queries.append((schema, data, instruction))
        return {"account": "ACC-9", "amount": 5}


def run(
    source: str,
    *,
    table: FakeTable | None = None,
    reader: FakeReader | None = None,
    rules: PropagationRules | None = None,
    limits: Limits | None = None,
    initial: Mapping[str, Labeled[Any]] | None = None,
    clock: Any = None,
) -> ExecutionResult:
    table = table or FakeTable()
    kwargs: dict[str, Any] = {}
    if clock is not None:
        kwargs["clock"] = clock
    interpreter = Interpreter(table, reader, limits=limits, rules=rules, **kwargs)
    plan = parse_plan(
        source, known_functions=interpreter.known_functions, limits=limits or Limits()
    )
    return interpreter.run(plan, initial=initial)


def label_of(result: ExecutionResult, name: str) -> Label:
    return effective_label(result.env[name])


# ----------------------------------------------------------------------------- explicit flows


def test_explicit_flows_join_labels_and_keep_provenance() -> None:
    result = run(
        'e = fetch(id="1")\n'
        'p = lookup(name="x")\n'
        'a = e["body"] + "!"\n'
        "b = f\"{e['n']}-{p['account']}\"\n"
        'c = lower(e["body"])\n'
        'd = [e["body"], "k"]\n'
        'g = {"k": p["account"]}\n'
        'h = e["items"][0]\n'
        'i = e["n"] * 2\n'
        'j = e["n"] < 5\n'
        'k = (e["n"] == 3) and p["account"]\n'
        'm = not e["n"]\n'
        'n = -e["n"]\n'
        'o = "k" in g\n'
        'q = str(e["n"])\n'
    )
    assert result.status == "completed"
    for name in "achijmnq":
        assert label_of(result, name).integrity is Integrity.UNTRUSTED, name
        assert "email:1" in label_of(result, name).sources
    # `o` is `"k" in g`, and g holds only the trusted lookup result: no untrusted input flows in.
    assert label_of(result, "o").integrity is Integrity.TRUSTED_TOOL
    assert "email:1" not in label_of(result, "o").sources
    # "plan" joins in from the dict key constants: indexing joins the key label too.
    assert label_of(result, "b") == UNTRUSTED.join(TRUSTED).with_sources("plan")
    assert label_of(result, "d").integrity is Integrity.UNTRUSTED
    assert label_of(result, "g") == TRUSTED.with_sources("plan")
    assert label_of(result, "k") == UNTRUSTED.join(TRUSTED).with_sources("plan")
    assert result.env["g"].label == Label.user("plan")  # the container itself is plan-made
    node = result.provenance
    assert node.depth(next(n for n in node.graph.nodes if node.node(n).description == "a")) >= 2


def test_reader_output_is_labeled_with_its_input_and_capped() -> None:
    reader = FakeReader()
    result = run(
        'e = fetch(id="1")\n'
        'inv = query_quarantined("invoice", e, instruction="amount?")\n'
        'x = query_quarantined("invoice", "plain constant")\n',
        reader=reader,
    )
    assert result.status == "completed"
    assert result.reader_queries == 2
    inv = label_of(result, "inv")
    assert inv.integrity is Integrity.UNTRUSTED
    assert {"email:1", "reader#1"} <= inv.sources
    assert inv.readers == UNTRUSTED.readers
    x = label_of(result, "x")
    assert x.integrity is Integrity.TRUSTED_TOOL  # never higher than a tool, even for constants
    assert reader.queries[0] == (
        "invoice",
        {"body": "untrusted text", "n": 3, "items": ["a", "b"]},
        "amount?",
    )
    assert reader.queries[1][2] is None


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ('inv = query_quarantined("invoice")\n', "takes a schema"),
        ('inv = query_quarantined("nope", "d")\n', "unknown reader schema"),
        ('e = fetch(id="1")\ninv = query_quarantined(e["body"], "d")\n', "plan constant"),
        (
            'e = fetch(id="1")\ninv = query_quarantined("invoice", "d", instruction=e["body"])\n',
            "plan constant",
        ),
    ],
)
def test_reader_schema_and_instruction_must_be_plan_constants(source: str, message: str) -> None:
    result = run(source, reader=FakeReader())
    assert result.status == "error"
    assert message in (result.error or "")


def test_reader_is_required_for_query_quarantined() -> None:
    interpreter = Interpreter(FakeTable(), None)
    assert "query_quarantined" not in interpreter.known_functions


# ----------------------------------------------------------------------------- implicit flows


def test_branch_on_untrusted_data_raises_pc_for_assignments_and_calls() -> None:
    result = run(
        'e = fetch(id="1")\n'
        'name = "a"\n'
        'if e["n"] == 3:\n'
        '    name = "b"\n'
        '    send(to="me", body="hi")\n'
        'other = "c"\n',
    )
    assert result.status == "denied"
    assert result.denial is not None
    assert result.denial.argument == "to"
    assert result.denial.provenance_path
    assert result.calls[-1].outcome == "denied"
    assert result.env["name"].label.integrity is Integrity.UNTRUSTED


def test_skipped_branch_assignments_are_upgraded_to_the_guard_label() -> None:
    result = run(
        'e = fetch(id="1")\nname = "a"\nif e["n"] == 99:\n    name = "b"\nafter = "c"\n',
    )
    assert result.status == "completed"
    assert result.env["name"].label.integrity is Integrity.UNTRUSTED  # no-sensitive-upgrade
    assert result.env["after"].label.integrity is Integrity.USER  # pc restored after the if
    labels = [
        n
        for n in result.provenance.graph.nodes
        if "raised after control flow" in result.provenance.node(n).description
    ]
    assert labels


def test_else_branch_and_empty_loops_upgrade_too() -> None:
    result = run(
        'e = fetch(id="1")\n'
        'x = "a"\n'
        'if e["n"] == 3:\n'
        "    y = 1\n"
        "else:\n"
        '    x = "b"\n'
        'z = "c"\n'
        "for item in []:\n"
        '    z = "d"\n'
        "w = 0\n"
        'for item in e["items"]:\n'
        "    w = w + 1\n",
    )
    assert result.status == "completed"
    assert result.env["x"].label.integrity is Integrity.UNTRUSTED
    assert result.env["z"].label.integrity is Integrity.USER  # empty plan-made list: pc stays user
    assert result.env["w"].label.integrity is Integrity.UNTRUSTED
    assert result.env["item"].label.integrity is Integrity.UNTRUSTED


def test_loop_over_untrusted_collection_taints_side_effects() -> None:
    table = FakeTable()
    result = run(
        'e = fetch(id="1")\nfor item in e["items"]:\n    send(to="me", body=item)\n', table=table
    )
    assert result.status == "denied"
    assert table.calls[-1].pc.integrity is Integrity.UNTRUSTED


def test_constants_outside_control_flow_reach_sinks() -> None:
    table = FakeTable()
    result = run('send(to="me", body="hi")\nr = pay(amount=3)\n', table=table)
    assert result.status == "completed"
    assert [c.name for c in result.executed_calls] == ["send", "pay"]
    assert table.calls[0].arg_labels["to"].integrity is Integrity.USER
    assert result.env["r"].label.integrity is Integrity.TRUSTED_TOOL


def test_held_calls_stop_the_run_with_a_request_id() -> None:
    result = run('e = fetch(id="1")\nsend(to=e["body"], body="x")\n', table=FakeTable(hold=True))
    assert result.status == "held"
    assert result.held is not None
    assert result.held.request_id == "req-1"
    assert result.summary()["held"] == {"sink": "send"}


def test_initial_values_are_labeled_inputs() -> None:
    result = run('y = x + "!"\n', initial={"x": Labeled("v", UNTRUSTED)})
    assert label_of(result, "y").integrity is Integrity.UNTRUSTED
    assert result.provenance.node(0).kind == "user_request"


# ------------------------------------------------------------------------------------ limits


def test_step_loop_collection_and_value_limits() -> None:
    limits = Limits(max_steps=5)
    result = run("a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n", limits=limits)
    assert result.status == "limit"
    assert "steps" in (result.error or "")
    result = run("for i in range(20):\n    x = i\n", limits=Limits(max_loop_iterations=3))
    assert result.status == "limit"
    assert "loop iterations" in (result.error or "")
    result = run("x = range(10)\nfor i in x:\n    y = i\n", limits=Limits(max_collection_size=5))
    assert result.status == "limit"
    assert "collection size" in (result.error or "")
    result = run("x = [1, 2] + [3, 4]\n", limits=Limits(max_collection_size=3))
    assert result.status == "limit"
    result = run('x = "ab" + "cd"\n', limits=Limits(max_value_chars=3))
    assert result.status == "limit"
    assert "value size" in (result.error or "")
    result = run('x = f"{1}{2}{3}"\n', limits=Limits(max_value_chars=2))
    assert result.status == "limit"


def test_wall_clock_timeout_uses_the_injected_clock() -> None:
    ticks = iter([0.0, 0.0, 10.0, 10.0, 10.0, 10.0])
    result = run("a = 1\nb = 2\n", limits=Limits(timeout_seconds=1.0), clock=lambda: next(ticks))
    assert result.status == "limit"
    assert "wall-clock" in (result.error or "")


def test_recursion_and_overflow_become_limit_status() -> None:
    class Deep(FakeTable):
        def invoke(self, call: PendingCall, provenance: ProvenanceGraph) -> ToolOutcome:
            raise RecursionError("deep")

    result = run('x = fetch(id="1")\n', table=Deep())
    assert result.status == "limit"


# ------------------------------------------------------------------------------------ errors


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("y = x\n", "not defined"),
        ('e = fetch(id="1")\ny = e["missing"]\n', "missing dict key"),
        ('e = fetch(id="1")\ny = e[0]\n', "dict keys must be strings"),
        ('e = fetch(id="1")\ny = e["items"][5]\n', "out of range"),
        ('e = fetch(id="1")\ny = e["items"]["k"]\n', "list indexes must be integers"),
        ('e = fetch(id="1")\ny = e["items"][True]\n', "list indexes must be integers"),
        ('y = "s"[0]\n', "only lists and dicts"),
        ('y = "a" < 1\n', "ordering needs"),
        ("y = 1 in 2\n", "'in' needs"),
        ('y = 1 in "abc"\n', "needs a string"),
        ('y = "a" - "b"\n', "operator needs"),
        ('y = -"a"\n', "unary minus"),
        ('y = f"{[1]}"\n', "scalars"),
        ("for i in 3:\n    y = i\n", "lists only"),
        ("y = len(1, 2)\n", "argument"),
        ("y = len(x=1)\n", "positional arguments only"),
        ("y = fetch(1, 2)\n", "too many positional"),
        ('y = fetch("1", id="2")\n', "given twice"),
        ("y = 10 ** 1\n", "not allowed"),
        ("y = 1.0e308 * 10.0\n", "overflow"),
        ("y = 1000000000000 * 1000000000000\n", "too large"),
    ],
)
def test_runtime_errors_are_reported_without_values(source: str, message: str) -> None:
    """Some of these are caught at parse time and some at run time; both must be value-free."""
    try:
        result = run(source)
    except PlanError as exc:
        reported = str(exc)
    else:
        assert result.status == "error", result
        reported = result.error or ""
    assert message in reported
    assert "untrusted text" not in reported


def test_comparisons_of_mixed_types() -> None:
    result = run(
        'a = "x" == 1\nb = "b" > "a"\nc = 2.5 >= 2\nd = 1 <= 0\n'
        'e = "a" in ["a"]\nf = "k" not in {"k": 1}\ng = 1 != 2\n'
    )
    assert result.status == "completed"
    assert [to_plain(result.env[n]) for n in "abcdefg"] == [
        False,
        True,
        True,
        False,
        True,
        False,
        True,
    ]


def test_bool_ops_short_circuit_and_truthiness() -> None:
    result = run('a = [] or "x"\nb = "" and 1\nc = {"k": 1} and 2\nd = 0 or 0\n')
    assert [to_plain(result.env[n]) for n in "abcd"] == ["x", "", 2, 0]


def test_tool_name_collisions_with_builtins_are_refused() -> None:
    class Bad(FakeTable):
        def names(self) -> Collection[str]:
            return ("len",)

    with pytest.raises(ValueError, match="collide"):
        Interpreter(Bad())


def test_observer_and_rules_helpers() -> None:
    seen: list[dict[str, Any]] = []

    def observe(**kwargs: Any) -> None:
        seen.append(kwargs)

    interpreter = Interpreter(FakeTable(), observer=observe)
    plan = parse_plan(
        'x = 1\nsend(to="me", body="b")\n',
        known_functions=interpreter.known_functions,
        limits=Limits(),
    )
    interpreter.run(plan)
    assert [s["kind"] for s in seen] == ["assign", "expr"]
    assert seen[0]["assigned"] == "x"
    assert seen[0]["label"] is not None
    assert PropagationRules.all().without("assign_joins_pc").disabled == ("assign_joins_pc",)
    with pytest.raises(ValueError, match="unknown propagation rule"):
        PropagationRules.all().without("nope")
    assert len(PropagationRules.names()) == 15
    assert interpreter.rules == PropagationRules.all()
    assert interpreter.limits == Limits()


# ----------------------------------------------------------------------------- properties

LABELS = st.builds(
    Label,
    st.sampled_from(list(Integrity)),
    st.one_of(
        st.just(Readers()), st.frozensets(st.sampled_from(["me", "dana", "bob"])).map(Readers.of)
    ),
    st.frozensets(st.sampled_from(["s1", "s2", "s3"]), max_size=2),
)
# Expressions where every named input flows into the single result value, so the derived label
# must dominate the join of all of them.
EXPRESSIONS = [
    "s1 + s2",
    'f"{s1}-{s2}"',
    "lower(s1)",
    "n1 + n2",
    "n1 * n2",
    "n1 < n2",
    "s1 == s2",
    "len(s1)",
    "str(n1)",
    "lower(s1) + str(n1 < n2)",
    "not n1",
    "-n1",
    "s1 in s2",
    'join([s1, s2], n1 * "")',
    "abs(n1 - n2)",
    "replace(s1, s2, s1)",
    "s1 + str(n2)",
]
# Expressions that *select* one element out of a container. Labels are per element (CaMeL-style
# fine granularity), so the selected value carries its own label joined with the container's own
# label and the key's -- deliberately not its siblings'. The container as a whole still dominates
# every element, which is what reaches a sink when the whole container is passed.
SELECTIONS = ["[s1, s2][0]", '{"k": s1}["k"]', "sorted([n1, n2])[1]", "[[s1, s2]][0][1]"]


# One strategy for the whole starting environment: two labeled strings and two labeled numbers.
ENVIRONMENTS = st.builds(
    lambda s1, s2, n1, n2, l1, l2, l3, l4: {
        "s1": Labeled(s1, l1),
        "s2": Labeled(s2, l2),
        "n1": Labeled(n1, l3),
        "n2": Labeled(n2, l4),
    },
    st.text(max_size=5),
    st.text(max_size=5),
    st.integers(-9, 9),
    st.integers(-9, 9),
    LABELS,
    LABELS,
    LABELS,
    LABELS,
)


def _names(expression: str) -> set[str]:
    return {node.id for node in ast.walk(ast.parse(expression)) if isinstance(node, ast.Name)}


@settings(max_examples=150)
@given(st.sampled_from(EXPRESSIONS), ENVIRONMENTS)
def test_derived_label_is_at_least_the_join_of_its_inputs(
    expression: str, initial: dict[str, Labeled[Any]]
) -> None:
    result = run(f"r = {expression}\n", initial=initial)
    if result.status != "completed":
        assert result.status == "error"  # e.g. replace() with an empty search string
        return
    inputs = join_all(
        effective_label(initial[name]) for name in _names(expression) if name in initial
    )
    assert inputs <= label_of(result, "r")


@settings(max_examples=120)
@given(st.sampled_from(SELECTIONS), ENVIRONMENTS)
def test_selecting_an_element_keeps_that_element_label_and_the_container_dominates(
    expression: str, initial: dict[str, Labeled[Any]]
) -> None:
    """Indexing keeps per-element labels; the container still dominates every element."""
    container = expression.rsplit("[", 1)[0]
    whole = run(f"r = {container}\n", initial=initial)
    selected = run(f"r = {expression}\n", initial=initial)
    assert whole.status == "completed"
    assert selected.status == "completed"
    inputs = join_all(
        effective_label(initial[name]) for name in _names(expression) if name in initial
    )
    # The container carries every element's label ...
    assert inputs <= label_of(whole, "r")
    # ... and the selected element is dominated by it, while staying at least as high as the
    # element label it came from (checked concretely below).
    assert label_of(selected, "r") <= label_of(whole, "r")


def test_selection_carries_the_selected_element_label_not_its_siblings() -> None:
    secret = Label.untrusted("email:secret", readers=Readers.of({"me"}))
    public = Label.trusted_tool("tool:public")
    initial = {"s1": Labeled("a", public), "s2": Labeled("b", secret)}
    first = run("r = [s1, s2][0]\n", initial=initial)
    second = run("r = [s1, s2][1]\n", initial=initial)
    both = run("r = [s1, s2]\n", initial=initial)
    assert public <= label_of(first, "r")
    assert label_of(first, "r").integrity is Integrity.TRUSTED_TOOL  # sibling did not leak in
    assert secret <= label_of(second, "r")
    assert public.join(secret) <= label_of(both, "r")  # the whole list carries both


@settings(max_examples=60)
@given(LABELS, LABELS, st.integers(-3, 3), st.integers(-3, 3), st.booleans())
def test_implicit_flows_taint_variables_assigned_under_a_guard(
    l1: Label, l2: Label, n1: int, n2: int, else_branch: bool
) -> None:
    body = 'if n1 < n2:\n    r = "taken"\n' + ('else:\n    r = "other"\n' if else_branch else "")
    result = run('r = "before"\n' + body, initial={"n1": Labeled(n1, l1), "n2": Labeled(n2, l2)})
    assert result.status == "completed"
    assert l1.join(l2) <= result.env["r"].label


_PROTECTED = ("to", "amount")
# Every plan-written constant that may legitimately land in a protected sink argument.
_PLAN_CONSTANTS: frozenset[Plain] = frozenset({"me", 7})
_NONINTERFERENCE_PLANS = [
    'e = fetch(id="1")\nsend(to="me", body=e["body"])\n',
    'e = fetch(id="1")\nif e["n"] == 3:\n    send(to="me", body="x")\n',
    'e = fetch(id="1")\nname = "a"\nif e["body"] == "k":\n    name = "b"\n'
    'send(to=name, body="x")\n',
    'e = fetch(id="1")\nx = e["n"]\npay(amount=7)\nsend(to=e["body"], body="x")\n',
]


def _protected_arguments(result: ExecutionResult) -> dict[tuple[str, str], Plain]:
    """The protected arguments of every sink call that actually executed."""
    found: dict[tuple[str, str], Plain] = {}
    for call in result.executed_calls:
        if not call.is_sink:
            continue
        for key in _PROTECTED:
            if key in call.args:
                found[(call.name, key)] = call.args[key]
    return found


@settings(max_examples=60)
@given(st.text(max_size=40), st.text(max_size=40), st.integers(0, 5), st.integers(0, 5))
def test_noninterference_for_user_integrity_sink_arguments(
    a: str, b: str, na: int, nb: int
) -> None:
    """Varying untrusted inputs never changes the protected arguments a sink actually receives.

    Whether a sink runs at all *can* change -- a sink reached through untrusted control flow is
    denied instead, and the benchmark reports that as the utility cost. What the architecture
    guarantees is that any protected argument a sink does receive is a value the *plan* chose,
    identical no matter what the attacker wrote.
    """
    for plan in _NONINTERFERENCE_PLANS:
        seen: list[dict[tuple[str, str], Plain]] = []
        for body, n in ((a, na), (b, nb)):
            table = FakeTable()
            table.results["fetch"] = {"body": body, "n": n, "items": []}
            result = run(plan, table=table)
            assert result.status in {"completed", "denied"}
            arguments = _protected_arguments(result)
            assert all(value in _PLAN_CONSTANTS for value in arguments.values()), arguments
            seen.append(arguments)
        first, second = seen
        for key in set(first) & set(second):
            assert first[key] == second[key], (plan, key)


def test_plan_objects_expose_their_body() -> None:
    plan: Plan = parse_plan("x = 1\n", known_functions=set(), limits=Limits())
    assert len(plan.body) == 1
    assert plan.source == "x = 1\n"
    assert Label.user() >= BOTTOM
