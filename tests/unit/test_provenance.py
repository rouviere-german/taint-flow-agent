from __future__ import annotations

import pytest

from taint_flow_agent.dsl.provenance import ProvenanceGraph
from taint_flow_agent.ifc.labels import Label

pytestmark = pytest.mark.unit


def build() -> tuple[ProvenanceGraph, int]:
    graph = ProvenanceGraph()
    email = graph.add(
        "tool_result", "result of read_email", Label.untrusted("email:1"), statement=0
    )
    query = graph.add(
        "reader_query", "query_quarantined(invoice)", Label.untrusted("email:1"), depends_on=[email]
    )
    output = graph.add(
        "reader_output", "reader#1", Label.untrusted("email:1", "reader#1"), depends_on=[query]
    )
    variable = graph.add(
        "variable", "inv", Label.untrusted("email:1", "reader#1"), statement=2, depends_on=[output]
    )
    constant = graph.add("variable", "ref", Label.user("plan"), statement=3)
    argument = graph.add(
        "sink_argument",
        "pay_invoice.recipient",
        Label.untrusted("email:1", "reader#1"),
        statement=4,
        depends_on=[variable, constant],
    )
    return graph, argument


def test_paths_depth_origins_and_rendering() -> None:
    graph, argument = build()
    assert len(graph) == 6
    assert graph.depth(argument) == 4
    path = graph.longest_path(argument)
    assert [node.kind for node in path] == [
        "tool_result",
        "reader_query",
        "reader_output",
        "variable",
        "sink_argument",
    ]
    assert [node.kind for node in graph.origins(argument)] == ["tool_result", "reader_output"]
    rendered = graph.render_path(argument)
    assert rendered[0].startswith("[0] tool_result: result of read_email @stmt 0")
    assert "'integrity': 'untrusted'" in rendered[-1]
    subgraph = graph.render_subgraph(argument)
    assert "<- [0]" in subgraph
    assert "pay_invoice.recipient" in subgraph
    exported = graph.to_json(argument)
    assert {n["id"] for n in exported["nodes"]} == graph.ancestors(argument) | {argument}
    assert [4, 5] in exported["edges"]
    assert [0, 1] in exported["edges"]
    assert len(graph.to_json()["nodes"]) == 6


def test_graph_never_holds_data_values_and_ignores_bad_edges() -> None:
    graph = ProvenanceGraph()
    node = graph.add("variable", "x", Label.user(), depends_on=[42, -1])
    assert graph.ancestors(node) == set()
    assert graph.node(node).label == {"integrity": "user", "readers": "public", "sources": []}
    assert graph.longest_path(node) == [graph.node(node)]


def test_graph_size_is_bounded() -> None:
    graph = ProvenanceGraph(max_nodes=2)
    graph.add("a", "a", Label.user())
    graph.add("b", "b", Label.user())
    with pytest.raises(OverflowError):
        graph.add("c", "c", Label.user())
