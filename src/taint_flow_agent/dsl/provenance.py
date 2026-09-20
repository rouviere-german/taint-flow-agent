"""Provenance DAG built while a plan runs.

Nodes are the values a plan creates (constants are not tracked individually): variables at each
assignment, loop variables, branch decisions, tool calls and their results, quarantined queries
and their outputs, and the arguments of sink calls. An edge ``a -> b`` means ``b`` was derived
from ``a``. A branch node is an ancestor of every value assigned inside the branch, so implicit
flows are visible in the graph, not only in the labels.

The graph carries label *summaries* (integrity, reader count, source ids) and structural
descriptions, never data values, so it can be shown to an approver and written to the audit log
without leaking the content being protected.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, final

import networkx as nx

from taint_flow_agent.ifc.labels import Label

__all__ = ["ProvenanceGraph", "ProvenanceNode"]


@final
@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    id: int
    kind: str
    description: str
    label: dict[str, Any]
    statement: int | None

    def render(self) -> str:
        where = f" @stmt {self.statement}" if self.statement is not None else ""
        return f"[{self.id}] {self.kind}: {self.description}{where} {self.label}"


@final
class ProvenanceGraph:
    _ORIGINS = frozenset({"tool_result", "reader_output", "user_request"})

    def __init__(self, *, max_nodes: int = 20_000) -> None:
        self._graph: nx.DiGraph[int] = nx.DiGraph()
        self._next = 0
        self._max_nodes = max_nodes

    @property
    def graph(self) -> nx.DiGraph[int]:
        return self._graph

    def __len__(self) -> int:
        return self._graph.number_of_nodes()

    def add(
        self,
        kind: str,
        description: str,
        label: Label,
        *,
        statement: int | None = None,
        depends_on: Iterable[int] = (),
    ) -> int:
        if self._graph.number_of_nodes() >= self._max_nodes:
            raise OverflowError("provenance graph is full")
        node_id = self._next
        self._next += 1
        self._graph.add_node(
            node_id,
            kind=kind,
            description=description,
            label=label.summary(),
            statement=statement,
        )
        for dependency in depends_on:
            if dependency != node_id and dependency in self._graph:
                self._graph.add_edge(dependency, node_id)
        return node_id

    def node(self, node_id: int) -> ProvenanceNode:
        data = self._graph.nodes[node_id]
        return ProvenanceNode(
            id=node_id,
            kind=str(data["kind"]),
            description=str(data["description"]),
            label=dict(data["label"]),
            statement=data["statement"],
        )

    def ancestors(self, node_id: int) -> set[int]:
        return set(nx.ancestors(self._graph, node_id))

    def depth(self, node_id: int) -> int:
        """Length of the longest derivation chain ending at ``node_id``."""
        sub = self._graph.subgraph(self.ancestors(node_id) | {node_id})
        return int(nx.dag_longest_path_length(sub))

    def longest_path(self, node_id: int) -> list[ProvenanceNode]:
        """The longest chain of derivations from an origin down to ``node_id``."""
        sub = self._graph.subgraph(self.ancestors(node_id) | {node_id})
        best: list[int] = [node_id]
        lengths: dict[int, list[int]] = {}
        for current in nx.topological_sort(sub):
            predecessors = list(sub.predecessors(current))
            if not predecessors:
                lengths[current] = [current]
                continue
            longest = max((lengths[p] for p in predecessors), key=len)
            lengths[current] = [*longest, current]
        best = lengths.get(node_id, best)
        return [self.node(item) for item in best]

    def origins(self, node_id: int) -> list[ProvenanceNode]:
        """Origin nodes (tool results, reader outputs, user request) the value depends on."""
        found = [self.node(a) for a in self.ancestors(node_id) | {node_id}]
        return sorted((n for n in found if n.kind in self._ORIGINS), key=lambda n: n.id)

    def render_path(self, node_id: int) -> list[str]:
        return [node.render() for node in self.longest_path(node_id)]

    def render_subgraph(self, node_id: int) -> str:
        """Human-readable dump of every ancestor of ``node_id`` for a declassification review."""
        nodes = sorted(self.ancestors(node_id) | {node_id})
        lines = []
        for item in nodes:
            node = self.node(item)
            parents = sorted(self._graph.predecessors(item))
            arrow = f" <- {parents}" if parents else ""
            lines.append(f"{node.render()}{arrow}")
        return "\n".join(lines)

    def to_json(self, node_id: int | None = None) -> dict[str, Any]:
        """JSON view (whole graph, or the ancestry of one node) for API responses."""
        selected = (
            sorted(self.ancestors(node_id) | {node_id})
            if node_id is not None
            else sorted(self._graph.nodes)
        )
        chosen = set(selected)
        return {
            "nodes": [dataclasses.asdict(self.node(item)) for item in selected],
            "edges": [[a, b] for a, b in self._graph.edges if a in chosen and b in chosen],
        }
