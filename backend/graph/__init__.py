"""Attack graph module — single entry point.

Usage:
    G, paths = build_attack_graph(network, attacker_location="internet")
"""
from __future__ import annotations

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.graph.mulval_generator import generate_mulval_facts
from backend.graph.mulval_runner import run_mulval
from backend.graph.attack_graph import build_nx_graph, graph_to_dict
from backend.graph.centrality import compute_centrality, get_critical_paths


def build_attack_graph(
    network: NormalizedNetwork,
    attacker_location: str = "internet",
    top_paths: int = 5,
) -> tuple[nx.DiGraph, list[dict]]:
    """Full pipeline: generate facts → run MulVAL → build graph → centrality → paths."""

    # 1. Generate MulVAL Prolog facts
    facts = generate_mulval_facts(network, attacker_location)

    # 2. Run MulVAL (Docker or fallback)
    mulval_result = run_mulval(facts)

    # 3. Build NetworkX graph
    G = build_nx_graph(mulval_result, network, attacker_location)

    # 4. Compute centrality metrics
    compute_centrality(G)

    # 5. Get critical paths
    paths = get_critical_paths(G, top_n=top_paths)

    return G, paths


__all__ = [
    "build_attack_graph",
    "graph_to_dict",
    "generate_mulval_facts",
    "run_mulval",
    "compute_centrality",
    "get_critical_paths",
]
