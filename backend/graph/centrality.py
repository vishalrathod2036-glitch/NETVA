"""Graph centrality metrics — betweenness, eigenvector, closeness, degree."""
from __future__ import annotations

import networkx as nx
from typing import Optional


def compute_centrality(G: nx.DiGraph) -> None:
    """Compute five centrality metrics and write as node attributes."""
    n = G.number_of_nodes()
    if n < 2:
        for nid in G.nodes:
            for metric in ("centrality_betweenness", "centrality_eigenvector",
                          "centrality_closeness", "centrality_in_degree",
                          "centrality_out_degree", "centrality_composite"):
                G.nodes[nid][metric] = 0.0
        return

    # Inverted weights for distance-based metrics
    inv_weight = {}
    for u, v, data in G.edges(data=True):
        w = data.get("weight", 0.5)
        inv_weight[(u, v)] = max(1.0 - w, 0.01)

    nx.set_edge_attributes(G, {k: v for k, v in inv_weight.items()}, "inv_weight")

    # Betweenness (inverted weights = distances)
    try:
        bw = nx.betweenness_centrality(G, weight="inv_weight", normalized=True)
    except Exception:
        bw = {n: 0.0 for n in G.nodes}

    # Eigenvector (power iteration, fallback to degree)
    try:
        ev = nx.eigenvector_centrality(G, max_iter=500, weight="weight")
    except (nx.NetworkXError, nx.PowerIterationFailedConvergence):
        try:
            ev = nx.degree_centrality(G)
        except Exception:
            ev = {n: 0.0 for n in G.nodes}

    # Closeness (inverted weights)
    try:
        cl = nx.closeness_centrality(G, distance="inv_weight")
    except Exception:
        cl = {n: 0.0 for n in G.nodes}

    # Degree centrality
    try:
        in_deg = nx.in_degree_centrality(G)
        out_deg = nx.out_degree_centrality(G)
    except Exception:
        in_deg = {n: 0.0 for n in G.nodes}
        out_deg = {n: 0.0 for n in G.nodes}

    # Composite
    for nid in G.nodes:
        b = bw.get(nid, 0.0)
        e = ev.get(nid, 0.0)
        c = cl.get(nid, 0.0)
        i = in_deg.get(nid, 0.0)
        o = out_deg.get(nid, 0.0)

        G.nodes[nid]["centrality_betweenness"] = b
        G.nodes[nid]["centrality_eigenvector"] = e
        G.nodes[nid]["centrality_closeness"] = c
        G.nodes[nid]["centrality_in_degree"] = i
        G.nodes[nid]["centrality_out_degree"] = o
        G.nodes[nid]["centrality_composite"] = (
            b * 0.40 + e * 0.25 + c * 0.20 + i * 0.10 + o * 0.05
        )


def get_critical_paths(
    G: nx.DiGraph,
    top_n: int = 5,
) -> list[dict]:
    """Find shortest paths from entry nodes to absorbing nodes.

    Returns sorted by path probability (product of edge weights).
    """
    entry_nodes = [n for n, d in G.nodes(data=True) if d.get("is_entry")]
    absorbing_nodes = [n for n, d in G.nodes(data=True) if d.get("is_absorbing")]

    if not entry_nodes or not absorbing_nodes:
        return []

    # Build inverted weight graph for shortest path
    paths: list[dict] = []

    for entry in entry_nodes:
        for target in absorbing_nodes:
            try:
                path = nx.shortest_path(G, entry, target, weight="inv_weight")
                # Compute path probability = product of edge weights
                prob = 1.0
                edges_info = []
                for i in range(len(path) - 1):
                    edge_data = G.edges[path[i], path[i + 1]]
                    w = edge_data.get("weight", 0.5)
                    prob *= w
                    edges_info.append({
                        "from": path[i],
                        "to": path[i + 1],
                        "weight": w,
                        "mechanism": edge_data.get("mechanism", ""),
                        "vuln_id": edge_data.get("vuln_id", ""),
                    })

                paths.append({
                    "path": path,
                    "probability": round(prob, 4),
                    "length": len(path) - 1,
                    "entry": entry,
                    "target": target,
                    "edges": edges_info,
                })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    # Sort by probability descending
    paths.sort(key=lambda p: p["probability"], reverse=True)
    return paths[:top_n]
