"""Build NetworkX DiGraph from MulVALResult + NormalizedNetwork.

Three edge-type builders:
1. Remote exploit edges (internet/DMZ → service vuln → USER foothold)
2. Lateral movement edges (SSH trust / cred reuse)
3. Privilege escalation edges (USER → ROOT on same host)
"""
from __future__ import annotations

import networkx as nx

from backend.normalization.schema import (
    NormalizedNetwork, NetworkAsset, PrivilegeLevel, Zone,
)
from backend.graph.state import AttackState, is_absorbing, enumerate_states
from backend.graph.mulval_runner import MulVALResult


def build_nx_graph(
    mulval_result: MulVALResult,
    network: NormalizedNetwork,
    attacker_location: str = "internet",
) -> nx.DiGraph:
    """Build the full attack graph as a NetworkX DiGraph."""
    G = nx.DiGraph()

    # ── 1. Create nodes from asset states ───────────────────────────────────
    for ip, asset in network.assets.items():
        for state in enumerate_states(asset):
            absorbing = is_absorbing(state, asset)
            G.add_node(state.state_id, **{
                "state_id": state.state_id,
                "host_id": state.host_id,
                "privilege": state.privilege.value,
                "is_absorbing": absorbing,
                "is_entry": False,
                "asset_type": asset.asset_type,
                "criticality": asset.criticality,
                "risk_score": 0.0,
                "zone": asset.zone.value,
                "label": state.short_label,
                "ip": asset.ip,
                "hostname": asset.hostname,
                "open_ports": asset.open_ports,
                "vuln_count": asset.vuln_count,
                "max_cvss": asset.max_cvss,
                "has_exploit": asset.has_exploit,
            })

    # ── 2. Add entry node (internet) ────────────────────────────────────────
    G.add_node("internet", **{
        "state_id": "internet",
        "host_id": "internet",
        "privilege": "none",
        "is_absorbing": False,
        "is_entry": True,
        "asset_type": "external",
        "criticality": 0.0,
        "risk_score": 0.0,
        "zone": "internet",
        "label": "Internet (Attacker)",
        "ip": "0.0.0.0",
        "hostname": "internet",
        "open_ports": [],
        "vuln_count": 0,
        "max_cvss": 0.0,
        "has_exploit": False,
    })

    # ── 3. Remote exploit edges ─────────────────────────────────────────────
    _add_remote_exploit_edges(G, network, attacker_location)

    # ── 4. Lateral movement edges ───────────────────────────────────────────
    _add_lateral_movement_edges(G, network)

    # ── 5. Privilege escalation edges ───────────────────────────────────────
    _add_privilege_escalation_edges(G, network)

    # Mark entry nodes
    for node_id in G.nodes:
        if G.nodes[node_id].get("is_entry"):
            continue
        # Nodes directly reachable from internet are entry points
        if G.has_edge("internet", node_id):
            G.nodes[node_id]["is_entry"] = True

    return G


def _add_remote_exploit_edges(
    G: nx.DiGraph,
    network: NormalizedNetwork,
    attacker_location: str,
) -> None:
    """Internet/DMZ → service vuln → USER foothold."""
    for ip, asset in network.assets.items():
        if asset.zone not in (Zone.DMZ, Zone.INTERNAL):
            continue

        target_state = f"{ip}::user"
        if target_state not in G:
            continue

        for vuln in asset.vulns:
            if vuln.port and vuln.port > 0 and vuln.cvss >= 4.0:
                weight = vuln.cvss / 10.0
                if vuln.exploit_available:
                    weight += 0.2
                # Same subnet bonus
                if asset.zone == Zone.DMZ:
                    weight += 0.1
                weight = min(weight, 0.99)

                G.add_edge(attacker_location, target_state, **{
                    "weight": weight,
                    "vuln_id": vuln.vuln_id,
                    "cvss": vuln.cvss,
                    "mechanism": f"remote_exploit:{vuln.name}",
                    "requires_port": vuln.port,
                    "exploit_available": vuln.exploit_available,
                    "edge_type": "remote_exploit",
                })
                break  # One edge per asset from internet (highest CVSS first)


def _add_lateral_movement_edges(G: nx.DiGraph, network: NormalizedNetwork) -> None:
    """SSH trust / credential reuse edges between compromised hosts."""
    for edge in network.edges:
        if edge.edge_type != "iam":
            continue

        dst_priv = edge.privilege_level.value
        dst_state_id = f"{edge.dst_id}::{dst_priv}"

        # Auto-add destination node if missing (critical per spec)
        if dst_state_id not in G:
            dst_asset = network.assets.get(edge.dst_id)
            if dst_asset:
                absorbing = is_absorbing(
                    AttackState(edge.dst_id, edge.privilege_level), dst_asset
                )
                G.add_node(dst_state_id, **{
                    "state_id": dst_state_id,
                    "host_id": edge.dst_id,
                    "privilege": dst_priv,
                    "is_absorbing": absorbing,
                    "is_entry": False,
                    "asset_type": dst_asset.asset_type,
                    "criticality": dst_asset.criticality,
                    "risk_score": 0.0,
                    "zone": dst_asset.zone.value,
                    "label": f"{edge.dst_id} [{dst_priv}]",
                    "ip": dst_asset.ip,
                    "hostname": dst_asset.hostname,
                    "open_ports": dst_asset.open_ports,
                    "vuln_count": dst_asset.vuln_count,
                    "max_cvss": dst_asset.max_cvss,
                    "has_exploit": dst_asset.has_exploit,
                })

        weight = 0.90 if edge.link_type == "ssh_key" else 0.70

        # Add lateral edges from BOTH user and root states on the source
        for src_priv in ("user", "root"):
            src_state_id = f"{edge.src_id}::{src_priv}"
            if src_state_id not in G:
                continue
            if G.has_edge(src_state_id, dst_state_id):
                continue

            G.add_edge(src_state_id, dst_state_id, **{
                "weight": weight,
                "vuln_id": "",
                "cvss": 0.0,
                "mechanism": f"lateral:{edge.link_type}",
                "requires_port": 22,
                "exploit_available": False,
                "edge_type": "lateral_movement",
            })

    # Also add edges between same-subnet user states via network edges
    for edge in network.edges:
        if edge.edge_type != "network":
            continue
        src_state = f"{edge.src_id}::user"
        dst_state = f"{edge.dst_id}::user"
        if src_state in G and dst_state in G:
            if not G.has_edge(src_state, dst_state):
                # Check if dst has exploitable vulns
                dst_asset = network.assets.get(edge.dst_id)
                if dst_asset and dst_asset.max_cvss >= 4.0:
                    best_vuln = max(dst_asset.vulns, key=lambda v: v.cvss)
                    w = best_vuln.cvss / 10.0
                    if best_vuln.exploit_available:
                        w += 0.15
                    same_zone = (network.assets.get(edge.src_id, None) and
                                 network.assets.get(edge.dst_id, None) and
                                 network.assets[edge.src_id].zone == network.assets[edge.dst_id].zone)
                    if same_zone:
                        w += 0.10
                    w = min(w, 0.99)
                    G.add_edge(src_state, dst_state, **{
                        "weight": w,
                        "vuln_id": best_vuln.vuln_id,
                        "cvss": best_vuln.cvss,
                        "mechanism": f"network_exploit:{best_vuln.name}",
                        "requires_port": best_vuln.port,
                        "exploit_available": best_vuln.exploit_available,
                        "edge_type": "network_exploit",
                    })


def _add_privilege_escalation_edges(
    G: nx.DiGraph, network: NormalizedNetwork
) -> None:
    """USER → ROOT on same host via local vuln."""
    for ip, asset in network.assets.items():
        user_state = f"{ip}::user"
        root_state = f"{ip}::root"

        if user_state not in G or root_state not in G:
            continue

        # Find best local privesc vuln
        local_vulns = [v for v in asset.vulns if (v.port == 0 or "local" in v.name.lower()
                        or "suid" in v.name.lower() or "world-writable" in v.name.lower()
                        or "sudo" in v.name.lower()) and v.cvss > 0]

        if local_vulns:
            best = max(local_vulns, key=lambda v: v.cvss)
            weight = best.cvss / 10.0
            G.add_edge(user_state, root_state, **{
                "weight": min(weight, 0.99),
                "vuln_id": best.vuln_id,
                "cvss": best.cvss,
                "mechanism": f"privesc:{best.name}",
                "requires_port": 0,
                "exploit_available": best.exploit_available,
                "edge_type": "privilege_escalation",
            })

        # Also USER → ADMIN for databases
        admin_state = f"{ip}::admin"
        if user_state in G and admin_state in G:
            admin_vulns = [v for v in asset.vulns
                          if "default" in v.name.lower() or "mysql" in v.name.lower()]
            if admin_vulns:
                best = max(admin_vulns, key=lambda v: v.cvss)
                G.add_edge(user_state, admin_state, **{
                    "weight": min(best.cvss / 10.0, 0.99),
                    "vuln_id": best.vuln_id,
                    "cvss": best.cvss,
                    "mechanism": f"db_access:{best.name}",
                    "requires_port": best.port,
                    "exploit_available": best.exploit_available,
                    "edge_type": "privilege_escalation",
                })


def graph_to_dict(G: nx.DiGraph) -> dict:
    """Serialise graph to {nodes: [...], edges: [...]} for the API."""
    nodes = []
    for nid, data in G.nodes(data=True):
        nodes.append({**data})

    edges = []
    for src, dst, data in G.edges(data=True):
        edges.append({"source": src, "target": dst, **data})

    return {"nodes": nodes, "edges": edges}
