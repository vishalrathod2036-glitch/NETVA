"""Transition probability computation for AMC edges.

Six factor functions (each 0–1), combined via weighted sum.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx

from backend.normalization.schema import NormalizedNetwork, NetworkAsset, Zone


@dataclass
class TransitionWeights:
    """Configurable weights for the six transition factors."""
    w_vuln: float = 0.35
    w_reachability: float = 0.25
    w_privilege: float = 0.20
    w_misconfig: float = 0.12
    w_telemetry: float = 0.08


def _vuln_score(edge_data: dict, dst_data: dict) -> float:
    """CVSS/10 + exploit bonus."""
    cvss = edge_data.get("cvss", 0.0) / 10.0
    exploit = 0.15 if edge_data.get("exploit_available", False) else 0.0
    dst_cvss = dst_data.get("max_cvss", 0.0) / 10.0
    return min(max(cvss, dst_cvss) + exploit, 1.0)


def _reachability_score(edge_data: dict, src_data: dict, dst_data: dict) -> float:
    """Score based on edge type and zone crossing."""
    etype = edge_data.get("edge_type", "")
    if "lateral" in etype:
        return 0.85
    src_zone = src_data.get("zone", "unknown")
    dst_zone = dst_data.get("zone", "unknown")
    if src_zone == dst_zone:
        return 0.75
    if src_zone == "dmz" and dst_zone == "internal":
        return 0.55
    if src_zone == "internal" and dst_zone == "prod":
        return 0.50
    if src_zone == "internet":
        return 0.65
    return 0.40


def _privilege_score(edge_data: dict, src_data: dict) -> float:
    """Score based on attacker's current privilege level."""
    priv = src_data.get("privilege", "none")
    return {"none": 0.1, "user": 0.4, "sudo": 0.65, "admin": 0.80, "root": 0.95}.get(priv, 0.1)


def _misconfig_score(dst_data: dict, asset: Optional[NetworkAsset]) -> float:
    """Sum of misconfiguration flags."""
    if asset is None:
        return 0.0
    score = 0.0
    if asset.has_default_credentials:
        score += 0.30
    if asset.has_weak_ssh_password:
        score += 0.25
    if asset.ssh_root_login_enabled:
        score += 0.20
    if asset.has_world_writable_files:
        score += 0.15
    if asset.has_exposed_backup_files:
        score += 0.10
    if asset.has_command_injection:
        score += 0.25
    if asset.has_suid_binary:
        score += 0.15
    return min(score, 1.0)


def _telemetry_score(dst_data: dict) -> float:
    """1 - detection probability (lower detection = easier for attacker)."""
    zone = dst_data.get("zone", "unknown")
    detection = {"prod": 0.70, "internal": 0.45, "dmz": 0.25, "internet": 0.05}.get(zone, 0.30)
    return 1.0 - detection


def _centrality_score(dst_data: dict) -> float:
    """Use the composite centrality from graph analysis."""
    return dst_data.get("centrality_composite", 0.0)


def compute_edge_score(
    edge_data: dict,
    src_data: dict,
    dst_data: dict,
    dst_asset: Optional[NetworkAsset],
    network: NormalizedNetwork,
    weights: TransitionWeights,
) -> float:
    """Weighted sum of all six factors for one edge."""
    v = _vuln_score(edge_data, dst_data)
    r = _reachability_score(edge_data, src_data, dst_data)
    p = _privilege_score(edge_data, src_data)
    m = _misconfig_score(dst_data, dst_asset)
    t = _telemetry_score(dst_data)
    c = _centrality_score(dst_data)

    score = (
        weights.w_vuln * v
        + weights.w_reachability * r
        + weights.w_privilege * p
        + weights.w_misconfig * m
        + weights.w_telemetry * t
    )
    # Centrality is a bonus — doesn't replace the main weight sum
    score = score * 0.85 + c * 0.15
    return min(max(score, 0.01), 0.99)


def compute_transition_matrix_row(
    G: nx.DiGraph,
    state_id: str,
    network: NormalizedNetwork,
    weights: TransitionWeights,
    self_loop_mass: float = 0.05,
) -> dict[str, float]:
    """Compute normalised transition probabilities for one state.

    Returns dict of {dst_state_id: probability}, summing to (1 - self_loop_mass).
    """
    if state_id not in G:
        return {}

    src_data = G.nodes[state_id]
    successors = list(G.successors(state_id))

    if not successors:
        return {}

    raw_scores: dict[str, float] = {}
    for dst_id in successors:
        edge_data = G.edges[state_id, dst_id]
        dst_data = G.nodes[dst_id]
        dst_ip = dst_data.get("host_id", "")
        dst_asset = network.assets.get(dst_ip)

        score = compute_edge_score(edge_data, src_data, dst_data, dst_asset, network, weights)
        raw_scores[dst_id] = score

    # Normalise to sum to (1 - self_loop_mass)
    total = sum(raw_scores.values())
    if total <= 0:
        return {}

    target_sum = 1.0 - self_loop_mass
    return {dst: (score / total) * target_sum for dst, score in raw_scores.items()}
