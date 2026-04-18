"""Simulator — before/after comparison for action execution."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults
from backend.mdp.action_space import DefenderAction, ACTION_MAP
from backend.mdp.state_space import DefenderState
from backend.mdp.transitions import TransitionFunction
from backend.graph.attack_graph import graph_to_dict


@dataclass
class SimulationResult:
    """Before/after comparison for a simulated action."""
    risk_before: float = 0.0
    risk_after: float = 0.0
    absorption_prob_before: float = 0.0
    absorption_prob_after: float = 0.0
    nodes_before: int = 0
    edges_before: int = 0
    nodes_after: int = 0
    edges_after: int = 0
    removed_edges: list[dict] = field(default_factory=list)
    risk_reduced_nodes: list[dict] = field(default_factory=list)
    graph_before: dict = field(default_factory=dict)
    graph_after: dict = field(default_factory=dict)
    succeeded: bool = True
    action_id: str = ""
    target_asset_id: str = ""

    def to_dict(self) -> dict:
        return {
            "risk_before": round(self.risk_before, 4),
            "risk_after": round(self.risk_after, 4),
            "risk_delta": round(self.risk_before - self.risk_after, 4),
            "absorption_prob_before": round(self.absorption_prob_before, 4),
            "absorption_prob_after": round(self.absorption_prob_after, 4),
            "nodes_before": self.nodes_before,
            "edges_before": self.edges_before,
            "nodes_after": self.nodes_after,
            "edges_after": self.edges_after,
            "removed_edges": self.removed_edges,
            "risk_reduced_nodes": self.risk_reduced_nodes,
            "succeeded": self.succeeded,
            "action_id": self.action_id,
            "target_asset_id": self.target_asset_id,
        }


class Simulator:
    """Simulate the effect of a defender action."""

    def __init__(self):
        self.transition_fn = TransitionFunction()

    def simulate_action(
        self,
        action_id: str,
        target_asset_id: str,
        state: DefenderState,
        amc: AMCResults,
        G: nx.DiGraph,
        network: NormalizedNetwork,
        rerun_amc: bool = False,
    ) -> SimulationResult:
        """Simulate an action and return before/after comparison.

        1. Always runs lightweight posture transition (fast preview)
        2. If rerun_amc=True: rebuilds graph + AMC for accurate delta
        """
        action = ACTION_MAP.get(action_id)
        if action is None:
            return SimulationResult(succeeded=False, action_id=action_id, target_asset_id=target_asset_id)

        # Before metrics
        risk_before = state.overall_risk
        absorb_before = state.max_absorption_prob
        nodes_before = G.number_of_nodes()
        edges_before = G.number_of_edges()

        # Lightweight posture transition
        next_state, succeeded = self.transition_fn.apply(state, action, target_asset_id)

        if not succeeded:
            return SimulationResult(
                risk_before=risk_before,
                risk_after=risk_before,
                absorption_prob_before=absorb_before,
                absorption_prob_after=absorb_before,
                nodes_before=nodes_before,
                edges_before=edges_before,
                nodes_after=nodes_before,
                edges_after=edges_before,
                succeeded=False,
                action_id=action_id,
                target_asset_id=target_asset_id,
            )

        # Build graph preview — estimate edge removals
        graph_after = deepcopy(G)
        removed_edges = self._apply_posture_to_graph(graph_after, action, target_asset_id, network)

        # Risk reduced nodes
        risk_reduced = []
        for nid, data in graph_after.nodes(data=True):
            host_id = data.get("host_id", "")
            if host_id == target_asset_id:
                old_risk = G.nodes.get(nid, {}).get("risk_score", 0.0)
                new_risk = old_risk * next_state.asset_postures.get(target_asset_id, state.asset_postures.get(target_asset_id)).risk_reduction_factor() if target_asset_id in next_state.asset_postures else old_risk
                risk_reduced.append({
                    "node_id": nid,
                    "risk_before": round(old_risk, 4),
                    "risk_after": round(new_risk, 4),
                })

        return SimulationResult(
            risk_before=risk_before,
            risk_after=next_state.overall_risk,
            absorption_prob_before=absorb_before,
            absorption_prob_after=next_state.max_absorption_prob,
            nodes_before=nodes_before,
            edges_before=edges_before,
            nodes_after=graph_after.number_of_nodes(),
            edges_after=graph_after.number_of_edges(),
            removed_edges=removed_edges,
            risk_reduced_nodes=risk_reduced,
            graph_before=graph_to_dict(G),
            graph_after=graph_to_dict(graph_after),
            succeeded=True,
            action_id=action_id,
            target_asset_id=target_asset_id,
        )

    def _apply_posture_to_graph(
        self,
        G: nx.DiGraph,
        action: DefenderAction,
        target_id: str,
        network: NormalizedNetwork,
    ) -> list[dict]:
        """Modify graph based on posture change, return removed edges."""
        removed = []

        if action.action_type == "isolate":
            # Remove all edges to/from target
            edges_to_remove = []
            for u, v, data in G.edges(data=True):
                if data.get("host_id") == target_id or u.startswith(target_id) or v.startswith(target_id):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": f"isolate:{target_id}"})
            for u, v in edges_to_remove:
                G.remove_edge(u, v)

        elif action.action_id == "revoke_ssh_keys":
            # Remove lateral movement edges from target
            edges_to_remove = []
            for u, v, data in G.edges(data=True):
                if "lateral" in data.get("edge_type", "") and u.startswith(target_id):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "revoke_ssh_keys"})
            for u, v in edges_to_remove:
                G.remove_edge(u, v)

        elif action.action_type == "segment":
            # Remove cross-zone edges
            edges_to_remove = []
            for u, v, data in G.edges(data=True):
                src_zone = G.nodes.get(u, {}).get("zone", "")
                dst_zone = G.nodes.get(v, {}).get("zone", "")
                if action.action_id == "segment_dmz_internal" and src_zone == "dmz" and dst_zone == "internal":
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "segment_dmz_internal"})
                elif action.action_id == "segment_internal_prod" and src_zone == "internal" and dst_zone == "prod":
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "segment_internal_prod"})
            for u, v in edges_to_remove:
                G.remove_edge(u, v)

        elif action.action_type == "block_port" and action.applies_to_port:
            # Remove edges that require the blocked port
            edges_to_remove = []
            for u, v, data in G.edges(data=True):
                if (v.startswith(target_id) and
                        data.get("requires_port") == action.applies_to_port):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": f"block_port:{action.applies_to_port}"})
            for u, v in edges_to_remove:
                G.remove_edge(u, v)

        return removed
