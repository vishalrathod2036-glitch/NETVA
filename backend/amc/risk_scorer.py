"""Risk scorer — composite risk per attack state using AMC metrics.

Risk(node) = α·Vuln + β·Reach + γ·VisitFreq + δ·Criticality + ε·PrivilegeImpact
"""
from __future__ import annotations

import os

import numpy as np
import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults


class RiskScorer:
    """Compute composite risk score per state from AMC analysis."""

    def __init__(self):
        self.alpha = float(os.environ.get("RISK_ALPHA", 0.25))
        self.beta = float(os.environ.get("RISK_BETA", 0.20))
        self.gamma = float(os.environ.get("RISK_GAMMA", 0.25))
        self.delta = float(os.environ.get("RISK_DELTA", 0.20))
        self.epsilon = float(os.environ.get("RISK_EPSILON", 0.10))

    def score(
        self,
        amc: AMCResults,
        G: nx.DiGraph,
        network: NormalizedNetwork,
    ) -> None:
        """Compute and write risk scores to amc.node_risk and G.nodes."""
        # Max visit freq for normalisation
        max_vf = 1.0
        if amc.visit_freq is not None and len(amc.visit_freq) > 0:
            max_vf = max(float(amc.visit_freq.max()), 1.0)

        for state_id in amc.transient_states:
            data = G.nodes.get(state_id, {})
            host_id = data.get("host_id", "")
            asset = network.assets.get(host_id)

            # Factor 1: Vuln score
            vuln = 0.0
            if asset:
                vuln = asset.max_cvss / 10.0
                if asset.has_exploit:
                    vuln += 0.15
                high_count = asset.critical_vuln_count + asset.high_vuln_count
                if high_count >= 3:
                    vuln += 0.10
            vuln = min(vuln, 1.0)

            # Factor 2: Reach — absorption prob + centrality
            absorb = amc.absorption_prob(state_id)
            cent = data.get("centrality_composite", 0.0)
            reach = 0.6 * absorb + 0.4 * cent

            # Factor 3: Visit frequency (normalised)
            vf = amc.visit_frequency(state_id) / max_vf

            # Factor 4: Criticality
            crit = asset.criticality if asset else 0.0

            # Factor 5: Privilege impact — max(dst_criticality × edge_weight) over out-edges
            priv_impact = 0.0
            for _, dst_id, edata in G.out_edges(state_id, data=True):
                dst_data = G.nodes.get(dst_id, {})
                dst_crit = dst_data.get("criticality", 0.0)
                edge_w = edata.get("weight", 0.0)
                priv_impact = max(priv_impact, dst_crit * edge_w)

            # Composite
            risk = (
                self.alpha * vuln
                + self.beta * reach
                + self.gamma * vf
                + self.delta * crit
                + self.epsilon * priv_impact
            )
            risk = min(max(risk, 0.0), 1.0)

            amc.node_risk[state_id] = risk
            if state_id in G:
                G.nodes[state_id]["risk_score"] = risk

        # Absorbing states always get risk_score = 1.0
        for state_id in amc.absorbing_states:
            amc.node_risk[state_id] = 1.0
            if state_id in G:
                G.nodes[state_id]["risk_score"] = 1.0
