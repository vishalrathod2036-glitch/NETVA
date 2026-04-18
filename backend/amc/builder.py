"""AMC matrix builder — partition nodes, fill Q and R matrices."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.transition_probs import (
    TransitionWeights, compute_transition_matrix_row,
)


@dataclass
class MatrixBundle:
    """Raw matrices before solving."""
    Q: np.ndarray                   # (t, t) transient-to-transient
    R: np.ndarray                   # (t, a) transient-to-absorbing
    transient_states: list[str] = field(default_factory=list)
    absorbing_states: list[str] = field(default_factory=list)


class MatrixBuilder:
    """Build the AMC transition sub-matrices Q and R from the attack graph."""

    def build(
        self,
        G: nx.DiGraph,
        network: NormalizedNetwork,
        weights: TransitionWeights | None = None,
    ) -> MatrixBundle:
        """Partition nodes and fill matrices."""
        if weights is None:
            weights = TransitionWeights()

        # 1. Partition nodes into transient / absorbing
        transient: list[str] = []
        absorbing: list[str] = []

        for nid, data in G.nodes(data=True):
            if data.get("is_absorbing", False):
                absorbing.append(nid)
            else:
                transient.append(nid)

        # 2. If no absorbing states, designate highest-criticality node
        if not absorbing:
            best = max(G.nodes(data=True), key=lambda nd: nd[1].get("criticality", 0))
            absorbing.append(best[0])
            if best[0] in transient:
                transient.remove(best[0])
            G.nodes[best[0]]["is_absorbing"] = True

        t = len(transient)
        a = len(absorbing)

        t_idx = {s: i for i, s in enumerate(transient)}
        a_idx = {s: i for i, s in enumerate(absorbing)}

        Q = np.zeros((t, t), dtype=np.float64)
        R = np.zeros((t, a), dtype=np.float64)

        # 3. Fill Q and R using transition probabilities
        for state_id in transient:
            i = t_idx[state_id]
            row = compute_transition_matrix_row(G, state_id, network, weights)

            for dst_id, prob in row.items():
                if dst_id in t_idx:
                    Q[i, t_idx[dst_id]] = prob
                elif dst_id in a_idx:
                    R[i, a_idx[dst_id]] = prob

        # 4. Validate: rows of [Q|R] must not exceed 1.0
        for i in range(t):
            row_sum = Q[i].sum() + R[i].sum()
            if row_sum > 1.0:
                # Clamp — normalise Q and R proportionally
                scale = 1.0 / row_sum
                Q[i] *= scale
                R[i] *= scale

        return MatrixBundle(
            Q=Q,
            R=R,
            transient_states=transient,
            absorbing_states=absorbing,
        )
