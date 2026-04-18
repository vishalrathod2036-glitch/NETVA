"""AMCResults — single output object for the Absorbing Markov Chain analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np


@dataclass
class AMCResults:
    """Complete output of the AMC analysis."""
    transient_states: list[str] = field(default_factory=list)  # ordered state_ids
    absorbing_states: list[str] = field(default_factory=list)
    Q: Optional[np.ndarray] = None   # (t, t) sub-stochastic
    R: Optional[np.ndarray] = None   # (t, a)
    N: Optional[np.ndarray] = None   # (t, t) fundamental matrix
    B: Optional[np.ndarray] = None   # (t, a) absorption probabilities
    t_vec: Optional[np.ndarray] = None  # (t,) expected steps
    visit_freq: Optional[np.ndarray] = None  # (t,) row sums of N
    node_risk: dict[str, float] = field(default_factory=dict)
    solver_converged: bool = True
    solver_method: str = ""
    condition_number: float = 0.0

    # ── Convenience methods ─────────────────────────────────────────────────

    @property
    def num_transient(self) -> int:
        return len(self.transient_states)

    @property
    def num_absorbing(self) -> int:
        return len(self.absorbing_states)

    def _t_index(self, state_id: str) -> Optional[int]:
        try:
            return self.transient_states.index(state_id)
        except ValueError:
            return None

    def _a_index(self, state_id: str) -> Optional[int]:
        try:
            return self.absorbing_states.index(state_id)
        except ValueError:
            return None

    def absorption_prob(self, state_id: str) -> float:
        """Total absorption probability from a transient state."""
        i = self._t_index(state_id)
        if i is None or self.B is None:
            return 0.0
        return float(self.B[i].sum())

    def absorption_prob_to(self, state_id: str, absorbing_id: str) -> float:
        """Absorption probability from state_id to a specific absorbing state."""
        i = self._t_index(state_id)
        j = self._a_index(absorbing_id)
        if i is None or j is None or self.B is None:
            return 0.0
        return float(self.B[i, j])

    def expected_steps(self, state_id: str) -> float:
        """Expected steps from state_id to absorption."""
        i = self._t_index(state_id)
        if i is None or self.t_vec is None:
            return float("inf")
        return float(self.t_vec[i])

    def visit_frequency(self, state_id: str) -> float:
        """Expected visit frequency for a transient state."""
        i = self._t_index(state_id)
        if i is None or self.visit_freq is None:
            return 0.0
        return float(self.visit_freq[i])

    def to_dict(self) -> dict:
        """JSON-serialisable dict."""
        return {
            "transient_states": self.transient_states,
            "absorbing_states": self.absorbing_states,
            "num_transient": self.num_transient,
            "num_absorbing": self.num_absorbing,
            "Q": self.Q.tolist() if self.Q is not None else [],
            "R": self.R.tolist() if self.R is not None else [],
            "N": self.N.tolist() if self.N is not None else [],
            "B": self.B.tolist() if self.B is not None else [],
            "t_vec": self.t_vec.tolist() if self.t_vec is not None else [],
            "visit_freq": self.visit_freq.tolist() if self.visit_freq is not None else [],
            "node_risk": self.node_risk,
            "solver_converged": self.solver_converged,
            "solver_method": self.solver_method,
            "condition_number": self.condition_number,
            "state_metrics": [
                {
                    "state_id": sid,
                    "absorption_prob": self.absorption_prob(sid),
                    "expected_steps": self.expected_steps(sid),
                    "visit_frequency": self.visit_frequency(sid),
                    "risk_score": self.node_risk.get(sid, 0.0),
                }
                for sid in self.transient_states
            ],
        }
