"""AMC solver — compute fundamental matrix N, absorption B, expected steps t.

Three inversion strategies (tried in order):
1. scipy LU decomposition (fast, stable)
2. numpy SVD pseudo-inverse (robust)
3. Neumann series (always converges for sub-stochastic Q)
"""
from __future__ import annotations

import logging

import numpy as np
from scipy import linalg as sp_linalg

from backend.amc.builder import MatrixBundle
from backend.amc.results import AMCResults

logger = logging.getLogger(__name__)


class AMCSolver:
    """Solve the AMC from a MatrixBundle."""

    def solve(self, bundle: MatrixBundle) -> AMCResults:
        """Compute N = (I - Q)^-1, B = N·R, t = N·1."""
        t = bundle.Q.shape[0]
        if t == 0:
            return AMCResults(
                transient_states=bundle.transient_states,
                absorbing_states=bundle.absorbing_states,
                solver_converged=True,
                solver_method="trivial",
            )

        I = np.eye(t, dtype=np.float64)
        IminusQ = I - bundle.Q

        # Condition number check
        cond = np.linalg.cond(IminusQ)
        if cond > 1e10:
            logger.warning(f"AMC: (I-Q) condition number = {cond:.2e} — high, may be unstable")

        # Try three inversion strategies
        N, method, converged = self._invert(IminusQ, I)

        # Post-process
        N = np.clip(N, 0.0, None)  # Clip to [0, ∞)

        # B = N · R
        B = N @ bundle.R
        B = np.clip(B, 0.0, 1.0)

        # Normalise B rows to sum ≤ 1
        for i in range(B.shape[0]):
            row_sum = B[i].sum()
            if row_sum > 1.0:
                B[i] /= row_sum

        # Expected steps: t_vec = N · ones
        t_vec = N @ np.ones(t)

        # Visit frequency: row sums of N
        visit_freq = N.sum(axis=1)

        return AMCResults(
            transient_states=bundle.transient_states,
            absorbing_states=bundle.absorbing_states,
            Q=bundle.Q,
            R=bundle.R,
            N=N,
            B=B,
            t_vec=t_vec,
            visit_freq=visit_freq,
            solver_converged=converged,
            solver_method=method,
            condition_number=float(cond),
        )

    def _invert(
        self, IminusQ: np.ndarray, I: np.ndarray
    ) -> tuple[np.ndarray, str, bool]:
        """Try three strategies to compute N = (I-Q)^-1."""

        # Strategy 1: LU decomposition via scipy.linalg.solve
        try:
            N = sp_linalg.solve(IminusQ, I)
            logger.info("AMC: Solved via LU decomposition (scipy)")
            return N, "lu_decomposition", True
        except (np.linalg.LinAlgError, sp_linalg.LinAlgError) as e:
            logger.warning(f"AMC: LU failed — {e}")

        # Strategy 2: SVD pseudo-inverse
        try:
            N = np.linalg.pinv(IminusQ)
            logger.info("AMC: Solved via SVD pseudo-inverse")
            return N, "svd_pseudoinverse", True
        except np.linalg.LinAlgError as e:
            logger.warning(f"AMC: SVD failed — {e}")

        # Strategy 3: Neumann series N = I + Q + Q² + Q³ + ...
        logger.info("AMC: Falling back to Neumann series")
        Q = I - IminusQ  # recover Q
        N = I.copy()
        Q_power = Q.copy()
        for k in range(1, 1000):
            N += Q_power
            norm = np.linalg.norm(Q_power)
            if norm < 1e-8:
                logger.info(f"AMC: Neumann converged at iteration {k}")
                return N, "neumann_series", True
            Q_power = Q_power @ Q

        logger.warning("AMC: Neumann series did not converge in 1000 iterations")
        return N, "neumann_series", False
