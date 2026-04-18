"""Reachability matrix — port-level and privilege-level reachability between assets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.normalization.schema import (
    PrivilegeLevel, NetworkEdge, NormalizedNetwork,
)


@dataclass
class ReachabilityMatrix:
    """Encodes which assets can reach which, on which ports, at which privilege."""
    reach: dict[str, dict[str, list[int]]] = field(default_factory=dict)
    privilege_reach: dict[str, dict[str, PrivilegeLevel]] = field(default_factory=dict)

    def can_reach(self, src: str, dst: str) -> bool:
        return dst in self.reach.get(src, {})

    def allowed_ports(self, src: str, dst: str) -> list[int]:
        return self.reach.get(src, {}).get(dst, [])

    def privilege_to(self, src: str, dst: str) -> PrivilegeLevel:
        return self.privilege_reach.get(src, {}).get(dst, PrivilegeLevel.NONE)


def build_reachability(network: NormalizedNetwork) -> ReachabilityMatrix:
    """Build a ReachabilityMatrix from the NormalizedNetwork edges."""
    matrix = ReachabilityMatrix()

    for edge in network.edges:
        src, dst = edge.src_id, edge.dst_id

        # Port-level reachability
        if src not in matrix.reach:
            matrix.reach[src] = {}
        if dst not in matrix.reach[src]:
            matrix.reach[src][dst] = []

        if edge.ports:
            for p in edge.ports:
                if p not in matrix.reach[src][dst]:
                    matrix.reach[src][dst].append(p)
        # empty list = all ports allowed

        # Privilege-level reachability — keep the highest
        if src not in matrix.privilege_reach:
            matrix.privilege_reach[src] = {}
        current = matrix.privilege_reach[src].get(dst, PrivilegeLevel.NONE)
        if edge.privilege_level.numeric > current.numeric:
            matrix.privilege_reach[src][dst] = edge.privilege_level

    # Same-subnet reachability: hosts on same /24 can talk
    ips = list(network.assets.keys())
    for i, a in enumerate(ips):
        for b in ips[i + 1 :]:
            subnet_a = ".".join(a.split(".")[:3])
            subnet_b = ".".join(b.split(".")[:3])
            if subnet_a == subnet_b:
                matrix.reach.setdefault(a, {}).setdefault(b, [])
                matrix.reach.setdefault(b, {}).setdefault(a, [])

    return matrix
