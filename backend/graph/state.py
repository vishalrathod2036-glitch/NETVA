"""Attack graph state representation — frozen (hashable) for graph nodes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from backend.normalization.schema import NetworkAsset, PrivilegeLevel, Zone


@dataclass(frozen=True)
class AttackState:
    """A single state in the attack graph: (host, privilege level)."""
    host_id: str
    privilege: PrivilegeLevel

    @property
    def state_id(self) -> str:
        return f"{self.host_id}::{self.privilege.value}"

    @property
    def short_label(self) -> str:
        return f"{self.host_id} [{self.privilege.value}]"

    def __str__(self) -> str:
        return self.state_id


def is_absorbing(state: AttackState, asset: Optional[NetworkAsset]) -> bool:
    """Determine if a state is absorbing (crown jewel compromised).

    True when:
    - asset.criticality >= 0.8 AND privilege is ADMIN or ROOT
    - OR asset is in PROD zone with privilege >= SUDO
    """
    if asset is None:
        return False

    high_priv = state.privilege in (PrivilegeLevel.ADMIN, PrivilegeLevel.ROOT)
    if asset.criticality >= 0.8 and high_priv:
        return True

    if asset.zone == Zone.PROD and state.privilege.numeric >= PrivilegeLevel.SUDO.numeric:
        return True

    return False


def enumerate_states(asset: NetworkAsset) -> list[AttackState]:
    """Return meaningful AttackStates for an asset.

    - USER always present
    - ROOT if ssh_root_login_enabled, world_writable_files, or has_suid_binary
    - ADMIN if database or domain_controller type
    """
    states = [AttackState(host_id=asset.ip, privilege=PrivilegeLevel.USER)]

    if (asset.ssh_root_login_enabled
            or asset.has_world_writable_files
            or asset.has_suid_binary
            or asset.has_default_credentials
            or asset.has_command_injection):
        states.append(AttackState(host_id=asset.ip, privilege=PrivilegeLevel.ROOT))

    if asset.asset_type in ("database", "domain_controller"):
        states.append(AttackState(host_id=asset.ip, privilege=PrivilegeLevel.ADMIN))

    return states
