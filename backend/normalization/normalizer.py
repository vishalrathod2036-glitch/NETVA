"""Normalizer — merges all parser outputs into a unified NormalizedNetwork."""
from __future__ import annotations

from typing import Optional, Any

from backend.ingestion.models import (
    RawNessusScan, RawNmapScan, RawIaCScan, RawACLConfig, RawIAMData,
)
from backend.normalization.schema import (
    Severity, Zone, PrivilegeLevel,
    Vulnerability, NetworkEdge, NetworkAsset, NormalizedNetwork,
)


class Normalizer:
    """Merge raw scan data into a single NormalizedNetwork."""

    # ── Zone inference by subnet ────────────────────────────────────────────
    SUBNET_ZONE_MAP = {
        "10.10.": Zone.DMZ,
        "10.20.": Zone.INTERNAL,
        "10.30.": Zone.PROD,
        "192.168.": Zone.INTERNAL,
        "172.16.": Zone.INTERNAL,
    }

    # ── Criticality by asset type ───────────────────────────────────────────
    TYPE_CRITICALITY = {
        "database": 0.95,
        "domain_controller": 0.95,
        "firewall": 0.85,
        "appserver": 0.75,
        "webserver": 0.60,
        "workstation": 0.40,
        "server": 0.50,
    }

    def normalize(
        self,
        nessus: Optional[RawNessusScan] = None,
        nmap: Optional[RawNmapScan] = None,
        iac: Optional[RawIaCScan] = None,
        acl: Optional[RawACLConfig] = None,
        iam: Optional[RawIAMData] = None,
    ) -> NormalizedNetwork:
        """Run the full normalisation pipeline."""
        network = NormalizedNetwork()

        # 1. Build assets from Nmap (ports/services)
        if nmap:
            self._merge_nmap(network, nmap)

        # 2. Merge Nessus vulns into existing assets (same IP = same asset)
        if nessus:
            self._merge_nessus(network, nessus)

        # 3. Infer zones, types, criticality
        for asset in network.assets.values():
            asset.zone = self._infer_zone(asset.ip)
            asset.asset_type = self._infer_type(asset)
            asset.criticality = self.TYPE_CRITICALITY.get(asset.asset_type, 0.50)
            self._set_flags(asset)

        # 4. Build edges from ACL rules
        if acl:
            self._build_acl_edges(network, acl)

        # 5. Build edges from IaC topology
        if iac:
            self._build_iac_edges(network, iac)

        # 6. Build edges from IAM trust
        if iam:
            self._build_iam_edges(network, iam)

        # 7. Add same-subnet reachability edges
        self._add_subnet_edges(network)

        return network

    # ── Nmap merge ──────────────────────────────────────────────────────────

    def _merge_nmap(self, network: NormalizedNetwork, nmap: RawNmapScan) -> None:
        for host in nmap.hosts:
            ip = host.ip
            if not ip:
                continue
            asset = network.assets.get(ip, NetworkAsset(asset_id=ip, ip=ip))
            asset.hostname = asset.hostname or host.hostname
            asset.os = asset.os or host.os
            for port in host.ports:
                if port.port not in asset.open_ports:
                    asset.open_ports.append(port.port)
                asset.services[port.port] = port.service or port.version
            network.assets[ip] = asset

    # ── Nessus merge ────────────────────────────────────────────────────────

    def _merge_nessus(self, network: NormalizedNetwork, nessus: RawNessusScan) -> None:
        for host in nessus.hosts:
            ip = host.ip
            if not ip:
                continue
            asset = network.assets.get(ip, NetworkAsset(asset_id=ip, ip=ip))
            asset.hostname = asset.hostname or host.hostname
            asset.os = asset.os or host.os

            for rv in host.vulns:
                cvss = max(rv.cvss3_base, rv.cvss_base)
                severity = self._cvss_to_severity(cvss) if cvss > 0 else self._nessus_severity(rv.severity)
                vuln = Vulnerability(
                    vuln_id=rv.cve or f"PLUGIN-{rv.plugin_id}",
                    cve=rv.cve,
                    name=rv.plugin_name,
                    description=rv.description,
                    solution=rv.solution,
                    severity=severity,
                    cvss=max(rv.cvss_base, rv.cvss3_base),
                    cvss3=rv.cvss3_base,
                    exploit_available=rv.exploit_available,
                    port=rv.port,
                    protocol=rv.protocol,
                    service=rv.service,
                    plugin_id=rv.plugin_id,
                    plugin_output=rv.plugin_output,
                )
                asset.vulns.append(vuln)

                # Track open port from vuln
                if rv.port and rv.port not in asset.open_ports:
                    asset.open_ports.append(rv.port)

            network.assets[ip] = asset

    # ── Zone inference ──────────────────────────────────────────────────────

    def _infer_zone(self, ip: str) -> Zone:
        for prefix, zone in self.SUBNET_ZONE_MAP.items():
            if ip.startswith(prefix):
                return zone
        return Zone.UNKNOWN

    # ── Type inference ──────────────────────────────────────────────────────

    def _infer_type(self, asset: NetworkAsset) -> str:
        hn = asset.hostname.lower()
        if "database" in hn or "db" in hn or 3306 in asset.open_ports or 5432 in asset.open_ports:
            return "database"
        if "firewall" in hn or "fw" in hn:
            return "firewall"
        if "app" in hn and 3000 in asset.open_ports:
            return "appserver"
        if 80 in asset.open_ports or 443 in asset.open_ports:
            return "webserver"
        if "dc" in hn or "domain" in hn:
            return "domain_controller"
        return "server"

    # ── Flag extraction ─────────────────────────────────────────────────────

    def _set_flags(self, asset: NetworkAsset) -> None:
        for v in asset.vulns:
            name_lower = v.name.lower()
            if "root login" in name_lower or "ssh" in name_lower and "root" in name_lower:
                asset.ssh_root_login_enabled = True
            if "weak" in name_lower and ("ssh" in name_lower or "password" in name_lower):
                asset.has_weak_ssh_password = True
            if "world-writable" in name_lower or "world writable" in name_lower:
                asset.has_world_writable_files = True
            if "backup" in name_lower and ("file" in name_lower or "accessible" in name_lower):
                asset.has_exposed_backup_files = True
            if "default" in name_lower and ("credential" in name_lower or "password" in name_lower):
                asset.has_default_credentials = True
            if "suid" in name_lower:
                asset.has_suid_binary = True
            if "command injection" in name_lower:
                asset.has_command_injection = True
            if ".git" in name_lower:
                asset.has_exposed_git = True
            if "cgi" in name_lower:
                asset.has_cgi_enabled = True
            if "phpinfo" in name_lower:
                asset.has_phpinfo = True
            if "listening on all" in name_lower or "0.0.0.0" in name_lower:
                asset.db_listens_all_interfaces = True
            if "pii" in name_lower:
                asset.has_pii_data = True

    # ── ACL edges ───────────────────────────────────────────────────────────

    def _build_acl_edges(self, network: NormalizedNetwork, acl: RawACLConfig) -> None:
        if acl.default_policy == "ACCEPT":
            # Default ACCEPT = flag as finding on all assets
            for asset in network.assets.values():
                asset.vulns.append(Vulnerability(
                    vuln_id="MISCONFIG-FW-DEFAULT-ACCEPT",
                    name="Firewall Default ACCEPT Policy",
                    description="The firewall default FORWARD policy is ACCEPT, allowing unrestricted traffic between subnets.",
                    severity=Severity.HIGH,
                    cvss=7.5,
                ))

        for rule in acl.rules:
            if rule.action != "ACCEPT":
                continue
            # Create edges for ACCEPT rules between known subnets
            src_assets = self._match_assets(network, rule.src)
            dst_assets = self._match_assets(network, rule.dst)
            for src in src_assets:
                for dst in dst_assets:
                    if src.ip == dst.ip:
                        continue
                    ports = [rule.port] if rule.port else []
                    network.edges.append(NetworkEdge(
                        src_id=src.ip,
                        dst_id=dst.ip,
                        edge_type="network",
                        permitted_by=f"ACL: {rule.chain} {rule.src}->{rule.dst}",
                        ports=ports,
                        protocol=rule.protocol,
                    ))

    def _match_assets(self, network: NormalizedNetwork, cidr: str) -> list[NetworkAsset]:
        """Find assets matching a CIDR or IP."""
        if cidr == "0.0.0.0/0":
            return list(network.assets.values())
        # Subnet match
        if "/" in cidr:
            prefix = cidr.rsplit(".", 1)[0]  # rough /24 match
            return [a for a in network.assets.values() if a.ip.startswith(prefix.rstrip(".0") + ".")]
        # Exact IP
        asset = network.assets.get(cidr)
        return [asset] if asset else []

    # ── IaC edges ───────────────────────────────────────────────────────────

    def _build_iac_edges(self, network: NormalizedNetwork, iac: RawIaCScan) -> None:
        # Map resource IDs to IPs
        id_to_ip: dict[str, str] = {}
        for res in iac.resources:
            ip = res.properties.get("ip", "")
            if ip:
                id_to_ip[res.resource_id] = ip

        for res in iac.resources:
            src_ip = res.properties.get("ip", "")
            if not src_ip or src_ip not in network.assets:
                continue
            for conn_id in res.connections:
                dst_ip = id_to_ip.get(conn_id, "")
                if dst_ip and dst_ip in network.assets and dst_ip != src_ip:
                    network.edges.append(NetworkEdge(
                        src_id=src_ip,
                        dst_id=dst_ip,
                        edge_type="network",
                        permitted_by=f"IaC: {res.resource_id}->{conn_id}",
                    ))

    # ── IAM edges ───────────────────────────────────────────────────────────

    def _build_iam_edges(self, network: NormalizedNetwork, iam: RawIAMData) -> None:
        priv_map = {
            "root": PrivilegeLevel.ROOT,
            "admin": PrivilegeLevel.ADMIN,
            "sudo": PrivilegeLevel.SUDO,
            "user": PrivilegeLevel.USER,
        }
        for link in iam.links:
            if link.src_host == link.dst_host and link.link_type == "sudo":
                continue  # local sudo, not a network edge
            if not link.src_host or not link.dst_host:
                continue
            network.edges.append(NetworkEdge(
                src_id=link.src_host,
                dst_id=link.dst_host,
                edge_type="iam",
                link_type=link.link_type,
                privilege_level=priv_map.get(link.privilege, PrivilegeLevel.USER),
                description=link.description,
                permitted_by=f"IAM: {link.link_type} {link.username}@{link.src_host}->{link.dst_host}",
            ))

    # ── Subnet edges ────────────────────────────────────────────────────────

    def _add_subnet_edges(self, network: NormalizedNetwork) -> None:
        """Hosts on the same /24 subnet can communicate by default."""
        existing = {(e.src_id, e.dst_id) for e in network.edges}
        asset_list = list(network.assets.values())
        for i, a in enumerate(asset_list):
            for b in asset_list[i + 1:]:
                subnet_a = ".".join(a.ip.split(".")[:3])
                subnet_b = ".".join(b.ip.split(".")[:3])
                if subnet_a == subnet_b:
                    if (a.ip, b.ip) not in existing:
                        network.edges.append(NetworkEdge(
                            src_id=a.ip, dst_id=b.ip,
                            edge_type="network",
                            permitted_by="same-subnet",
                        ))
                        existing.add((a.ip, b.ip))
                    if (b.ip, a.ip) not in existing:
                        network.edges.append(NetworkEdge(
                            src_id=b.ip, dst_id=a.ip,
                            edge_type="network",
                            permitted_by="same-subnet",
                        ))
                        existing.add((b.ip, a.ip))

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _cvss_to_severity(cvss: float) -> Severity:
        if cvss >= 9.0:
            return Severity.CRITICAL
        if cvss >= 7.0:
            return Severity.HIGH
        if cvss >= 4.0:
            return Severity.MEDIUM
        if cvss > 0:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _nessus_severity(sev_str: str) -> Severity:
        return {
            "4": Severity.CRITICAL,
            "3": Severity.HIGH,
            "2": Severity.MEDIUM,
            "1": Severity.LOW,
        }.get(sev_str, Severity.INFO)
