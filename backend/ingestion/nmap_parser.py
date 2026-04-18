"""Nmap XML (-oX) parser + synthetic lab-data generator."""
from __future__ import annotations

from defusedxml import ElementTree as SafeET

from backend.ingestion.models import RawPort, RawNmapHost, RawNmapScan


def parse_nmap(xml_content: str | bytes) -> RawNmapScan:
    """Parse nmap XML output (-oX format)."""
    if isinstance(xml_content, str):
        xml_content = xml_content.encode("utf-8")

    root = SafeET.fromstring(xml_content)
    hosts: list[RawNmapHost] = []

    for host_el in root.iter("host"):
        # Status check
        status_el = host_el.find("status")
        status = status_el.get("state", "down") if status_el is not None else "down"
        if status != "up":
            continue

        # Address
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                break

        # Hostname
        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # OS
        os_name = ""
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")

        # Ports
        ports: list[RawPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                version = service_el.get("product", "") if service_el is not None else ""
                if service_el is not None and service_el.get("version"):
                    version += " " + service_el.get("version", "")

                # NSE scripts
                scripts: dict[str, str] = {}
                for script_el in port_el.findall("script"):
                    scripts[script_el.get("id", "")] = script_el.get("output", "")

                ports.append(RawPort(
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state="open",
                    service=service,
                    version=version.strip(),
                    scripts=scripts,
                ))

        hosts.append(RawNmapHost(ip=ip, hostname=hostname, os=os_name, ports=ports, status=status))

    return RawNmapScan(hosts=hosts)


def generate_lab_nmap_xml() -> str:
    """Generate synthetic nmap XML for the lab network."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -sC -oX" start="1700000000">

<host>
  <status state="up"/>
  <address addr="10.10.0.10" addrtype="ipv4"/>
  <hostnames><hostname name="webserver"/></hostnames>
  <os><osmatch name="Linux 5.x (Ubuntu 22.04)" accuracy="95"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
      <script id="ssh-auth-methods" output="Supported: publickey,password"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache httpd" version="2.4.49"/>
      <script id="http-headers" output="Server: Apache/2.4.49 (Ubuntu)"/>
      <script id="http-vuln-cve2021-41773" output="VULNERABLE: Path Traversal CVE-2021-41773"/>
      <script id="http-git" output="/.git/ found: Git repository exposed"/>
      <script id="http-backup-finder" output="backup.sql.bak, .env.bak found"/>
    </port>
  </ports>
</host>

<host>
  <status state="up"/>
  <address addr="10.10.0.20" addrtype="ipv4"/>
  <hostnames><hostname name="appserver"/></hostnames>
  <os><osmatch name="Linux 5.x (Ubuntu 22.04)" accuracy="95"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
    </port>
    <port protocol="tcp" portid="3000">
      <state state="open"/>
      <service name="http" product="Node.js Express" version="4.18"/>
      <script id="http-vuln-cve" output="Command injection via ?cmd= parameter"/>
    </port>
  </ports>
</host>

<host>
  <status state="up"/>
  <address addr="10.20.0.20" addrtype="ipv4"/>
  <hostnames><hostname name="database"/></hostnames>
  <os><osmatch name="Linux 5.x (Ubuntu 22.04)" accuracy="95"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="open"/>
      <service name="mysql" product="MySQL" version="8.0.35"/>
      <script id="mysql-info" output="Protocol: 10, Server: MySQL 8.0.35"/>
      <script id="mysql-vuln-cve" output="Default credentials: root:root"/>
    </port>
  </ports>
</host>

<host>
  <status state="up"/>
  <address addr="10.10.0.1" addrtype="ipv4"/>
  <hostnames><hostname name="firewall"/></hostnames>
  <os><osmatch name="Linux (Alpine)" accuracy="90"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.0"/>
    </port>
  </ports>
</host>

</nmaprun>"""
