#!/bin/bash
# default.sh — Intentionally misconfigured firewall rules
# FORWARD ACCEPT = all traffic between subnets is allowed (BAD)

echo "[firewall] Loading default (permissive) rules..."

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -X

# Default policies: ACCEPT everything (misconfiguration)
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# NAT masquerade for outbound
iptables -t nat -A POSTROUTING -j MASQUERADE

echo "[firewall] Default rules loaded — WARNING: FORWARD ACCEPT policy active"
