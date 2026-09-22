#!/usr/bin/env bash
# Forward standard SSH/Telnet ports to Cowrie's unprivileged listeners.
# Real admin SSH already lives on 22222 (see cloud-init.yaml), so 22/23
# are safe to hand to the honeypot. Run as root.
set -euo pipefail

EXT_IF="$(ip route | awk '/default/ {print $5; exit}')"
COWRIE_UID="$(id -u cowrie)"

# Allow the cowrie user to have its low-port traffic forwarded to it
# (authbind not needed since we NAT rather than bind directly).
iptables -t nat -A PREROUTING -i "$EXT_IF" -p tcp --dport 22  -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -i "$EXT_IF" -p tcp --dport 23  -j REDIRECT --to-port 2223

# Loopback-originated connections (e.g. local health checks) too.
iptables -t nat -A OUTPUT -o lo -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A OUTPUT -o lo -p tcp --dport 23 -j REDIRECT --to-port 2223

netfilter-persistent save

echo "NAT rules active: 22->2222 (ssh), 23->2223 (telnet) on $EXT_IF"
