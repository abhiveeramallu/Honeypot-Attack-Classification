#!/usr/bin/env bash
# Lock down outbound traffic so a compromised/emulated shell inside Cowrie
# cannot be used to pivot laterally or join an outbound DDoS/spam campaign.
# Cowrie fakes command execution (no real shell for most commands), but any
# `wget`/`curl` a session issues IS real network activity by default unless
# download emulation is used — this ensures that even a misconfiguration
# can't turn the box into an attack platform. Run as root.
set -euo pipefail

EXT_IF="$(ip route | awk '/default/ {print $5; exit}')"

# Default-deny egress at the filter table's OUTPUT chain.
iptables -P OUTPUT DROP
iptables -F OUTPUT

# Always allow loopback and established/related return traffic.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow only what the box itself needs to function:
#  - DNS (for package updates / cowrie's own needs)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
#  - NTP for accurate log timestamps
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
#  - Outbound HTTPS/HTTP so Cowrie can optionally fetch/mirror attacker
#    payloads for offline analysis (disable if not needed: comment out).
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
#  - Log/telemetry shipping to your own collector (replace IP/port).
# iptables -A OUTPUT -p tcp -d <YOUR_LOG_COLLECTOR_IP> --dport 443 -j ACCEPT

# Explicitly drop everything else outbound, and log it for review.
iptables -A OUTPUT -j LOG --log-prefix "EGRESS-BLOCKED: " --log-level 4
iptables -A OUTPUT -j DROP

netfilter-persistent save

cat <<EOF
Egress lock-down applied on $EXT_IF:
  allowed  -> DNS(53), NTP(123), HTTPS(443), HTTP(80), loopback, established
  blocked  -> everything else outbound (SMTP/25, arbitrary TCP/UDP, ICMP flood potential, etc.)
This alone does not stop outbound floods over the allowed ports (80/443) —
also set cloud-provider bandwidth alerts/rate limits and review EGRESS-BLOCKED
log lines regularly (journalctl -k | grep EGRESS-BLOCKED).
EOF
