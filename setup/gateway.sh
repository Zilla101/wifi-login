#!/usr/bin/env bash
# Turn this Linux box (Raspberry Pi / laptop) into the captive-portal gateway.
# Students connect to the hotspot on LAN_IF; internet comes in on WAN_IF.
# Unauthorised devices: web traffic is sent to the portal, everything else dropped.
# Authorised devices: the portal app adds their MAC to the "portal_ok" chain.
#
#   sudo ./setup/gateway.sh wlan0 eth0        # LAN_IF WAN_IF [PORTAL_PORT]
set -euo pipefail
LAN=${1:?hotspot interface, e.g. wlan0}
WAN=${2:?internet interface, e.g. eth0 or usb0}
PORT=${3:-8080}
GW_IP=$(ip -4 -o addr show "$LAN" | awk '{print $4}' | cut -d/ -f1)
[ -n "$GW_IP" ] || { echo "No IPv4 address on $LAN — start the hotspot first"; exit 1; }

sysctl -qw net.ipv4.ip_forward=1

# MAC allow-list (filled in by the app)
iptables -t mangle -N portal_ok 2>/dev/null || iptables -t mangle -F portal_ok
iptables -t mangle -C PREROUTING -i "$LAN" -j portal_ok 2>/dev/null ||
  iptables -t mangle -A PREROUTING -i "$LAN" -j portal_ok

# Unauthorised HTTP -> portal (this is what makes the "Sign in to network" popup appear)
iptables -t nat -C PREROUTING -i "$LAN" -p tcp --dport 80 -m mark ! --mark 0x1 -j DNAT --to-destination "$GW_IP:$PORT" 2>/dev/null ||
  iptables -t nat -I PREROUTING -i "$LAN" -p tcp --dport 80 -m mark ! --mark 0x1 -j DNAT --to-destination "$GW_IP:$PORT"

# Forwarding: only marked (authorised) devices get out
iptables -C FORWARD -i "$LAN" -o "$WAN" -m mark --mark 0x1 -j ACCEPT 2>/dev/null ||
  iptables -I FORWARD 1 -i "$LAN" -o "$WAN" -m mark --mark 0x1 -j ACCEPT
iptables -C FORWARD -i "$LAN" -o "$WAN" -j DROP 2>/dev/null ||
  iptables -I FORWARD 2 -i "$LAN" -o "$WAN" -j DROP
iptables -C FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
  iptables -I FORWARD 1 -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE

echo "Gateway ready. Portal: http://$GW_IP:$PORT  (set PORTAL_URL to this in .env)"
echo "Now run: sudo python3 app.py   (root is needed to change firewall rules)"
