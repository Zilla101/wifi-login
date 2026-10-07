#!/usr/bin/env bash
# One-shot setup for a Raspberry Pi (Raspberry Pi OS Bookworm) as the portal gateway.
#   Airtel ODU --ethernet--> Pi eth0      (internet in)
#   Pi wlan0   --WiFi hotspot--> students (portal in front)
#
#   sudo ./setup/install_pi.sh "Room WiFi" "hotspotpassword"
# After this, everything starts by itself whenever the Pi powers on.
set -euo pipefail
SSID=${1:?WiFi name}
PSK=${2:?WiFi password (8+ chars)}
WAN=${WAN:-eth0}
LAN=${LAN:-wlan0}
DIR=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "Run with sudo"; exit 1; }
[ ${#PSK} -ge 8 ] || { echo "WiFi password must be 8+ characters"; exit 1; }

apt-get update -qq
apt-get install -y -qq python3-flask iptables conntrack

# Hotspot: NetworkManager gives it 10.42.0.1, DHCP and DNS automatically
nmcli con delete portal-hotspot >/dev/null 2>&1 || true
nmcli con add type wifi ifname "$LAN" con-name portal-hotspot autoconnect yes ssid "$SSID" \
  802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared \
  wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PSK"
nmcli con up portal-hotspot

# Point the app at the hotspot address and switch on the real firewall
ENV="$DIR/.env"
touch "$ENV"
set_env() { grep -q "^$1=" "$ENV" && sed -i "s|^$1=.*|$1=$2|" "$ENV" || echo "$1=$2" >> "$ENV"; }
set_env PORTAL_BACKEND iptables
set_env PORTAL_URL http://10.42.0.1:8080
set_env NETWORK_NAME "$SSID"
grep -q '^ADMIN_PHONE=.' "$ENV" || echo "!! Set ADMIN_PHONE and ADMIN_PASSWORD in $ENV before rebooting"

cat > /etc/systemd/system/wifi-portal.service <<UNIT
[Unit]
Description=WiFi sign-in portal
After=NetworkManager.service network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$DIR
ExecStartPre=/bin/bash -c 'for i in \$(seq 30); do ip -4 addr show $LAN | grep -q inet && break; sleep 2; done'
ExecStartPre=$DIR/setup/gateway.sh $LAN $WAN 8080
ExecStart=/usr/bin/python3 $DIR/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wifi-portal
echo
echo "Done. Join \"$SSID\" on your phone — the sign-in page should pop up."
echo "Admin page: http://10.42.0.1:8080/admin    Logs: journalctl -u wifi-portal -f"
