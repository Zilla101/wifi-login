"""Firewall backends: let a device's MAC through, or kick it back to the portal.

PORTAL_BACKEND picks one:
  iptables  - this machine (Pi / Linux laptop) is the gateway; see setup/gateway.sh
  opennds   - an OpenWrt router running openNDS; commands run over ssh if PORTAL_SSH is set
  dryrun    - just logs (for testing on any computer)
"""
import logging
import os
import re
import shlex
import subprocess

log = logging.getLogger("portal.firewall")

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
BACKEND = os.environ.get("PORTAL_BACKEND", "dryrun")
SSH_TARGET = os.environ.get("PORTAL_SSH", "")  # e.g. root@192.168.1.1
CHAIN = "portal_ok"


def _run(cmd):
    if SSH_TARGET:
        cmd = ["ssh", "-o", "BatchMode=yes", SSH_TARGET, shlex.join(cmd)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        log.warning("%s -> %s", " ".join(cmd), r.stderr.strip())
    return r.returncode == 0


def _check(mac):
    if not MAC_RE.match(mac or ""):
        raise ValueError(f"bad MAC: {mac!r}")


def allow(mac):
    _check(mac)
    log.info("ALLOW %s", mac)
    if BACKEND == "iptables":
        rule = [CHAIN, "-m", "mac", "--mac-source", mac, "-j", "MARK", "--set-mark", "0x1"]
        if not _run(["iptables", "-t", "mangle", "-C"] + rule):
            _run(["iptables", "-t", "mangle", "-A"] + rule)
    elif BACKEND == "opennds":
        _run(["ndsctl", "auth", mac])


def block(mac, ip=None):
    _check(mac)
    log.info("BLOCK %s", mac)
    if BACKEND == "iptables":
        rule = [CHAIN, "-m", "mac", "--mac-source", mac, "-j", "MARK", "--set-mark", "0x1"]
        while _run(["iptables", "-t", "mangle", "-D"] + rule):
            pass
        if ip:  # drop already-open connections so the kick is instant
            _run(["conntrack", "-D", "-s", ip])
    elif BACKEND == "opennds":
        _run(["ndsctl", "deauth", mac])


def mac_for_ip(ip):
    """Look up a LAN client's MAC from this machine's neighbour (ARP) table."""
    if os.environ.get("PORTAL_FAKE_MAC"):  # testing without a real network
        return os.environ["PORTAL_FAKE_MAC"]
    try:
        out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True,
                             text=True, timeout=5).stdout
        m = re.search(r"lladdr ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", out, re.I)
        if m:
            return m.group(1).lower()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts[0] == ip and MAC_RE.match(parts[3].lower()) and parts[3] != "00:00:00:00:00:00":
                    return parts[3].lower()
    except OSError:
        pass
    return None
