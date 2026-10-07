# WiFi sign-in portal

Anyone joining the WiFi gets a "Sign in to network" page. They make an account with
**phone number + a password they choose**, and each account can connect **4 devices**
(change with `DEVICE_LIMIT`). Sharing the WiFi password alone gets nobody online, and
sharing an account just uses up that person's slots.

The super admin (`ADMIN_PHONE`) has no device limit and gets `/admin`, where you can
kick devices, block, delete, reset passwords, or give someone a custom limit.

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env      # set ADMIN_PHONE / ADMIN_PASSWORD
python3 app.py            # http://localhost:8080  (PORTAL_BACKEND=dryrun just logs)
```

## Hook it to real WiFi

The page alone doesn't block anything; something on the network has to hold devices back
until they sign in. Pick the setup that matches your hardware:

**Airtel ODU / Raspberry Pi (the quick path)**
Plug the ODU's ethernet (from its PoE adapter) into the Pi, then:
```bash
sudo ./setup/install_pi.sh "Room WiFi" "hotspotpassword"
```
That creates the hotspot, turns on the firewall and starts the portal on every boot.
**Turn off the ODU's own WiFi** (or give it a long secret password). Anyone who
joins it directly skips the portal.

**A. Raspberry Pi or Linux laptop as the gateway, by hand** (works with any router or MiFi)
Internet comes in on one interface (e.g. the MiFi over USB or `eth0`) and the Pi or laptop
runs the hotspot people join (e.g. `nmcli dev wifi hotspot ifname wlan0 ssid RoomWiFi password ...`).
```bash
sudo ./setup/gateway.sh wlan0 usb0      # hotspot iface, internet iface
# .env: PORTAL_BACKEND=iptables, PORTAL_URL=http://<printed ip>:8080
sudo python3 app.py
```
Firewall rules are cleared on reboot. Run `gateway.sh` again before starting the app;
the app reopens every saved device when it starts.

**B. A router running OpenWrt + openNDS**
Set openNDS's FAS to point at the machine running this app. Then in `.env` set
`PORTAL_BACKEND=opennds` and `PORTAL_SSH=root@<router-ip>` (use an ssh key).

## Limits worth knowing

- Devices are recognised by MAC address. Phones use a random MAC per network, but it
  stays the same on the same network, so that's fine. If someone sets
  "randomise every time", they just sign in again.
- A user who removes a device frees the slot, so at most 4 devices can be online at the
  same time per account. That cap is what the portal enforces.
- The portal is plain HTTP on your LAN. Passwords are hashed in `data/portal.db`.
