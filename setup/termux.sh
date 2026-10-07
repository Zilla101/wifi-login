#!/data/data/com.termux/files/usr/bin/bash
# Run the portal on a spare Android phone (Termux from F-Droid).
#   bash setup/termux.sh
# Then: install the Termux:Boot app and open it once, so the portal starts when the phone boots.
set -euo pipefail
DIR=$(cd "$(dirname "$0")/.." && pwd)
pkg update -y
pkg install -y python
pip install flask

ENV="$DIR/.env"
touch "$ENV"
grep -q '^PORTAL_BACKEND=' "$ENV" && sed -i 's/^PORTAL_BACKEND=.*/PORTAL_BACKEND=manual/' "$ENV" \
  || echo "PORTAL_BACKEND=manual" >> "$ENV"
grep -q '^ADMIN_PHONE=.' "$ENV" || echo "!! Set ADMIN_PHONE and ADMIN_PASSWORD in $ENV"

mkdir -p ~/.termux/boot "$DIR/data"
cat > ~/.termux/boot/start-portal <<BOOT
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
cd "$DIR" && exec python app.py >> data/portal.log 2>&1
BOOT
chmod +x ~/.termux/boot/start-portal

echo
echo "Start it now with:   termux-wake-lock; cd $DIR && python app.py"
echo "It prints the address to share (http://192.168.x.x:8080)."
