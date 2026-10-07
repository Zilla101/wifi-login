"""WiFi sign-in portal: phone number + password, N devices per person, one super admin."""
import logging
import os
import re
import secrets
import socket
import sqlite3
import sys
import time
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import firewall

HERE = Path(__file__).resolve().parent


def load_env(path):
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


load_env(HERE / ".env")
firewall.BACKEND = os.environ.get("PORTAL_BACKEND", "dryrun")
firewall.SSH_TARGET = os.environ.get("PORTAL_SSH", "")

DATA = HERE / "data"
DATA.mkdir(exist_ok=True)
DB_PATH = DATA / "portal.db"
NETWORK_NAME = os.environ.get("NETWORK_NAME", "Room WiFi")
DEVICE_LIMIT = int(os.environ.get("DEVICE_LIMIT", "4"))
PORTAL_URL = os.environ.get("PORTAL_URL", "")  # e.g. http://10.42.0.1:8080
# Can this box see/control devices by MAC? If not ("manual" mode, e.g. running on an
# Android phone), devices are told apart by a cookie and the admin blocks MACs by hand
# in the router's own blacklist.
USES_MAC = firewall.BACKEND in ("iptables", "opennds", "dryrun")
MAC_RE = re.compile(r"\b((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})\b", re.I)
IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("portal")

app = Flask(__name__)
secret_file = DATA / "secret_key"
if not secret_file.exists():
    secret_file.write_text(secrets.token_hex(32))
app.secret_key = os.environ.get("SECRET_KEY") or secret_file.read_text().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  phone TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  device_limit INTEGER,
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key TEXT UNIQUE NOT NULL,
  mac TEXT,
  ip TEXT,
  label TEXT,
  created REAL NOT NULL,
  last_seen REAL NOT NULL
);
"""


def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def normalize_phone(raw):
    d = re.sub(r"\D", "", raw or "")
    if d.startswith("234") and len(d) == 13:
        d = "0" + d[3:]
    return d if re.fullmatch(r"0[789][01]\d{8}", d) else None


def device_label(ua):
    ua = ua or ""
    for key, name in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"),
                      ("Windows", "Windows PC"), ("Macintosh", "Mac"), ("Linux", "Linux"),
                      ("CrOS", "Chromebook")):
        if key in ua:
            return name
    return "Device"


def limit_for(user):
    return user["device_limit"] if user["device_limit"] is not None else DEVICE_LIMIT


# ---------------------------------------------------------------- startup

def bootstrap():
    with connect() as d:
        d.executescript(SCHEMA)
        phone = normalize_phone(os.environ.get("ADMIN_PHONE", ""))
        pw = os.environ.get("ADMIN_PASSWORD", "")
        if not phone:
            sys.exit("Set ADMIN_PHONE in wifi_portal/.env (see .env.example)")
        row = d.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone()
        if row:
            d.execute("UPDATE users SET is_admin=1, blocked=0 WHERE id=?", (row["id"],))
        else:
            if len(pw) < 6:
                sys.exit("Set ADMIN_PASSWORD (6+ chars) in wifi_portal/.env for first run")
            d.execute("INSERT INTO users (phone, pw_hash, is_admin, created) VALUES (?,?,1,?)",
                      (phone, generate_password_hash(pw), time.time()))
            log.info("created super admin %s", phone)
        # firewall rules don't survive a reboot; re-open every known device
        if USES_MAC:
            for r in d.execute("SELECT d.mac FROM devices d JOIN users u ON u.id=d.user_id "
                               "WHERE u.blocked=0 AND d.mac IS NOT NULL"):
                firewall.allow(r["mac"])


# ---------------------------------------------------------------- helpers

@app.before_request
def csrf_and_user():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST" and request.form.get("csrf") != session["csrf"]:
        abort(400)
    g.user = None
    if "uid" in session:
        g.user = db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
        if not g.user or g.user["blocked"]:
            session.pop("uid", None)
            g.user = None


@app.context_processor
def inject():
    return {"csrf": session.get("csrf", ""), "network": NETWORK_NAME, "me": g.get("user"),
            "manual": not USES_MAC}


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.user:
            return redirect(url_for("index"))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.user or not g.user["is_admin"]:
            abort(403)
        return f(*a, **kw)
    return wrapper


_fails = defaultdict(deque)


def too_many_fails(ip):
    q = _fails[ip]
    while q and q[0] < time.time() - 600:
        q.popleft()
    return len(q) >= 8


def current_device():
    """(key, mac) for the device making this request. key is the MAC when we can see
    it, otherwise a long-lived random cookie."""
    if USES_MAC:
        mac = firewall.mac_for_ip(request.remote_addr)
        return mac, mac
    tok = request.cookies.get("dev") or g.get("new_dev")
    if not tok or not re.fullmatch(r"[0-9a-f]{32}", tok):
        tok = g.new_dev = secrets.token_hex(16)
    return "c:" + tok, None


@app.after_request
def set_device_cookie(resp):
    if g.get("new_dev"):
        resp.set_cookie("dev", g.new_dev, max_age=60 * 60 * 24 * 365 * 5,
                        httponly=True, samesite="Lax")
    return resp


def attach_device(user):
    """Register the device making this request to `user` and open the firewall for it.
    Returns None on success or an error message."""
    ip = request.remote_addr
    key, mac = current_device()
    if not key:
        return "Couldn't detect your device. Make sure you're connected to the WiFi."
    d = db()
    now = time.time()
    dev = d.execute("SELECT * FROM devices WHERE key=?", (key,)).fetchone()
    if dev and dev["user_id"] != user["id"]:
        if not user["is_admin"]:
            return "This device is already linked to another account."
        d.execute("DELETE FROM devices WHERE id=?", (dev["id"],))
        dev = None
    if dev:
        d.execute("UPDATE devices SET ip=?, last_seen=? WHERE id=?", (ip, now, dev["id"]))
    else:
        count = d.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user["id"],)).fetchone()[0]
        if not user["is_admin"] and count >= limit_for(user):
            return "full"
        d.execute("INSERT INTO devices (user_id, key, mac, ip, label, created, last_seen) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (user["id"], key, mac, ip, device_label(request.user_agent.string), now, now))
    d.commit()
    if mac:
        firewall.allow(mac)
    return None


def block_dev(dev):
    if USES_MAC and dev["mac"]:
        firewall.block(dev["mac"], dev["ip"])


def local_ip():
    """This machine's address on the WiFi (what people type in to reach the portal)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def blacklist_hint(devs):
    """Manual mode: tell the admin what to put in the router's MAC blacklist."""
    if USES_MAC or not devs:
        return
    macs = [dv["mac"] for dv in devs if dv["mac"]]
    unknown = [dv["ip"] for dv in devs if not dv["mac"]]
    if macs:
        flash("Add to the router's MAC blacklist: " + ", ".join(macs), "error")
    if unknown:
        flash("MAC not known yet for IP " + ", ".join(unknown) +
              ". Run Router check to find it.", "error")


def remove_device(dev):
    block_dev(dev)
    db().execute("DELETE FROM devices WHERE id=?", (dev["id"],))
    db().commit()


# ---------------------------------------------------------------- user pages

@app.get("/")
def index():
    if g.user:
        return redirect(url_for("me"))
    return render_template("login.html", tab=request.args.get("tab", "login"))


@app.post("/login")
def login():
    ip = request.remote_addr
    if too_many_fails(ip):
        flash("Too many attempts. Wait a few minutes.", "error")
        return redirect(url_for("index"))
    phone = normalize_phone(request.form.get("phone"))
    user = phone and db().execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    if not user or not check_password_hash(user["pw_hash"], request.form.get("password", "")):
        _fails[ip].append(time.time())
        flash("Wrong phone number or password.", "error")
        return redirect(url_for("index"))
    if user["blocked"]:
        flash("This account has been blocked.", "error")
        return redirect(url_for("index"))
    return finish_login(user)


@app.post("/signup")
def signup():
    phone = normalize_phone(request.form.get("phone"))
    pw = request.form.get("password", "")
    if not phone:
        flash("Enter a valid phone number, e.g. 0803 123 4567.", "error")
    elif len(pw) < 6:
        flash("Password must be at least 6 characters.", "error")
    elif pw != request.form.get("confirm", ""):
        flash("Passwords don't match.", "error")
    elif db().execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
        flash("That number already has an account. Sign in instead.", "error")
    else:
        db().execute("INSERT INTO users (phone, pw_hash, created) VALUES (?,?,?)",
                     (phone, generate_password_hash(pw), time.time()))
        db().commit()
        user = db().execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        return finish_login(user)
    return redirect(url_for("index", tab="signup"))


def finish_login(user):
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    session["csrf"] = secrets.token_hex(16)
    g.user = user
    err = attach_device(user)
    if err == "full":
        flash(f"You've hit your {limit_for(user)}-device limit. Remove one to connect this device.", "error")
    elif err:
        flash(err, "error")
    else:
        flash("You're signed in. This device is registered." if not USES_MAC
              else "You're connected. Enjoy!", "ok")
    return redirect(url_for("me"))


@app.get("/me")
@login_required
def me():
    devices = db().execute("SELECT * FROM devices WHERE user_id=? ORDER BY created",
                           (g.user["id"],)).fetchall()
    here = current_device()[0]
    return render_template("me.html", devices=devices, here=here,
                           limit=None if g.user["is_admin"] else limit_for(g.user),
                           connected=any(d["key"] == here for d in devices))


@app.post("/connect")
@login_required
def connect_here():
    return finish_login(g.user)


@app.post("/device/<int:dev_id>/remove")
@login_required
def remove_own_device(dev_id):
    dev = db().execute("SELECT * FROM devices WHERE id=? AND user_id=?",
                       (dev_id, g.user["id"])).fetchone()
    if dev:
        remove_device(dev)
        flash(f"Removed {dev['label']}.", "ok")
    return redirect(url_for("me"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- admin

@app.get("/admin")
@admin_required
def admin():
    users = db().execute("""
        SELECT u.*, COUNT(d.id) AS n FROM users u LEFT JOIN devices d ON d.user_id=u.id
        GROUP BY u.id ORDER BY u.is_admin DESC, u.created DESC""").fetchall()
    devices = db().execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    by_user = defaultdict(list)
    for dv in devices:
        by_user[dv["user_id"]].append(dv)
    return render_template("admin.html", users=users, by_user=by_user,
                           default_limit=DEVICE_LIMIT, total_devices=len(devices),
                           address=f"http://{local_ip()}:{os.environ.get('PORT', '8080')}")


def target_user(uid):
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    if u["is_admin"]:
        flash("Can't change the super admin.", "error")
        return None
    return u


@app.post("/admin/user/<int:uid>/<action>")
@admin_required
def admin_user(uid, action):
    u = target_user(uid)
    if not u:
        return redirect(url_for("admin"))
    d = db()
    devs = d.execute("SELECT * FROM devices WHERE user_id=?", (uid,)).fetchall()
    if action == "block":
        d.execute("UPDATE users SET blocked=1 WHERE id=?", (uid,))
        for dv in devs:
            block_dev(dv)
        flash(f"Blocked {u['phone']}.", "ok")
        blacklist_hint(devs)
    elif action == "unblock":
        d.execute("UPDATE users SET blocked=0 WHERE id=?", (uid,))
        for dv in devs:
            if USES_MAC and dv["mac"]:
                firewall.allow(dv["mac"])
        flash(f"Unblocked {u['phone']}.", "ok")
        if not USES_MAC and any(dv["mac"] for dv in devs):
            flash("Remove from the router's MAC blacklist: " +
                  ", ".join(dv["mac"] for dv in devs if dv["mac"]), "ok")
    elif action == "delete":
        for dv in devs:
            block_dev(dv)
        d.execute("DELETE FROM users WHERE id=?", (uid,))
        flash(f"Deleted {u['phone']}.", "ok")
        blacklist_hint(devs)
    elif action == "limit":
        raw = request.form.get("limit", "").strip()
        new = None if raw == "" else max(0, min(50, int(raw))) if raw.isdigit() else u["device_limit"]
        d.execute("UPDATE users SET device_limit=? WHERE id=?", (new, uid))
        flash(f"{u['phone']} limit set to {DEVICE_LIMIT if new is None else new}.", "ok")
    elif action == "password":
        pw = request.form.get("password", "")
        if len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
        else:
            d.execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(pw), uid))
            flash(f"Password reset for {u['phone']}.", "ok")
    else:
        abort(404)
    d.commit()
    return redirect(url_for("admin"))


@app.post("/admin/device/<int:dev_id>/remove")
@admin_required
def admin_remove_device(dev_id):
    dev = db().execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
    if dev:
        remove_device(dev)
        flash(f"Removed {dev['label']} ({dev['mac'] or dev['ip']}).", "ok")
        blacklist_hint([dev])
    return redirect(url_for("admin"))


def parse_router_list(text):
    """Pull (name, ip, mac) rows out of a copy-paste of the router's connected devices
    page. Works per line; if IPs and MACs ended up on separate lines, pairs them in order."""
    rows, ips, macs = [], [], []
    for line in text.splitlines():
        ip, mac = IP_RE.search(line), MAC_RE.search(line)
        if ip and mac:
            name = MAC_RE.sub("", IP_RE.sub("", line)).strip(" \t-|,")
            rows.append((name, ip.group(1), norm_mac(mac.group(1))))
        elif ip:
            ips.append(ip.group(1))
        elif mac:
            macs.append(norm_mac(mac.group(1)))
    if not rows and ips and len(ips) == len(macs):
        rows = [("", ip, mac) for ip, mac in zip(ips, macs)]
    return rows


def norm_mac(mac):
    return mac.lower().replace("-", ":")


@app.route("/admin/check", methods=["GET", "POST"])
@admin_required
def admin_check():
    """Manual mode: compare who is on the router with who has signed in."""
    results, to_block = [], []
    text = request.form.get("devices", "")
    if request.method == "POST":
        d = db()
        me_ip = local_ip()
        for name, ip, mac in parse_router_list(text):
            dev = (d.execute("SELECT d.*, u.phone, u.blocked FROM devices d JOIN users u "
                             "ON u.id=d.user_id WHERE d.mac=?", (mac,)).fetchone()
                   or d.execute("SELECT d.*, u.phone, u.blocked FROM devices d JOIN users u "
                                "ON u.id=d.user_id WHERE d.ip=? AND d.mac IS NULL "
                                "ORDER BY d.last_seen DESC", (ip,)).fetchone())
            if ip == me_ip:
                status, who = "server", "this portal phone"
            elif not dev:
                status, who = "stranger", "not signed in"
                to_block.append(mac)
            else:
                d.execute("UPDATE devices SET mac=?, ip=? WHERE id=?", (mac, ip, dev["id"]))
                if dev["blocked"]:
                    status, who = "blocked", dev["phone"] + " (blocked)"
                    to_block.append(mac)
                else:
                    status, who = "ok", dev["phone"]
            results.append({"name": name, "ip": ip, "mac": mac, "status": status, "who": who})
        d.commit()
        if not results:
            flash("Couldn't find any IP + MAC pairs in that text.", "error")
    return render_template("check.html", results=results, to_block=to_block, text=text)


# ---------------------------------------------------------------- captive probes
# Phones check sites like connectivitycheck.gstatic.com/generate_204 or
# captive.apple.com/hotspot-detect.html. The gateway sends those to us; answering
# with a redirect makes the phone pop up the sign-in sheet automatically.

@app.errorhandler(404)
def to_portal(_):
    return redirect((PORTAL_URL.rstrip("/") + "/") if PORTAL_URL else url_for("index"))


bootstrap()
if not USES_MAC:
    log.info("Portal address for people on the WiFi: http://%s:%s",
             local_ip(), os.environ.get("PORT", "8080"))

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8080")))
