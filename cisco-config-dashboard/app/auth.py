"""Users, roles, permissions and signed session cookies (standard library only)."""
import base64, hashlib, hmac, json, os, re, secrets, threading, time
from pathlib import Path

PERMISSIONS = {
    "view": "Read-only: port map, topology, show commands, route table, templates",
    "diagnostics": "Ping, monitor, IP scanner, traceroute",
    "config": "Push config, VLANs, interfaces, routing changes, restore backups",
    "backup": "Download running-config backups",
    "ssh_setup": "Enable SSH through the console cable",
    "reboot": "Reboot the switch (needs a second confirmation)",
    "bootloader": "Bootloader (switch: prompt) tools and password recovery over the console",
}
DEFAULT_USER_PERMS = ["view", "diagnostics"]
SESSION_TTL = 12 * 3600
DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR") or Path(__file__).resolve().parent.parent / "data")
_lock = threading.RLock()
_fails: dict = {}

# API path -> permission needed (anything /api/* not listed here is denied)
ROUTE_PERMS = {
    "/api/test-connection": "view", "/api/show": "view", "/api/ports": "view", "/api/port-detail": "view",
    "/api/topology": "view", "/api/templates": "view", "/api/serial-ports": "view", "/api/routing/table": "view",
    "/api/ping": "diagnostics", "/api/scan": "diagnostics", "/api/traceroute": "diagnostics",
    "/api/config": "config", "/api/vlan": "config", "/api/interface": "config", "/api/restore": "config",
    "/api/backup": "backup", "/api/ssh-setup": "ssh_setup", "/api/ssh-setup/preview": "ssh_setup",
    "/api/reboot/request": "reboot", "/api/reboot": "reboot", "/api/reboot/cancel": "reboot",
    "/api/bootloader/action": "bootloader",
}
PUBLIC = {"/login", "/health", "/api/auth/login", "/favicon.ico"}


# ---------- passwords ----------
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"pbkdf2${200_000}${salt.hex()}${dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        _, it, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), h)
    except Exception:
        return False


# ---------- storage ----------
def _file() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / "users.json"

def _load() -> dict:
    try:
        return json.loads(_file().read_text())
    except Exception:
        return {}

def _save(users: dict) -> None:
    f = _file(); tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(users, indent=2)); os.replace(tmp, f)
    try: os.chmod(f, 0o600)
    except OSError: pass

def ensure_admin() -> None:
    """First run: create 'admin' with a random password (or DASHBOARD_ADMIN_PASSWORD)."""
    with _lock:
        users = _load()
        if any(u["role"] == "admin" for u in users.values()):
            return
        pw = os.environ.get("DASHBOARD_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
        users["admin"] = {"hash": hash_password(pw), "role": "admin", "permissions": [], "disabled": False}
        _save(users)
        note = DATA_DIR / "first_run_credentials.txt"
        note.write_text(f"username: admin\npassword: {pw}\n(delete this file after your first login)\n")
        print(f"\n*** First run: admin account created. Password saved in {note} ***\n")

def _secret() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    f = DATA_DIR / "secret.key"
    if not f.exists():
        f.write_bytes(secrets.token_bytes(32))
        try: os.chmod(f, 0o600)
        except OSError: pass
    return f.read_bytes()


# ---------- sessions ----------
def make_token(username: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"u": username, "exp": int(time.time()) + SESSION_TTL}).encode()).decode()
    return body + "." + hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()

def user_from_token(token):
    """Username for a valid, unexpired token of an existing, enabled user; else None."""
    try:
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()):
            return None
        data = json.loads(base64.urlsafe_b64decode(body))
        u = _load().get(data["u"])
        return data["u"] if u and not u.get("disabled") and data["exp"] > time.time() else None
    except Exception:
        return None

def perms_of(username: str) -> set:
    u = _load().get(username)
    if not u: return set()
    return set(PERMISSIONS) | {"users"} if u["role"] == "admin" else set(u.get("permissions", [])) & set(PERMISSIONS)

def login(username: str, password: str, ip: str = ""):
    """-> (token, error, http_status). 5 failures / 5 min per user+IP are locked out."""
    key, now = f"{username.lower()}|{ip}", time.time()
    recent = [t for t in _fails.get(key, []) if now - t < 300]
    if len(recent) >= 5:
        return None, "Too many failed attempts. Try again in a few minutes.", 429
    u = _load().get(username)
    ok = bool(u) and not u.get("disabled") and verify_password(password, u["hash"])
    if not u:
        verify_password(password, "pbkdf2$200000$00$00")  # keep timing similar for unknown users
    if not ok:
        _fails[key] = recent + [now]
        return None, "Invalid username or password.", 401
    _fails.pop(key, None)
    return make_token(username), None, 200

def authorize(path: str, token):
    """-> (status, username, permissions). status: 200 ok, 302 go to login, 401, 403."""
    if path in PUBLIC or path.startswith("/static/"):
        return 200, None, set()
    user = user_from_token(token) if token else None
    api = path.startswith("/api/")
    if not user:
        return (401 if api else 302), None, set()
    perms = perms_of(user)
    if not api or path.startswith("/api/auth/"):
        return 200, user, perms
    need = "users" if path.startswith("/api/users") else ROUTE_PERMS.get(path)
    return (200 if need in perms else 403), user, perms


# ---------- user management (admin) ----------
def public_user(name: str, u: dict) -> dict:
    return {"username": name, "role": u["role"], "permissions": u.get("permissions", []), "disabled": u.get("disabled", False)}

def list_users() -> list:
    return [public_user(n, u) for n, u in sorted(_load().items())]

def upsert_user(name: str, password, role: str, permissions: list, disabled: bool = False):
    """-> error string or None. password may be empty when editing an existing user."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", name or ""): return "Username: 3-32 letters, digits, . _ -"
    if role not in ("admin", "user"): return "Role must be admin or user"
    bad = [p for p in permissions if p not in PERMISSIONS]
    if bad: return f"Unknown permission: {bad[0]}"
    with _lock:
        users = _load(); old = users.get(name)
        if not old and (not password or len(password) < 8): return "New users need a password of at least 8 characters"
        if password and len(password) < 8: return "Password must be at least 8 characters"
        if old and old["role"] == "admin" and (role != "admin" or disabled) and \
           sum(1 for u in users.values() if u["role"] == "admin" and not u.get("disabled")) <= 1:
            return "Cannot demote or disable the last admin"
        users[name] = {"hash": hash_password(password) if password else old["hash"], "role": role,
                       "permissions": sorted(set(permissions)), "disabled": disabled}
        _save(users)
    return None

def delete_user(name: str, actor: str):
    with _lock:
        users = _load()
        if name not in users: return "No such user"
        if name == actor: return "You cannot delete your own account"
        if users[name]["role"] == "admin" and sum(1 for u in users.values() if u["role"] == "admin") <= 1:
            return "Cannot delete the last admin"
        del users[name]; _save(users)
    return None
