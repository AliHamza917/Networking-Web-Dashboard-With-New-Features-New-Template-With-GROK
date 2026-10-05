"""
Cisco Switch Configuration Dashboard
Web GUI for configuring classic IOS / IOS-XE switches via SSH (Netmiko)
"""

from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List
import ipaddress
import os
import re
import secrets
import time
from datetime import datetime
from itertools import islice
from pathlib import Path

try:
    from . import auth, bootloader
except ImportError:  # run as a plain script
    import auth, bootloader

# Re-enable older SSH KEX/host-key algorithms for classic Cisco IOS.
# New Paramiko rejects them; Termius still allows them.
try:
    from paramiko import Transport
    _extra_kex = (
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
    )
    _kex = list(getattr(Transport, "_preferred_kex", ()) or ())
    for k in _extra_kex:
        if k not in _kex:
            _kex.append(k)
    Transport._preferred_kex = tuple(_kex)
    for attr, extras in (
        ("_preferred_keys", ("ssh-rsa", "ssh-dss")),
        ("_preferred_pubkeys", ("ssh-rsa", "ssh-dss")),
        ("_preferred_ciphers", ("aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc")),
    ):
        cur = getattr(Transport, attr, None)
        if cur is not None:
            lst = list(cur)
            for e in extras:
                if e not in lst:
                    lst.append(e)
            setattr(Transport, attr, tuple(lst))
except Exception:
    pass

import netmiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# Project root = parent of the "app" folder
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Ali Hamza Cisco Networking Dashboard", version="1.0.0")

# Mount static & templates (absolute paths so it works from any working directory)
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class DeviceCredentials(BaseModel):
    host: str = ""  # IP for SSH, or COM port for console e.g. COM3
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    port: int = 22
    device_type: str = "cisco_ios"
    # ssh | console
    connection_type: str = "ssh"
    # Console serial settings
    serial_port: Optional[str] = None  # COM3 or /dev/ttyUSB0
    baudrate: int = 9600


class ShowCommand(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    command: str
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class ConfigPush(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    config_commands: List[str]
    port: int = 22
    save: bool = True
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class VlanConfig(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    vlan_id: int
    vlan_name: Optional[str] = None
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class InterfaceConfig(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    interface: str
    mode: str = "access"          # access | trunk
    vlan: Optional[int] = None
    description: Optional[str] = None
    shutdown: bool = False
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class PortDetailRequest(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    interface: str
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class TraceRouteRequest(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    target: str
    port: int = 22
    probe: int = 3
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class PingRequest(BaseModel):
    target: str
    count: int = 2
    resolve: bool = False  # reverse-DNS lookup is slow; only the scanner wants it


class ScanRequest(BaseModel):
    subnet: str  # e.g. 192.168.4.0/24 or 192.168.4.1-50
    timeout: float = 1.0


# ------------------------------------------------------------------
# Helper
# ------------------------------------------------------------------

def expand_interface_name(name: str) -> str:
    """Expand short interface names for Cisco CLI."""
    n = name.strip()
    replacements = (
        ("Gi", "GigabitEthernet"),
        ("Fa", "FastEthernet"),
        ("Te", "TenGigabitEthernet"),
        ("Tw", "TwoGigabitEthernet"),
        ("Hu", "HundredGigE"),
        ("Eth", "Ethernet"),
        ("Po", "Port-channel"),
    )
    for short, full in replacements:
        if n.startswith(short) and len(n) > len(short) and n[len(short)].isdigit():
            return full + n[len(short):]
    return n

MAX_SCAN_HOSTS = 256


class EnableModeError(Exception):
    """The switch refused to enter privileged (enable) mode."""


def close_conn(conn) -> None:
    """Disconnect without ever raising (used in `finally` blocks)."""
    if conn is None:
        return
    try:
        conn.disconnect()
    except Exception:
        pass


def _enter_enable_mode(conn, secret: str) -> None:
    """
    Get into privileged mode. If an enable secret was supplied and it does not
    work, fail loudly instead of continuing in user EXEC mode.
    """
    prompt = conn.find_prompt().strip()
    if not prompt.endswith(">"):
        return  # already '#' (privileged) or a mode we should not touch
    try:
        conn.enable()
    except Exception as e:
        if secret:
            raise EnableModeError(
                "Enable failed – the enable secret was rejected "
                f"(or the switch did not accept 'enable'). Detail: {e}"
            ) from e
        # No secret given: stay in user EXEC. Read-only 'show' commands may still
        # work; config endpoints check privileged_error() and report it clearly.
        return
    if secret and not conn.find_prompt().strip().endswith("#"):
        raise EnableModeError("Enable failed – switch is still in user EXEC mode (>). Check the enable secret.")


def privileged_error(conn) -> Optional[str]:
    """Return an error message if the session is NOT in privileged mode."""
    try:
        prompt = conn.find_prompt().strip()
    except Exception as e:
        return f"Cannot read the switch prompt: {e}"
    if prompt.endswith(">"):
        return (
            "Switch is in user EXEC mode (>), so configuration is not possible. "
            "Enter the Enable Secret (or use a privilege-15 account) and try again."
        )
    return None


_FULL_TO_SHORT = {
    "gigabitethernet": "gi",
    "fastethernet": "fa",
    "tengigabitethernet": "te",
    "twogigabitethernet": "tw",
    "twentyfivegige": "twe",
    "fortygigabitethernet": "fo",
    "hundredgige": "hu",
    "ethernet": "eth",
    "port-channel": "po",
}


def canonical_if_name(name: str) -> str:
    """'GigabitEthernet1/0/1' and 'Gi1/0/1' both -> 'gi1/0/1' (for EXACT comparisons)."""
    n = (name or "").strip().lower().replace(" ", "")
    m = re.match(r"^([a-z][a-z\-]*)(\d.*)$", n)
    if not m:
        return n
    prefix, rest = m.groups()
    return _FULL_TO_SHORT.get(prefix, prefix) + rest


# Lines the switch prints when it rejects a command, e.g.
#   % Invalid input detected at '^' marker.
_IOS_ERROR_RE = re.compile(
    r"^%\s*(invalid input|incomplete command|ambiguous command|unrecognized command|"
    r"unknown command|command rejected|access denied|authorization failed|"
    r"bad (mask|ip address)|cannot |error\b|failed\b)",
    re.I,
)


def find_ios_errors(output: str) -> list:
    """Scan CLI output for IOS error lines; remember which command caused each one."""
    errors = []
    last_cmd = ""
    for line in (output or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if _IOS_ERROR_RE.match(s):
            errors.append({"command": last_cmd, "message": s})
        elif s != "^" and not s.startswith("%"):
            last_cmd = s
    return errors


def apply_config(conn, commands: List[str], save: bool = True) -> dict:
    """
    Send config commands. success is True ONLY if the switch accepted every
    command. If any command was rejected the config is NOT saved.
    """
    output = conn.send_config_set(commands)
    errors = find_ios_errors(output)
    if errors:
        summary = "\n".join(
            f"  • {e['message']}" + (f"   (near: {e['command']})" if e["command"] else "")
            for e in errors
        )
        return {
            "success": False,
            "saved": False,
            "errors": errors,
            "output": output,
            "error": (
                f"{len(errors)} command(s) were REJECTED by the switch. "
                "Config was NOT saved – the running-config may be partially applied.\n"
                f"{summary}\n\n--- switch output ---\n{output}"
            ),
        }
    saved = False
    if save:
        output += "\n\n--- save ---\n" + str(conn.save_config())
        saved = True
    return {"success": True, "saved": saved, "errors": [], "output": output}


def config_response(conn, commands: List[str], save: bool = True):
    """apply_config() wrapped as an HTTP response (checks privileged mode first)."""
    priv = privileged_error(conn)
    if priv:
        return JSONResponse({"success": False, "error": priv}, status_code=403)
    result = apply_config(conn, commands, save)
    return result if result["success"] else JSONResponse(result, status_code=422)


def get_connection(creds: dict):
    """
    Create Netmiko connection via SSH or console (serial) cable.
    """
    conn_type = (creds.get("connection_type") or "ssh").lower().strip()
    secret = (creds.get("secret") or "").strip()
    username = (creds.get("username") or "").strip()
    password = creds.get("password") or ""

    if conn_type in ("console", "serial"):
        serial_port = (creds.get("serial_port") or creds.get("host") or "").strip()
        if not serial_port:
            raise ValueError("Console mode requires a serial port (e.g. COM3)")
        device = {
            "device_type": "cisco_ios_serial",
            "username": username,
            "password": password,
            "secret": secret,
            "serial_settings": {
                "port": serial_port,
                "baudrate": int(creds.get("baudrate") or 9600),
                "bytesize": 8,
                "parity": "N",
                "stopbits": 1,
            },
            "timeout": 90,
            "fast_cli": False,
            "global_delay_factor": 3,
            "global_cmd_verify": False,
        }
    else:
        host = (creds.get("host") or "").strip()
        if not host:
            raise ValueError("SSH mode requires switch IP / hostname")
        device = {
            "device_type": creds.get("device_type", "cisco_ios"),
            "host": host,
            "username": username,
            "password": password,
            "port": int(creds.get("port") or 22),
            "secret": secret,
            "timeout": 90,
            "conn_timeout": 90,
            "auth_timeout": 90,
            "banner_timeout": 60,
            "fast_cli": False,
            "global_delay_factor": 3,
            "global_cmd_verify": False,
            "use_keys": False,
            "allow_agent": False,
        }

    conn = ConnectHandler(**device)
    try:
        _enter_enable_mode(conn, secret)
    except Exception:
        close_conn(conn)  # do not leak the session if enable fails
        raise
    try:
        conn.send_command_timing("terminal length 0")
    except Exception:
        pass  # harmless: Netmiko already disables paging
    return conn


def run_cmd(conn, command: str, use_textfsm: bool = False, read_timeout: int = 120):
    """Run a show command with timing fallback (avoids echo verify timeouts)."""
    try:
        return conn.send_command(
            command,
            use_textfsm=use_textfsm,
            read_timeout=read_timeout,
            cmd_verify=False,
        )
    except Exception:
        # Fallback: timing-based (no echo check)
        out = conn.send_command_timing(command, read_timeout=read_timeout)
        if use_textfsm:
            return out  # raw text; caller handles non-list
        return out


def safe_connect(creds: dict):
    try:
        return get_connection(creds), None
    except EnableModeError as e:
        return None, str(e)
    except NetmikoAuthenticationException:
        return None, "Authentication failed – check username / password / enable secret (same values that work in Termius)"
    except NetmikoTimeoutException:
        return None, (
            "SSH timed out in Netmiko (Termius works, so try):\n"
            "• Exact same IP, username, password as Termius\n"
            "• Enable secret if Termius uses it\n"
            "• Port 22 (or the port Termius uses)\n"
            "• Wait – first connect can take 15–30s across VLANs"
        )
    except Exception as e:
        err = str(e)
        low = err.lower()
        if "timed out" in low or "timeout" in low:
            return None, (
                "SSH timed out. Since Termius works:\n"
                "• Use the same IP/user/password as Termius\n"
                "• Leave Enable Secret empty if Termius does not use it\n"
                "• Confirm port matches Termius (usually 22)\n"
                f"Detail: {err}"
            )
        if "negotiation" in low or "kex" in low or "algorithm" in low:
            return None, (
                "SSH algorithm mismatch (common with old IOS + new Paramiko).\n"
                "Try: pip install 'paramiko<3'   then restart the app.\n"
                f"Detail: {err}"
            )
        return None, f"Connection error: {err}"


# ------------------------------------------------------------------
# Routes – Pages
# ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # Compatible with new Starlette (request first) and older versions
    try:
        return templates.TemplateResponse(request, "index.html")
    except TypeError:
        return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


# ------------------------------------------------------------------
# API – Connection test
# ------------------------------------------------------------------

@app.post("/api/test-connection")
def test_connection(creds: DeviceCredentials):
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        prompt = conn.find_prompt()
        version = run_cmd(conn, "show version | include Cisco IOS Software|System image")
        hostname = prompt.replace("#", "").replace(">", "")
        return {
            "success": True,
            "hostname": hostname,
            "prompt": prompt,
            "version_snippet": version[:300] if version else "N/A"
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Show commands
# ------------------------------------------------------------------

@app.post("/api/show")
def run_show(cmd: ShowCommand):
    command = cmd.command.strip()
    # Validate BEFORE opening an SSH session
    if not command.lower().startswith(("show", "display")):
        return JSONResponse({"success": False, "error": "Only 'show' commands are allowed here"}, status_code=400)
    if "\n" in command or "\r" in command:
        return JSONResponse({"success": False, "error": "Only a single command line is allowed"}, status_code=400)

    conn, err = safe_connect(cmd.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        output = run_cmd(conn, command, read_timeout=120)
        return {"success": True, "output": output}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Free-form config push
# ------------------------------------------------------------------

@app.post("/api/config")
def push_config(cfg: ConfigPush):
    # Validate BEFORE opening an SSH session
    commands = [c.strip() for c in cfg.config_commands if c.strip()]
    if not commands:
        return JSONResponse({"success": False, "error": "No commands provided"}, status_code=400)

    conn, err = safe_connect(cfg.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        return config_response(conn, commands, save=cfg.save)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – VLAN helper
# ------------------------------------------------------------------

@app.post("/api/vlan")
def create_vlan(vlan: VlanConfig):
    conn, err = safe_connect(vlan.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        commands = [f"vlan {vlan.vlan_id}"]
        if vlan.vlan_name:
            commands.append(f"name {vlan.vlan_name}")
        commands.append("exit")
        return config_response(conn, commands, save=True)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Interface helper
# ------------------------------------------------------------------

@app.post("/api/interface")
def configure_interface(iface: InterfaceConfig):
    conn, err = safe_connect(iface.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        commands = [f"interface {iface.interface}"]
        if iface.description:
            commands.append(f"description {iface.description}")
        if iface.mode == "access":
            commands.append("switchport mode access")
            if iface.vlan:
                commands.append(f"switchport access vlan {iface.vlan}")
        elif iface.mode == "trunk":
            commands.append("switchport mode trunk")
            if iface.vlan:
                commands.append(f"switchport trunk native vlan {iface.vlan}")
        if iface.shutdown:
            commands.append("shutdown")
        else:
            commands.append("no shutdown")
        commands.append("exit")
        return config_response(conn, commands, save=True)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Backup running-config
# ------------------------------------------------------------------

@app.post("/api/backup")
def backup_config(creds: DeviceCredentials):
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        output = run_cmd(conn, "show running-config", read_timeout=180)
        hostname = conn.find_prompt().replace("#", "").replace(">", "")
        safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", hostname) or "switch"
        filename = f"{safe_host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cfg"
        # Returned straight from memory: no temp file is written, so nothing to clean up.
        return Response(
            content=output,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


@app.post("/api/restore")
def restore_config(
    file: UploadFile = File(...),
    host: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    secret: str = Form(""),
    port: int = Form(22),
    connection_type: str = Form("ssh"),
    serial_port: str = Form(""),
    baudrate: int = Form(9600),
    save: bool = Form(True),
):
    """Upload a .cfg / text backup and apply lines to the switch."""
    try:
        raw = file.file.read()
        text = raw.decode("utf-8", errors="ignore")
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Cannot read file: {e}"}, status_code=400)

    # Strip comments / empty; skip typical show-run headers
    commands = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("!") or s.startswith("#"):
            continue
        if s.lower().startswith(("building configuration", "current configuration", "version ")):
            continue
        if s.lower() in ("end", "exit"):
            continue
        commands.append(s)

    if not commands:
        return JSONResponse({"success": False, "error": "No usable config lines in file"}, status_code=400)
    if len(commands) > 5000:
        return JSONResponse({"success": False, "error": "File too large (max 5000 lines)"}, status_code=400)

    creds = {
        "host": host,
        "username": username,
        "password": password,
        "secret": secret or None,
        "port": port,
        "connection_type": connection_type,
        "serial_port": serial_port or None,
        "baudrate": baudrate,
    }
    conn, err = safe_connect(creds)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        priv = privileged_error(conn)
        if priv:
            return JSONResponse({"success": False, "error": priv}, status_code=403)
        output = conn.send_config_set(commands)
        warnings = find_ios_errors(output)
        saved = False
        # A restore of a full 'show run' often produces a few harmless rejects, so
        # this stays success=True – but we never auto-save a config that had errors.
        if save and not warnings:
            output += "\n\n--- save ---\n" + str(conn.save_config())
            saved = True
        return {
            "success": True,
            "lines_applied": len(commands),
            "warnings": warnings,
            "saved": saved,
            "save_skipped": bool(save and warnings),
            "output": output,
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


@app.get("/api/serial-ports")
def list_serial_ports():
    """List COM / serial ports available on this PC (for console cable)."""
    ports = []
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            ports.append({
                "device": p.device,
                "description": p.description or "",
                "hwid": getattr(p, "hwid", "") or "",
            })
    except Exception as e:
        return {"success": True, "ports": [], "note": f"pyserial list failed: {e}. Type COM3 manually."}
    return {"success": True, "ports": ports}


# ------------------------------------------------------------------
# API – Port map (graphical view)
# ------------------------------------------------------------------

@app.post("/api/ports")
def get_ports(creds: DeviceCredentials):
    """
    Fetch interface status and return structured data for the graphical port map.
    Uses TextFSM (ntc-templates) when available.
    """
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        # Primary structured command
        raw = run_cmd(conn, "show interfaces status", use_textfsm=True, read_timeout=120)
        hostname = conn.find_prompt().replace("#", "").replace(">", "")

        # Extra trunk detection via switchport summary (more reliable)
        trunk_ports = set()  # canonical names, see canonical_if_name()
        try:
            sw = run_cmd(conn, "show interfaces switchport", read_timeout=120)
            if isinstance(sw, str):
                current_if = None
                for line in sw.splitlines():
                    m = re.match(r"\s*Name:\s+(\S+)", line)
                    if m:
                        current_if = m.group(1)
                    if current_if and re.search(r"Operational Mode:\s*trunk", line, re.I):
                        trunk_ports.add(canonical_if_name(current_if))
        except Exception:
            pass

        ports = []
        if isinstance(raw, list) and raw:
            for row in raw:
                port_name = row.get("port") or row.get("interface") or row.get("Port") or ""
                status = (row.get("status") or row.get("Status") or "").lower()
                vlan = str(row.get("vlan") or row.get("Vlan") or "")
                duplex = row.get("duplex") or row.get("Duplex") or ""
                speed = row.get("speed") or row.get("Speed") or ""
                port_type = row.get("type") or row.get("Type") or ""
                name = row.get("name") or row.get("Name") or ""

                if status in ("connected", "up"):
                    state = "up"
                elif status in ("notconnect", "not connected", "down", "disabled"):
                    state = "down"
                elif "err" in status or "error" in status:
                    state = "error"
                else:
                    state = "unknown"

                vlan_l = vlan.lower().strip()
                # EXACT match on canonical names. (The old substring match made
                # Gi1/0/2 look like a trunk whenever Gi1/0/24 was one.)
                is_trunk = (
                    vlan_l in ("trunk", "trnk", "tr")
                    or canonical_if_name(port_name) in trunk_ports
                )

                mode = "trunk" if is_trunk else "access"

                ports.append({
                    "port": port_name,
                    "name": name,
                    "status": status,
                    "state": state,
                    "vlan": vlan,
                    "mode": mode,
                    "duplex": duplex,
                    "speed": speed,
                    "type": port_type,
                })
        else:
            raw_text = run_cmd(conn, "show interfaces status", read_timeout=120)
            ports = [{"port": "raw", "raw": raw_text, "state": "unknown", "mode": "access"}]

        return {
            "success": True,
            "hostname": hostname,
            "ports": ports,
            "count": len(ports),
            "trunk_count": sum(1 for p in ports if p.get("mode") == "trunk"),
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Port detail (MAC + IP on a port)
# ------------------------------------------------------------------

@app.post("/api/port-detail")
def port_detail(req: PortDetailRequest):
    """MAC address table + ARP/IP for a specific interface."""
    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        import re
        iface = req.interface.strip()
        iface_full = expand_interface_name(iface)

        mac_entries = []
        # Try full then short name
        for ifname in (iface_full, iface):
            mac_raw = run_cmd(conn, f"show mac address-table interface {ifname}", read_timeout=60)
            if not isinstance(mac_raw, str):
                continue
            if "Invalid" in mac_raw or "not exist" in mac_raw.lower():
                continue
            for line in mac_raw.splitlines():
                # Typical: VLAN  MAC Address       Type        Ports
                # 10    0011.2233.4455    DYNAMIC     Gi1/0/1
                m = re.search(
                    r"(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\S+)\s+(\S+)",
                    line,
                )
                if m:
                    mac_entries.append({
                        "vlan": m.group(1),
                        "mac": m.group(2).lower(),
                        "type": m.group(3),
                        "port": m.group(4),
                    })
            if mac_entries:
                break

        # Resolve IP from ARP for each MAC
        arp_raw = run_cmd(conn, "show ip arp", read_timeout=90)
        arp_map = {}
        if isinstance(arp_raw, str):
            for line in arp_raw.splitlines():
                # Internet  192.168.1.10  0   0011.2233.4455  ARPA  Vlan10
                am = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})",
                    line,
                )
                if am:
                    arp_map[am.group(2).lower()] = am.group(1)

        hosts = []
        for e in mac_entries:
            hosts.append({
                "vlan": e["vlan"],
                "mac": e["mac"],
                "type": e["type"],
                "ip": arp_map.get(e["mac"], ""),
            })

        # Optional: IP device tracking
        idt_raw = ""
        try:
            idt_raw = run_cmd(conn, f"show ip device tracking interface {iface_full}", read_timeout=30)
            if isinstance(idt_raw, str) and ("Invalid" in idt_raw or "not enabled" in idt_raw.lower()):
                idt_raw = ""
        except Exception:
            idt_raw = ""

        return {
            "success": True,
            "interface": iface,
            "interface_full": iface_full,
            "hosts": hosts,
            "host_count": len(hosts),
            "mac_table_raw": mac_raw if isinstance(mac_raw, str) else "",
            "device_tracking": idt_raw if isinstance(idt_raw, str) else "",
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Traceroute (track route)
# ------------------------------------------------------------------

def _parse_traceroute_hops(output: str, source: str, target: str) -> list:
    """Parse Cisco IOS traceroute text into structured hops for the visual map."""
    import re
    hops = [
        {
            "hop": 0,
            "ip": source or "Switch",
            "label": source or "Switch",
            "rtt_ms": [],
            "status": "source",
        }
    ]
    # Examples:
    #  1 10.0.0.1 4 msec 2 msec 2 msec
    #  2 * * *
    #  3 8.8.8.8 20 msec 18 msec 19 msec
    #  1 10.0.0.1 [AS 0] 1 msec 1 msec 1 msec
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("tracing") or line.lower().startswith("type"):
            continue
        m = re.match(r"^(\d+)\s+(.*)$", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2).strip()
        if re.match(r"^[\*\s]+$", rest) or rest.replace("*", "").replace(" ", "") == "":
            hops.append({
                "hop": hop_num,
                "ip": "*",
                "label": "Timeout",
                "rtt_ms": [],
                "status": "timeout",
            })
            continue
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
        ip = ip_m.group(1) if ip_m else rest.split()[0]
        rtts = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*msec", rest, re.I)]
        hops.append({
            "hop": hop_num,
            "ip": ip,
            "label": ip,
            "rtt_ms": rtts,
            "status": "ok" if rtts else "unknown",
        })
    # Destination marker
    hops.append({
        "hop": 999,
        "ip": target,
        "label": target,
        "rtt_ms": [],
        "status": "destination",
    })
    return hops


@app.post("/api/traceroute")
def traceroute(req: TraceRouteRequest):
    """Run traceroute from the switch; return text + structured hops for visual map."""
    target = req.target.strip()
    # Validate BEFORE opening an SSH session
    if not target or any(c in target for c in (";", "|", "\r", "\n", "`")):
        return JSONResponse({"success": False, "error": "Invalid target"}, status_code=400)

    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        cmd = f"traceroute {target}"
        try:
            output = conn.send_command_timing(cmd, read_timeout=180)
            if "Probe" in str(output) or "Numeric" in str(output):
                output = str(output) + conn.send_command_timing("\n", read_timeout=60)
        except Exception as e:
            output = str(e)

        output = output if isinstance(output, str) else str(output)
        hostname = conn.find_prompt().replace("#", "").replace(">", "")

        hops = _parse_traceroute_hops(output, hostname, target)
        return {
            "success": True,
            "hostname": hostname,
            "target": target,
            "output": output,
            "hops": hops,
            "hop_count": max(0, len(hops) - 2),  # exclude source + destination markers
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Network Topology (CDP / LLDP)
# ------------------------------------------------------------------

def _parse_cdp_fallback(raw: str) -> list:
    """Basic regex fallback when TextFSM is unavailable."""
    import re
    neighbors = []
    # Split on device blocks
    blocks = re.split(r"(?=\nDevice ID:)", "\n" + raw)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        dev = re.search(r"Device ID:\s*(.+)", block)
        local = re.search(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)", block)
        if not local:
            local = re.search(r"Interface:\s*(\S+).+Port ID.+:\s*(\S+)", block)
        plat = re.search(r"Platform:\s*([^,\n]+)", block)
        cap = re.search(r"Capabilities:\s*(.+)", block)
        ip = re.search(r"IP address:\s*(\S+)", block)
        if dev:
            neighbors.append({
                "neighbor": dev.group(1).strip().split(".")[0],
                "local_interface": local.group(1).strip() if local else "",
                "neighbor_interface": local.group(2).strip() if local else "",
                "platform": plat.group(1).strip() if plat else "",
                "capabilities": cap.group(1).strip() if cap else "",
                "mgmt_address": ip.group(1).strip() if ip else "",
                "protocol": "cdp",
            })
    return neighbors


@app.post("/api/topology")
def get_topology(creds: DeviceCredentials):
    """
    Build a topology graph from CDP (preferred) and LLDP neighbors.
    Returns nodes + edges for interactive visualization.
    """
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        hostname = conn.find_prompt().replace("#", "").replace(">", "").strip()
        # Local management IP (best effort)
        local_ip = ""
        try:
            ip_out = run_cmd(conn, "show ip interface brief | include up")
            for line in ip_out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].count(".") == 3 and not parts[1].startswith("unassigned"):
                    local_ip = parts[1]
                    break
        except Exception:
            pass

        neighbors = []

        # --- CDP ---
        try:
            cdp = run_cmd(conn, "show cdp neighbors detail", use_textfsm=True, read_timeout=120)
            if isinstance(cdp, list) and cdp:
                for row in cdp:
                    neighbors.append({
                        "neighbor": (row.get("destination_host") or row.get("device_id") or row.get("neighbor") or "").split(".")[0],
                        "local_interface": row.get("local_port") or row.get("local_interface") or "",
                        "neighbor_interface": row.get("remote_port") or row.get("neighbor_port") or row.get("port_id") or "",
                        "platform": row.get("platform") or "",
                        "capabilities": row.get("capabilities") or "",
                        "mgmt_address": row.get("management_ip") or row.get("ip") or "",
                        "protocol": "cdp",
                    })
            else:
                raw = run_cmd(conn, "show cdp neighbors detail", read_timeout=120)
                if isinstance(raw, str) and "CDP is not enabled" not in raw and "Invalid" not in raw:
                    neighbors.extend(_parse_cdp_fallback(raw))
        except Exception:
            try:
                raw = run_cmd(conn, "show cdp neighbors detail", read_timeout=120)
                if isinstance(raw, str):
                    neighbors.extend(_parse_cdp_fallback(raw))
            except Exception:
                pass

        # --- LLDP (add only if not already seen via CDP) ---
        seen = {(n["neighbor"].lower(), n["local_interface"].lower()) for n in neighbors}
        try:
            lldp = run_cmd(conn, "show lldp neighbors detail", use_textfsm=True, read_timeout=120)
            if isinstance(lldp, list) and lldp:
                for row in lldp:
                    neigh = (row.get("neighbor") or row.get("system_name") or row.get("chassis_id") or "").split(".")[0]
                    local_if = row.get("local_interface") or row.get("local_port") or ""
                    key = (neigh.lower(), local_if.lower())
                    if key in seen or not neigh:
                        continue
                    neighbors.append({
                        "neighbor": neigh,
                        "local_interface": local_if,
                        "neighbor_interface": row.get("neighbor_port") or row.get("port_id") or "",
                        "platform": row.get("system_description") or row.get("platform") or "",
                        "capabilities": row.get("capabilities") or "",
                        "mgmt_address": row.get("management_ip") or row.get("ip") or "",
                        "protocol": "lldp",
                    })
        except Exception:
            pass


        # Build graph
        nodes = [
            {
                "id": hostname,
                "label": hostname,
                "type": "local",
                "ip": local_ip,
                "platform": "Local Switch",
            }
        ]
        edges = []
        node_ids = {hostname.lower()}

        for n in neighbors:
            nid = n["neighbor"] or "Unknown"
            if nid.lower() not in node_ids:
                node_ids.add(nid.lower())
                # Guess device type from capabilities / platform
                caps = (n.get("capabilities") or "").lower()
                plat = (n.get("platform") or "").lower()
                if "switch" in caps or "switch" in plat or "catalyst" in plat or "nexus" in plat:
                    dtype = "switch"
                elif "router" in caps or "router" in plat:
                    dtype = "router"
                elif "phone" in caps or "phone" in plat:
                    dtype = "phone"
                elif "host" in caps or "workstation" in caps:
                    dtype = "host"
                else:
                    dtype = "device"
                nodes.append({
                    "id": nid,
                    "label": nid,
                    "type": dtype,
                    "ip": n.get("mgmt_address") or "",
                    "platform": n.get("platform") or "",
                })

            edges.append({
                "from": hostname,
                "to": nid,
                "local_interface": n.get("local_interface") or "",
                "neighbor_interface": n.get("neighbor_interface") or "",
                "protocol": n.get("protocol") or "cdp",
                "label": f"{n.get('local_interface', '')} ↔ {n.get('neighbor_interface', '')}",
            })

        return {
            "success": True,
            "hostname": hostname,
            "nodes": nodes,
            "edges": edges,
            "neighbor_count": len(neighbors),
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Ping & IP Scanner (from the machine running this app)
# ------------------------------------------------------------------

def _guess_device_type(ttl: Optional[int], hostname: str = "") -> dict:
    """
    Heuristic end-host classification (not 100% accurate).
    TTL hints: Windows ~128, Linux/Android/iOS ~64, many network devices ~255.
    """
    hn = (hostname or "").lower()
    if any(x in hn for x in ("switch", "sw-", "catalyst", "nexus", "router", "rt-", "ap-", "wlc")):
        return {"device_class": "network", "device_label": "Likely switch/router/AP", "confidence": "medium"}
    if any(x in hn for x in ("iphone", "android", "galaxy", "pixel", "mobile", "phone")):
        return {"device_class": "mobile", "device_label": "Likely mobile phone", "confidence": "medium"}
    if any(x in hn for x in ("desktop", "laptop", "pc-", "win-", "workstation")):
        return {"device_class": "pc", "device_label": "Likely PC / workstation", "confidence": "medium"}

    if ttl is None:
        return {"device_class": "unknown", "device_label": "Unknown (alive)", "confidence": "low"}
    if 120 <= ttl <= 128:
        return {"device_class": "pc", "device_label": "Likely Windows PC", "confidence": "medium"}
    if 60 <= ttl <= 64:
        return {"device_class": "mobile_or_linux", "device_label": "Likely mobile / Linux / Mac", "confidence": "medium"}
    if ttl >= 250:
        return {"device_class": "network", "device_label": "Likely network device", "confidence": "low"}
    return {"device_class": "unknown", "device_label": f"Unknown (TTL={ttl})", "confidence": "low"}


def _ping_host(target: str, count: int = 2, timeout_sec: float = 2.0, resolve_name: bool = True) -> dict:
    """ICMP ping using system ping (Windows / Linux) + TTL-based device hint."""
    import platform
    import re
    import socket
    import subprocess
    import time

    target = target.strip()
    if not target or any(c in target for c in (";", "|", "&", "`", "\n", " ")):
        return {"target": target, "alive": False, "error": "Invalid target", "rtt_ms": None, "ttl": None}

    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", str(max(1, min(count, 4))), "-w", str(int(timeout_sec * 1000)), target]
        else:
            cmd = ["ping", "-c", str(max(1, min(count, 4))), "-W", str(max(1, int(timeout_sec))), target]

        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec * count + 5)
        elapsed = (time.time() - t0) * 1000
        out = (proc.stdout or "") + (proc.stderr or "")
        # Windows returns exit code 0 even for "Destination host unreachable"
        # replies from a gateway; a real echo reply always carries a TTL.
        alive = proc.returncode == 0 and bool(re.search(r"\bTTL[=:]\d+", out, re.I))

        rtt = None
        m = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", out, re.I)
        if m:
            rtt = float(m.group(1))
        elif alive:
            rtt = round(elapsed / max(count, 1), 1)

        ttl = None
        tm = re.search(r"\bTTL[=:](\d+)", out, re.I)
        if tm:
            ttl = int(tm.group(1))

        hostname = ""
        if alive and resolve_name:
            try:
                hostname = socket.getfqdn(target)
                if hostname == target:
                    hostname = ""
            except Exception:
                hostname = ""

        guess = _guess_device_type(ttl, hostname) if alive else {
            "device_class": "down", "device_label": "No reply", "confidence": "high"
        }

        return {
            "target": target,
            "alive": alive,
            "rtt_ms": rtt,
            "ttl": ttl,
            "hostname": hostname,
            "device_class": guess["device_class"],
            "device_label": guess["device_label"],
            "confidence": guess["confidence"],
            "error": None if alive else "Request timed out or host unreachable",
        }
    except subprocess.TimeoutExpired:
        return {"target": target, "alive": False, "rtt_ms": None, "ttl": None, "error": "Ping timed out",
                "device_class": "down", "device_label": "No reply", "confidence": "high"}
    except Exception as e:
        return {"target": target, "alive": False, "rtt_ms": None, "ttl": None, "error": str(e),
                "device_class": "down", "device_label": "Error", "confidence": "high"}


@app.post("/api/ping")
def api_ping(req: PingRequest):
    """Ping a single host from the PC running the dashboard."""
    result = _ping_host(req.target, count=req.count, resolve_name=req.resolve)
    return {"success": True, **result}


@app.post("/api/scan")
def api_scan(req: ScanRequest):
    """
    Simple IP scanner.
    Supports:
      - CIDR: 192.168.4.0/24 (first 256 hosts are scanned; larger nets are reported as truncated)
      - Range: 192.168.4.1-50
      - Single IP / hostname
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    subnet = req.subnet.strip()
    timeout = min(max(req.timeout, 0.2), 5.0)
    hosts = []
    total_hosts = 0  # size of the requested range before the cap

    try:
        if "/" in subnet:
            net = ipaddress.ip_network(subnet, strict=False)
            if net.version != 4:
                raise ValueError("only IPv4 is supported")
            total_hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
            # islice over the lazy iterator: a /8 no longer builds a 16-million item list
            hosts = [str(h) for h in islice(net.hosts(), MAX_SCAN_HOSTS)]
        else:
            m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$", subnet)
            if m:
                base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
                ipaddress.ip_address(f"{base}.0")  # validates the first three octets
                if start > end:
                    start, end = end, start
                if end > 255:
                    raise ValueError("last octet must be between 0 and 255")
                total_hosts = end - start + 1
                hosts = [f"{base}.{i}" for i in range(start, min(end, start + MAX_SCAN_HOSTS - 1) + 1)]
            else:
                hosts = [subnet]  # single IP / hostname
                total_hosts = 1
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Invalid subnet/range: {e}"}, status_code=400)

    if not hosts:
        return JSONResponse({"success": False, "error": "No hosts to scan"}, status_code=400)

    alive = []
    dead_count = 0

    def one(ip):
        return _ping_host(ip, count=1, timeout_sec=timeout)

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(one, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            r = fut.result()
            if r.get("alive"):
                alive.append(r)
            else:
                dead_count += 1

    def ip_sort_key(item):
        try:
            return (0, int(ipaddress.ip_address(item["target"])))
        except ValueError:
            return (1, item["target"])  # hostnames sort last instead of crashing

    alive.sort(key=ip_sort_key)
    return {
        "success": True,
        "subnet": subnet,
        "scanned": len(hosts),
        "total_hosts": total_hosts,
        "truncated": total_hosts > len(hosts),
        "max_hosts": MAX_SCAN_HOSTS,
        "alive_count": len(alive),
        "dead_count": dead_count,
        "alive": alive,
    }


# ------------------------------------------------------------------
# API – Enable SSH on a switch you are connected to by console cable
# ------------------------------------------------------------------

class SshSetupRequest(BaseModel):
    # how we are connected (console only)
    connection_type: str = "console"
    serial_port: Optional[str] = None
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    baudrate: int = 9600
    port: int = 22
    # what to configure on the switch
    hostname: Optional[str] = None
    domain: str = ""
    ssh_user: str = ""
    ssh_password: str = ""
    ssh_privilege: int = 15
    enable_secret: Optional[str] = None
    key_bits: int = 2048
    vty_range: str = "0 15"
    mgmt_interface: Optional[str] = None
    mgmt_ip: Optional[str] = None
    mgmt_mask: Optional[str] = None
    gateway: Optional[str] = None
    save: bool = True


def validate_ssh_setup(r: "SshSetupRequest") -> Optional[str]:
    """Return an error message, or None if the request is usable."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}\.[A-Za-z]{2,}|[A-Za-z0-9][A-Za-z0-9-]{0,62}", (r.domain or "").strip()):
        return "Domain name is required (e.g. lab.local). RSA keys cannot be created without one."
    if r.hostname and not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", r.hostname.strip()):
        return "Hostname may only contain letters, digits and '-', and must start with a letter."
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", (r.ssh_user or "").strip()):
        return "SSH username is required (letters, digits, . _ - only)."
    for label, val in (("SSH password", r.ssh_password), ("Enable secret", r.enable_secret)):
        if label == "Enable secret" and not val:
            continue
        # '?' triggers CLI help on a live console and spaces would split the argument
        if not val or len(val) < 4 or re.search(r"[\s?]", val):
            return f"{label} must be at least 4 characters with no spaces or '?'."
    if not 1 <= int(r.ssh_privilege) <= 15:
        return "Privilege level must be 1–15."
    if int(r.key_bits) not in (1024, 2048, 4096):
        return "RSA key size must be 1024, 2048 or 4096."
    if not re.fullmatch(r"\d{1,2}( \d{1,2})?", (r.vty_range or "").strip()):
        return "VTY range must look like '0 15'."
    mgmt = [r.mgmt_interface, r.mgmt_ip, r.mgmt_mask]
    if any(mgmt):
        if not all(mgmt):
            return "Management IP needs interface, IP address and subnet mask together (or leave all three empty)."
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9/.\-]*\s?\d[\d/.]*", r.mgmt_interface.strip()):
            return "Management interface looks invalid (e.g. Vlan1 or GigabitEthernet0/0)."
        try:
            ipaddress.IPv4Address(r.mgmt_ip.strip())
            ipaddress.IPv4Network(f"0.0.0.0/{r.mgmt_mask.strip()}")
        except ValueError:
            return "Management IP address or subnet mask is invalid."
    if r.gateway:
        try:
            ipaddress.IPv4Address(r.gateway.strip())
        except ValueError:
            return "Default gateway is not a valid IPv4 address."
    return None


def build_ssh_commands(r: "SshSetupRequest", mask_secrets: bool = False) -> dict:
    """
    The plan is split in three because RSA key generation is interactive and must
    happen after the domain-name/hostname exist and before 'ip ssh version 2'.
    """
    pw = (lambda s: "********") if mask_secrets else (lambda s: s)
    stage1 = []
    if r.mgmt_interface:
        stage1 += [f"interface {r.mgmt_interface.strip()}",
                   f"ip address {r.mgmt_ip.strip()} {r.mgmt_mask.strip()}", "no shutdown", "exit"]
    if r.gateway:
        stage1.append(f"ip default-gateway {r.gateway.strip()}")
    stage1.append(f"ip domain-name {r.domain.strip()}")
    stage1.append(f"username {r.ssh_user.strip()} privilege {int(r.ssh_privilege)} secret {pw(r.ssh_password)}")
    if r.enable_secret:
        stage1.append(f"enable secret {pw(r.enable_secret)}")
    if r.hostname:
        stage1.append(f"hostname {r.hostname.strip()}")  # last: it changes the prompt
    keygen = f"crypto key generate rsa modulus {int(r.key_bits)}"
    stage2 = [
        "ip ssh version 2",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
        f"line vty {r.vty_range.strip()}",
        "login local",
        "transport input ssh",
        "exec-timeout 10 0",
        "exit",
    ]
    return {"stage1": stage1, "keygen": keygen, "stage2": stage2}


def _mask_text(text: str, secrets: list) -> str:
    """The switch echoes typed commands, so scrub passwords from anything we return."""
    for s in secrets:
        if s:
            text = text.replace(s, "********")
    return text


def run_ssh_setup(conn, r: "SshSetupRequest") -> dict:
    plan = build_ssh_commands(r)
    shown = build_ssh_commands(r, mask_secrets=True)
    secrets = [r.ssh_password, r.enable_secret]
    log = []

    def fail(where: str, errors: list):
        detail = "\n".join(f"  • {e['message']}" + (f"   (near: {e['command']})" if e["command"] else "") for e in errors)
        return {"success": False, "saved": False, "errors": errors,
                "error": f"SSH setup stopped at the {where} step – the switch rejected a command.\n{detail}\n\n"
                         f"--- switch output ---\n{_mask_text(chr(10).join(log), secrets)}"}

    # 1) domain, user, (mgmt IP, enable secret, hostname)
    out = conn.send_config_set(plan["stage1"]); log.append(out)
    try:
        conn.set_base_prompt()  # hostname may have changed
    except Exception:
        pass
    errs = find_ios_errors(out)
    if errs:
        return fail("base configuration", errs)

    # 2) RSA keys – interactive, can take a minute or more on older hardware
    conn.config_mode()
    out = conn.send_command_timing(plan["keygen"], read_timeout=300, last_read=15.0)
    for _ in range(3):  # "Do you really want to replace them? [yes/no]"
        if "[yes/no]" in out.lower():
            out += conn.send_command_timing("yes", read_timeout=300, last_read=15.0)
    log.append(out)
    conn.exit_config_mode()
    errs = find_ios_errors(out)
    if errs:
        return fail("RSA key generation", errs)

    # 3) SSH v2 + VTY lines
    out = conn.send_config_set(plan["stage2"]); log.append(out)
    errs = find_ios_errors(out)
    if errs:
        return fail("SSH / VTY", errs)

    status = str(run_cmd(conn, "show ip ssh", read_timeout=60))
    enabled = bool(re.search(r"SSH\s+Enabled", status, re.I))
    saved = False
    if r.save and enabled:
        log.append("--- save ---\n" + str(conn.save_config()))
        saved = True
    ip_hint = f" Connect with:  ssh {r.ssh_user.strip()}@{r.mgmt_ip.strip()}" if r.mgmt_ip else ""
    return {
        "success": True,
        "ssh_enabled": enabled,
        "saved": saved,
        "commands": shown["stage1"] + [shown["keygen"]] + shown["stage2"],
        "ssh_status": status.strip(),
        "output": _mask_text("\n".join(log), secrets),
        "message": ("SSH is enabled." if enabled else "Commands were accepted but 'show ip ssh' does not report SSH Enabled – check the status below.") + ip_hint,
    }


@app.post("/api/ssh-setup/preview")
def ssh_setup_preview(req: SshSetupRequest):
    """Show exactly what would be sent. Does NOT touch the switch."""
    err = validate_ssh_setup(req)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    plan = build_ssh_commands(req, mask_secrets=True)
    return {"success": True, "commands": plan["stage1"] + [plan["keygen"]] + plan["stage2"]}


@app.post("/api/ssh-setup")
def ssh_setup(req: SshSetupRequest):
    if (req.connection_type or "").lower() not in ("console", "serial"):
        return JSONResponse({"success": False, "error": "SSH setup is for console (serial cable) connections. Switch Connection type to Console."}, status_code=400)
    err = validate_ssh_setup(req)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    conn, cerr = safe_connect(req.dict())
    if cerr:
        return JSONResponse({"success": False, "error": cerr}, status_code=400)
    try:
        priv = privileged_error(conn)
        if priv:
            return JSONResponse({"success": False, "error": priv}, status_code=403)
        result = run_ssh_setup(conn, req)
        return result if result["success"] else JSONResponse(result, status_code=422)
    except Exception as e:
        return JSONResponse({"success": False, "error": _mask_text(str(e), [req.ssh_password, req.enable_secret])}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# API – Quick templates
# ------------------------------------------------------------------



# ------------------------------------------------------------------
# Login, sessions, users
# ------------------------------------------------------------------
auth.ensure_admin()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    status, user, _ = auth.authorize(request.url.path, request.cookies.get("session"))
    if status == 302:
        return RedirectResponse("/login", status_code=302)
    if status in (401, 403):
        msg = "Please log in" if status == 401 else "You do not have permission for this action"
        return JSONResponse({"success": False, "error": msg}, status_code=status)
    request.state.user = user
    return await call_next(request)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserUpsert(BaseModel):
    username: str
    password: Optional[str] = None
    role: str = "user"
    permissions: List[str] = []
    disabled: bool = False


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    try:
        return templates.TemplateResponse(request, "login.html")
    except TypeError:
        return templates.TemplateResponse("login.html", {"request": request})


@app.post("/api/auth/login")
def api_login(body: LoginRequest, request: Request):
    ip = request.client.host if request.client else ""
    token, err, status = auth.login(body.username.strip(), body.password, ip)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=status)
    resp = JSONResponse({"success": True})
    resp.set_cookie("session", token, max_age=auth.SESSION_TTL, httponly=True, samesite="lax")
    return resp


@app.post("/api/auth/logout")
def api_logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie("session")
    return resp


@app.get("/api/auth/me")
def api_me(request: Request):
    name = request.state.user
    u = auth._load()[name]
    return {"success": True, "username": name, "role": u["role"], "permissions": sorted(auth.perms_of(name)),
            "catalog": auth.PERMISSIONS}


@app.get("/api/users")
def api_users():
    return {"success": True, "users": auth.list_users(), "catalog": auth.PERMISSIONS}


@app.post("/api/users")
def api_upsert_user(body: UserUpsert):
    err = auth.upsert_user(body.username.strip(), body.password or "", body.role, body.permissions, body.disabled)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    return {"success": True}


@app.delete("/api/users/{name}")
def api_delete_user(name: str, request: Request):
    err = auth.delete_user(name, request.state.user)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    return {"success": True}


# ------------------------------------------------------------------
# Routing table (parsed 'show ip route')
# ------------------------------------------------------------------
_ROUTE_RE = re.compile(r"^\s*([A-Za-z*+%]{1,3})(?:\s+(IA|E1|E2|N1|N2|L1|L2|ia|su))?\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?\s*(.*)$")
_CONT_RE = re.compile(r"^\s+\[(\d+)/(\d+)\]\s+via\s+(\d+\.\d+\.\d+\.\d+)(.*)$")
_PARENT_RE = re.compile(r"^\s*\d+\.\d+\.\d+\.\d+(?:/(\d+))?\s+is\s+(?:variably\s+)?subnetted")
_IFACE_RE = re.compile(r",\s*([A-Za-z][A-Za-z\-]*\d[\d/.:]*)\s*$")
ROUTE_CODES = {"C": "connected", "L": "local", "S": "static", "O": "ospf", "D": "eigrp", "B": "bgp",
               "R": "rip", "i": "isis", "EX": "eigrp"}


def parse_ip_route(text: str) -> dict:
    routes, parent_len = [], None
    for line in (text or "").splitlines():
        p = _PARENT_RE.match(line)
        if p:
            parent_len = p.group(1)
            continue
        c = _CONT_RE.match(line)
        if c and routes:  # extra equal-cost next hop for the previous prefix
            r = dict(routes[-1])
            r.update(ad=int(c.group(1)), metric=int(c.group(2)), via=c.group(3))
            i = _IFACE_RE.search(c.group(4))
            r["interface"] = i.group(1) if i else None
            routes.append(r)
            continue
        m = _ROUTE_RE.match(line)
        if not m:
            continue
        code, sub, net, plen, rest = m.groups()
        plen = plen or parent_len
        mm, via, i = re.search(r"\[(\d+)/(\d+)\]", rest), re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", rest), _IFACE_RE.search(rest)
        routes.append({
            "code": (code + (" " + sub if sub else "")).strip(),
            "protocol": ROUTE_CODES.get(code.rstrip("*+%"), "other"),
            "prefix": f"{net}/{plen}" if plen else net,
            "ad": int(mm.group(1)) if mm else 0, "metric": int(mm.group(2)) if mm else 0,
            "via": via.group(1) if via else None, "interface": i.group(1) if i else None,
            "default": code.endswith("*"),
        })
    summary = {}
    for r in routes:
        summary[r["protocol"]] = summary.get(r["protocol"], 0) + 1
    gw = re.search(r"Gateway of last resort is (\S+)", text or "")
    return {"routes": routes, "summary": summary, "gateway": gw.group(1) if gw and gw.group(1) != "not" else None}


@app.post("/api/routing/table")
def routing_table(creds: DeviceCredentials):
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        raw = str(run_cmd(conn, "show ip route", read_timeout=120))
        return {"success": True, "raw": raw, **parse_ip_route(raw)}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# Template library ({placeholders} are filled in by the browser)
# ------------------------------------------------------------------
def _t(cat, name, desc, params, cmds):
    return {"category": cat, "name": name, "description": desc, "commands": cmds,
            "params": [{"key": k, "label": l, "default": d} for k, l, d in params]}


TEMPLATE_LIBRARY = [
    # ---- VLAN
    _t("VLAN", "Create a VLAN", "Add one VLAN with a name", [("id", "VLAN ID", "10"), ("name", "Name", "USERS")], ["vlan {id}", "name {name}", "exit"]),
    _t("VLAN", "Standard VLAN plan", "Data, voice, management and native VLANs", [], ["vlan 10", "name DATA", "vlan 20", "name VOICE", "vlan 30", "name MGMT", "vlan 99", "name NATIVE", "exit"]),
    _t("VLAN", "Delete a VLAN", "Remove a VLAN from the database", [("id", "VLAN ID", "10")], ["no vlan {id}"]),
    _t("VLAN", "Access port in a VLAN", "Single access port with PortFast", [("port", "Port", "Gi1/0/1"), ("vlan", "VLAN", "10")], ["interface {port}", "switchport mode access", "switchport access vlan {vlan}", "spanning-tree portfast", "no shutdown", "exit"]),
    _t("VLAN", "Access ports (range)", "Many ports into one VLAN", [("range", "Port range", "Gi1/0/1 - 24"), ("vlan", "VLAN", "10")], ["interface range {range}", "switchport mode access", "switchport access vlan {vlan}", "spanning-tree portfast", "exit"]),
    _t("VLAN", "Voice + data port", "IP phone with a PC behind it", [("port", "Port", "Gi1/0/2"), ("data", "Data VLAN", "10"), ("voice", "Voice VLAN", "20")], ["interface {port}", "switchport mode access", "switchport access vlan {data}", "switchport voice vlan {voice}", "spanning-tree portfast", "exit"]),
    _t("VLAN", "Trunk port", "802.1Q trunk with allowed and native VLANs", [("port", "Port", "Gi1/0/24"), ("native", "Native VLAN", "99"), ("allowed", "Allowed VLANs", "10,20,30,99")], ["interface {port}", "switchport mode trunk", "switchport trunk native vlan {native}", "switchport trunk allowed vlan {allowed}", "no shutdown", "exit"]),
    _t("VLAN", "Add VLANs to a trunk", "Extend the allowed list without replacing it", [("port", "Port", "Gi1/0/24"), ("vlans", "VLANs to add", "40,50")], ["interface {port}", "switchport trunk allowed vlan add {vlans}", "exit"]),
    _t("VLAN", "VTP transparent", "Stop VTP from changing your VLAN database", [], ["vtp mode transparent"]),
    _t("VLAN", "VLAN interface (SVI)", "Layer 3 gateway for a VLAN", [("vlan", "VLAN", "10"), ("ip", "IP address", "192.168.10.1"), ("mask", "Mask", "255.255.255.0")], ["interface vlan {vlan}", "ip address {ip} {mask}", "no shutdown", "exit"]),
    # ---- Interfaces
    _t("Interface", "Shut down a port", "Administratively disable", [("port", "Port", "Gi1/0/5")], ["interface {port}", "shutdown", "exit"]),
    _t("Interface", "Enable a port", "Bring a port back up", [("port", "Port", "Gi1/0/5")], ["interface {port}", "no shutdown", "exit"]),
    _t("Interface", "Port description", "Label what is connected", [("port", "Port", "Gi1/0/1"), ("text", "Description", "PC-Reception")], ["interface {port}", "description {text}", "exit"]),
    _t("Interface", "Fixed speed and duplex", "Hard-set a port that will not auto-negotiate", [("port", "Port", "Gi1/0/1"), ("speed", "Speed", "100")], ["interface {port}", "speed {speed}", "duplex full", "exit"]),
    _t("Interface", "Port security", "Limit MACs per port and restrict on violation", [("port", "Port", "Gi1/0/1"), ("max", "Max MACs", "2")], ["interface {port}", "switchport mode access", "switchport port-security", "switchport port-security maximum {max}", "switchport port-security violation restrict", "switchport port-security mac-address sticky", "exit"]),
    _t("Interface", "BPDU guard", "Protect a PortFast port from rogue switches", [("port", "Port", "Gi1/0/1")], ["interface {port}", "spanning-tree portfast", "spanning-tree bpduguard enable", "exit"]),
    _t("Interface", "Err-disable auto recovery", "Re-enable ports that were shut by a violation", [("secs", "Seconds", "300")], ["errdisable recovery cause bpduguard", "errdisable recovery cause psecure-violation", "errdisable recovery interval {secs}"]),
    _t("Interface", "Disable unused ports", "Shut ports and park them in an unused VLAN", [("range", "Port range", "Gi1/0/10 - 20"), ("vlan", "Parking VLAN", "999")], ["interface range {range}", "switchport access vlan {vlan}", "shutdown", "exit"]),
    # ---- Switching
    _t("Switching", "Rapid PVST+", "Faster spanning-tree convergence", [], ["spanning-tree mode rapid-pvst"]),
    _t("Switching", "Make this the STP root", "Primary root bridge for a VLAN", [("vlan", "VLAN", "10")], ["spanning-tree vlan {vlan} root primary"]),
    _t("Switching", "LACP EtherChannel", "Bundle ports into a trunked port-channel", [("ports", "Member ports", "Gi1/0/23 - 24"), ("num", "Channel #", "1")], ["interface range {ports}", "channel-group {num} mode active", "exit", "interface port-channel {num}", "switchport mode trunk", "exit"]),
    _t("Switching", "DHCP snooping", "Only trusted uplinks may answer DHCP", [("vlan", "VLAN", "10"), ("uplink", "Trusted port", "Gi1/0/24")], ["ip dhcp snooping", "ip dhcp snooping vlan {vlan}", "interface {uplink}", "ip dhcp snooping trust", "exit"]),
    _t("Switching", "Storm control", "Limit broadcast traffic on a port", [("port", "Port", "Gi1/0/1"), ("level", "Level %", "20")], ["interface {port}", "storm-control broadcast level {level}", "exit"]),
    _t("Switching", "CDP and LLDP", "Neighbor discovery", [], ["cdp run", "lldp run"]),
    # ---- Routing
    _t("Routing", "Enable IP routing", "Turn a Layer 3 switch into a router", [], ["ip routing"]),
    _t("Routing", "Static route", "Route to a network via a next hop", [("net", "Network", "10.1.1.0"), ("mask", "Mask", "255.255.255.0"), ("nh", "Next hop", "192.168.1.2")], ["ip route {net} {mask} {nh}"]),
    _t("Routing", "Default route", "Send unknown traffic to a gateway", [("nh", "Next hop", "192.168.1.1")], ["ip route 0.0.0.0 0.0.0.0 {nh}"]),
    _t("Routing", "Floating static route", "Backup route with a higher distance", [("net", "Network", "10.1.1.0"), ("mask", "Mask", "255.255.255.0"), ("nh", "Next hop", "192.168.2.2"), ("ad", "Distance", "200")], ["ip route {net} {mask} {nh} {ad}"]),
    _t("Routing", "Routed port", "Turn a switch port into a Layer 3 interface", [("port", "Port", "Gi1/0/48"), ("ip", "IP address", "10.0.0.1"), ("mask", "Mask", "255.255.255.252")], ["interface {port}", "no switchport", "ip address {ip} {mask}", "no shutdown", "exit"]),
    _t("Routing", "OSPF (single area)", "Basic OSPF with one network", [("pid", "Process ID", "1"), ("rid", "Router ID", "1.1.1.1"), ("net", "Network", "192.168.10.0"), ("wc", "Wildcard", "0.0.0.255"), ("area", "Area", "0")], ["router ospf {pid}", "router-id {rid}", "network {net} {wc} area {area}", "exit"]),
    _t("Routing", "EIGRP", "Basic EIGRP with one network", [("as", "AS number", "100"), ("net", "Network", "192.168.10.0"), ("wc", "Wildcard", "0.0.0.255")], ["router eigrp {as}", "network {net} {wc}", "no auto-summary", "exit"]),
    _t("Routing", "HSRP gateway", "First-hop redundancy on a VLAN interface", [("vlan", "VLAN", "10"), ("grp", "Group", "10"), ("vip", "Virtual IP", "192.168.10.254"), ("prio", "Priority", "110")], ["interface vlan {vlan}", "standby {grp} ip {vip}", "standby {grp} priority {prio}", "standby {grp} preempt", "exit"]),
    # ---- Security
    _t("Security", "Local admin user", "Privilege-15 account", [("user", "Username", "admin"), ("pw", "Password", "ChangeMe123")], ["username {user} privilege 15 secret {pw}"]),
    _t("Security", "SSH-only VTY lines", "Needs SSH keys first (see Enable SSH)", [], ["ip ssh version 2", "line vty 0 15", "login local", "transport input ssh", "exec-timeout 10 0", "exit"]),
    _t("Security", "Enable secret + encryption", "Protect privileged mode", [("secret", "Enable secret", "ChangeMe123")], ["enable secret {secret}", "service password-encryption"]),
    _t("Security", "Login banner", "Legal notice shown before login", [("text", "Banner text", "Authorized access only")], ["banner motd ^{text}^"]),
    _t("Security", "Extended ACL for a service", "Permit one service from a subnet, deny the rest", [("name", "ACL name", "ALLOW-WEB"), ("src", "Source network", "192.168.10.0"), ("wc", "Wildcard", "0.0.0.255"), ("port", "TCP port", "443")], ["ip access-list extended {name}", "permit tcp {src} {wc} any eq {port}", "deny ip any any log", "exit"]),
    _t("Security", "Restrict VTY to a subnet", "Only management hosts may log in", [("net", "Network", "192.168.1.0"), ("wc", "Wildcard", "0.0.0.255")], ["ip access-list standard VTY-ACCESS", "permit {net} {wc}", "exit", "line vty 0 15", "access-class VTY-ACCESS in", "exit"]),
    # ---- System
    _t("System", "Basic switch setup", "Hostname, domain, NTP, logging", [("host", "Hostname", "SW1"), ("domain", "Domain", "lab.local"), ("ntp", "NTP server", "pool.ntp.org")], ["hostname {host}", "ip domain-name {domain}", "no ip domain-lookup", "service timestamps log datetime msec", "ntp server {ntp}"]),
    _t("System", "Management interface", "IP on a VLAN plus default gateway", [("vlan", "VLAN", "1"), ("ip", "IP address", "192.168.1.2"), ("mask", "Mask", "255.255.255.0"), ("gw", "Gateway", "192.168.1.1")], ["interface vlan {vlan}", "ip address {ip} {mask}", "no shutdown", "exit", "ip default-gateway {gw}"]),
    _t("System", "Syslog server", "Send logs to a collector", [("ip", "Server IP", "192.168.1.50")], ["logging host {ip}", "logging trap informational"]),
    _t("System", "SNMPv2c (read-only)", "Monitoring access", [("comm", "Community", "public-ro"), ("loc", "Location", "Server room")], ["snmp-server community {comm} RO", "snmp-server location {loc}"]),
    _t("System", "Timezone", "Clock timezone", [("tz", "Zone name", "PKT"), ("off", "Offset hours", "5")], ["clock timezone {tz} {off}"]),
    _t("System", "Save configuration", "Copy running-config to startup-config", [], ["do write memory"]),
]



def _s(sid, name, glyph, tagline, tags, params, cmds):
    return {"id": sid, "name": name, "glyph": glyph, "tagline": tagline, "tags": tags, "commands": cmds,
            "params": [{"key": k, "label": l, "default": d} for k, l, d in params]}


SWITCH_TEMPLATES = [
    _s("access", "Access switch", "▦", "Day-one config for a 24/48-port user switch", ["VLANs", "PortFast", "SSH", "Trunk uplink"],
       [("host", "Hostname", "SW-ACCESS-1"), ("domain", "Domain", "lab.local"), ("user", "Admin user", "admin"), ("pw", "Admin password", "ChangeMe123"),
        ("dvlan", "Data VLAN", "10"), ("vvlan", "Voice VLAN", "20"), ("mvlan", "Management VLAN", "99"),
        ("mip", "Mgmt IP", "192.168.99.11"), ("mmask", "Mgmt mask", "255.255.255.0"), ("gw", "Gateway", "192.168.99.1"),
        ("ports", "User ports", "Gi1/0/1 - 47"), ("uplink", "Uplink port", "Gi1/0/48")],
       ["hostname {host}", "ip domain-name {domain}", "no ip domain-lookup", "service password-encryption",
        "username {user} privilege 15 secret {pw}",
        "vlan {dvlan}", "name DATA", "vlan {vvlan}", "name VOICE", "vlan {mvlan}", "name MGMT", "exit",
        "spanning-tree mode rapid-pvst",
        "interface range {ports}", "switchport mode access", "switchport access vlan {dvlan}", "switchport voice vlan {vvlan}",
        "spanning-tree portfast", "spanning-tree bpduguard enable", "storm-control broadcast level 20", "exit",
        "interface {uplink}", "description UPLINK", "switchport mode trunk", "switchport trunk allowed vlan {dvlan},{vvlan},{mvlan}", "exit",
        "interface vlan {mvlan}", "ip address {mip} {mmask}", "no shutdown", "exit", "ip default-gateway {gw}",
        "ip ssh version 2", "line vty 0 15", "login local", "transport input ssh", "exec-timeout 10 0", "exit",
        "banner motd ^Authorized access only^"]),
    _s("distribution", "Distribution / L3 switch", "⇉", "Inter-VLAN routing, HSRP and OSPF for two VLANs", ["Layer 3", "HSRP", "OSPF", "STP root"],
       [("host", "Hostname", "SW-DIST-1"), ("domain", "Domain", "lab.local"), ("rid", "Router ID", "1.1.1.1"),
        ("avlan", "VLAN A", "10"), ("aip", "VLAN A switch IP", "192.168.10.2"), ("avip", "VLAN A virtual IP", "192.168.10.1"),
        ("bvlan", "VLAN B", "20"), ("bip", "VLAN B switch IP", "192.168.20.2"), ("bvip", "VLAN B virtual IP", "192.168.20.1"),
        ("mask", "Mask", "255.255.255.0"), ("prio", "HSRP priority", "110"), ("trunk", "Trunk to access", "Gi1/0/1"),
        ("onet", "OSPF network", "192.168.0.0"), ("owc", "OSPF wildcard", "0.0.255.255")],
       ["hostname {host}", "ip domain-name {domain}", "no ip domain-lookup", "ip routing", "spanning-tree mode rapid-pvst",
        "spanning-tree vlan {avlan},{bvlan} root primary",
        "vlan {avlan}", "name VLAN-A", "vlan {bvlan}", "name VLAN-B", "exit",
        "interface vlan {avlan}", "ip address {aip} {mask}", "standby {avlan} ip {avip}", "standby {avlan} priority {prio}", "standby {avlan} preempt", "no shutdown", "exit",
        "interface vlan {bvlan}", "ip address {bip} {mask}", "standby {bvlan} ip {bvip}", "standby {bvlan} priority {prio}", "standby {bvlan} preempt", "no shutdown", "exit",
        "interface {trunk}", "switchport mode trunk", "switchport trunk allowed vlan {avlan},{bvlan}", "exit",
        "router ospf 1", "router-id {rid}", "network {onet} {owc} area 0", "passive-interface default", "exit"]),
    _s("branch", "Branch office switch", "⌂", "Small site: user, voice and guest VLANs with a routed uplink", ["Branch", "Guest VLAN", "NTP"],
       [("host", "Hostname", "BR-SW1"), ("domain", "Domain", "branch.local"), ("user", "Admin user", "admin"), ("pw", "Admin password", "ChangeMe123"),
        ("vlan", "User VLAN", "10"), ("guest", "Guest VLAN", "50"), ("ip", "Switch IP", "10.20.1.2"), ("mask", "Mask", "255.255.255.0"),
        ("gw", "Gateway", "10.20.1.1"), ("ntp", "NTP server", "pool.ntp.org"), ("ports", "User ports", "Gi1/0/1 - 20"), ("gports", "Guest ports", "Gi1/0/21 - 22")],
       ["hostname {host}", "ip domain-name {domain}", "no ip domain-lookup", "username {user} privilege 15 secret {pw}",
        "vlan {vlan}", "name USERS", "vlan {guest}", "name GUEST", "exit",
        "interface range {ports}", "switchport mode access", "switchport access vlan {vlan}", "spanning-tree portfast", "exit",
        "interface range {gports}", "switchport mode access", "switchport access vlan {guest}", "spanning-tree portfast", "exit",
        "interface vlan {vlan}", "ip address {ip} {mask}", "no shutdown", "exit", "ip default-gateway {gw}",
        "ntp server {ntp}", "service timestamps log datetime msec", "ip ssh version 2", "line vty 0 15", "login local", "transport input ssh", "exit"]),
    _s("lab", "Lab / training switch", "⚗", "Minimal and forgiving: handy for classes and practice", ["Lab", "Minimal"],
       [("host", "Hostname", "LAB-SW1"), ("secret", "Enable secret", "cisco123"), ("user", "Username", "student"), ("pw", "Password", "student123")],
       ["hostname {host}", "no ip domain-lookup", "enable secret {secret}", "username {user} privilege 15 secret {pw}",
        "line con 0", "logging synchronous", "exec-timeout 0 0", "exit",
        "line vty 0 15", "login local", "transport input all", "logging synchronous", "exit",
        "spanning-tree mode rapid-pvst", "banner motd ^Training switch - changes are expected^"]),
    _s("hardened", "Secure baseline", "⛨", "Hardening for any switch: logging, lockouts, VTY limits", ["Security", "Hardening", "Logging"],
       [("secret", "Enable secret", "ChangeMe123"), ("net", "Management network", "192.168.1.0"), ("wc", "Wildcard", "0.0.0.255"),
        ("syslog", "Syslog server", "192.168.1.50"), ("ports", "Unused ports", "Gi1/0/10 - 20"), ("park", "Parking VLAN", "999")],
       ["service password-encryption", "enable secret {secret}", "no ip http server", "no ip http secure-server",
        "ip ssh version 2", "ip ssh time-out 60", "ip ssh authentication-retries 3", "login block-for 120 attempts 5 within 60",
        "ip access-list standard VTY-ACCESS", "permit {net} {wc}", "exit",
        "line vty 0 15", "access-class VTY-ACCESS in", "login local", "transport input ssh", "exec-timeout 10 0", "exit",
        "logging buffered 16384", "logging host {syslog}", "logging trap informational", "service timestamps log datetime msec",
        "errdisable recovery cause bpduguard", "errdisable recovery interval 300",
        "vlan {park}", "name PARKING", "exit",
        "interface range {ports}", "switchport access vlan {park}", "shutdown", "exit",
        "banner motd ^Authorized access only. Activity is logged.^"]),
]


@app.get("/api/templates")
def get_templates():
    return {"templates": TEMPLATE_LIBRARY, "switch_templates": SWITCH_TEMPLATES}


# ------------------------------------------------------------------
# Reboot: two-step confirmation enforced on the SERVER
#   step 1  /api/reboot/request -> one-time token (60 s) + the switch's real hostname
#   step 2  /api/reboot         -> token AND the hostname typed back by the person
# ------------------------------------------------------------------
_pending_reboots: dict = {}


class RebootRequest(DeviceCredentials):
    save: bool = True
    delay_minutes: int = 0
    token: Optional[str] = None
    confirm_text: Optional[str] = None


def _target(r) -> str:
    return (r.serial_port or r.host) if r.connection_type == "console" else r.host


def do_reload(conn, save: bool, delay: int) -> dict:
    log = []
    if save:
        log.append(str(conn.save_config()))
    out = conn.send_command_timing(f"reload in {delay}" if delay else "reload", read_timeout=15)
    log.append(out)
    for _ in range(4):
        low = out.lower()
        if "[yes/no]" in low:
            reply = "no"       # saving was already handled above
        elif "confirm" in low:
            reply = ""
        else:
            break
        try:
            out = conn.send_command_timing(reply, read_timeout=10)
        except Exception:
            log.append("(connection closed by the switch: it is restarting)")
            break
        log.append(out)
    text = "\n".join(log)
    errs = find_ios_errors(text)
    if errs:
        return {"success": False, "output": text, "error": "The switch rejected the reload command: " + errs[0]["message"]}
    return {"success": True, "scheduled": bool(delay), "output": text,
            "message": (f"Reload scheduled in {delay} minute(s)." if delay else "The switch is restarting. It will be unreachable for a few minutes.")}


@app.post("/api/reboot/request")
def reboot_request(req: RebootRequest, request: Request):
    if not 0 <= req.delay_minutes <= 720:
        return JSONResponse({"success": False, "error": "Delay must be 0–720 minutes"}, status_code=400)
    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        priv = privileged_error(conn)
        if priv:
            return JSONResponse({"success": False, "error": priv}, status_code=403)
        hostname = conn.find_prompt().strip().rstrip("#>").strip()
        now = time.time()
        for k in [k for k, v in _pending_reboots.items() if v["exp"] < now]:
            _pending_reboots.pop(k, None)
        token = secrets.token_urlsafe(24)
        _pending_reboots[token] = {"user": request.state.user, "target": _target(req), "hostname": hostname,
                                   "save": req.save, "delay": req.delay_minutes, "exp": now + 60, "tries": 0}
        return {"success": True, "token": token, "hostname": hostname, "expires_in": 60, "delay_minutes": req.delay_minutes}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


@app.post("/api/reboot")
def reboot_now(req: RebootRequest, request: Request):
    p = _pending_reboots.get(req.token or "")
    if not p or p["exp"] < time.time():
        _pending_reboots.pop(req.token or "", None)
        return JSONResponse({"success": False, "error": "Confirmation expired or invalid. Start again at step 1."}, status_code=400)
    if p["user"] != request.state.user or p["target"] != _target(req):
        return JSONResponse({"success": False, "error": "This confirmation was issued for a different user or switch."}, status_code=400)
    if (req.confirm_text or "").strip() != p["hostname"]:
        p["tries"] += 1
        if p["tries"] >= 3:
            _pending_reboots.pop(req.token, None)
        return JSONResponse({"success": False, "error": "The switch name you typed does not match." + (" Too many tries: start again." if p["tries"] >= 3 else "")}, status_code=400)
    _pending_reboots.pop(req.token, None)  # single use
    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        priv = privileged_error(conn)
        if priv:
            return JSONResponse({"success": False, "error": priv}, status_code=403)
        result = do_reload(conn, p["save"], p["delay"])  # save/delay come from step 1, not step 2
        return result if result["success"] else JSONResponse(result, status_code=422)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


@app.post("/api/reboot/cancel")
def reboot_cancel(req: RebootRequest):
    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        return {"success": True, "output": conn.send_command_timing("reload cancel", read_timeout=10)}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        close_conn(conn)


# ------------------------------------------------------------------
# Bootloader ('switch:' prompt) over the console + password recovery
# ------------------------------------------------------------------
class ConsoleRequest(BaseModel):
    serial_port: Optional[str] = None
    host: str = ""
    baudrate: int = 9600
    action: str = "detect"
    image: Optional[str] = None
    confirm_text: Optional[str] = None


@app.post("/api/bootloader/action")
def bootloader_action(req: ConsoleRequest):
    port = (req.serial_port or req.host or "").strip()
    if not port:
        return JSONResponse({"success": False, "error": "Enter the serial port, e.g. COM3"}, status_code=400)
    if req.action not in bootloader.ACTIONS:
        return JSONResponse({"success": False, "error": "Unknown action"}, status_code=400)
    if req.action == "recover" and (req.confirm_text or "").strip() != "RECOVER":
        return JSONResponse({"success": False, "error": "Type RECOVER to confirm password recovery."}, status_code=400)
    try:
        ser = bootloader.open_console(port, req.baudrate)
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Cannot open {port}: {e}"}, status_code=400)
    try:
        result = bootloader.run_action(bootloader.Console(ser), req.action, req.image)
        return result if result.get("success") else JSONResponse(result, status_code=422)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
    finally:
        try:
            ser.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
