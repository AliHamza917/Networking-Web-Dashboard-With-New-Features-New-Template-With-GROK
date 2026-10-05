"""
Talk to a Cisco switch that is sitting in its bootloader (the 'switch:' prompt) over a
serial console, and finish a password recovery once it is back in IOS.
Uses raw pyserial because Netmiko cannot log in to a bootloader.
"""
import re
import time

QUIET = 0.4  # seconds of silence that count as "the switch has finished talking"
BOOTLOADER_RE = re.compile(r"(?:^|\n)[ \t]*(?:(?:switch|loader)[ \t]*:|rommon[ \t]*\d+[ \t]*>)[ \t]*$", re.I)
IOS_RE = re.compile(r"(?:^|\n)[ \t]*[\w.\-]+(?:\([\w\-/]+\))?[>#][ \t]*$")
SETUP_RE = re.compile(r"initial configuration dialog|press return to get started", re.I)
ANY_PROMPT = re.compile(r"(?:[>#?:\]])[ \t]*$")
SAFE_FLASH = re.compile(r"^flash:[\w./\-]{1,120}$")   # boot images / config file names only
ACTIONS = ("detect", "info", "boot", "recover", "finish")


def classify(text: str) -> str:
    t = (text or "").rstrip()
    if BOOTLOADER_RE.search(t):
        return "bootloader"
    if SETUP_RE.search(t) and not IOS_RE.search(t):
        return "setup_dialog"
    if IOS_RE.search(t):
        return "ios"
    return "unknown"


def open_console(port: str, baud: int = 9600):
    try:
        import serial
    except ImportError:
        raise RuntimeError("pyserial is not installed (pip install pyserial)")
    return serial.Serial(port, baud, timeout=0.1)


class Console:
    def __init__(self, ser):
        self.ser = ser

    def read(self, wait: float = 3.0, until=None) -> str:
        buf, start = "", time.time()
        last = start
        while time.time() - start < wait:
            chunk = self.ser.read(getattr(self.ser, "in_waiting", 0) or 1)
            if chunk:
                buf += chunk.decode(errors="replace")
                last = time.time()
            else:
                time.sleep(0.01)
                quiet = time.time() - last >= QUIET
                if buf and quiet and (until is None and time.time() - last >= QUIET * 4 or until is not None and until.search(buf.rstrip())):
                    break
        return buf.replace("\r", "")

    def send(self, cmd: str, wait: float = 5.0, until=ANY_PROMPT) -> str:
        self.ser.write((cmd + "\r").encode())
        return self.read(wait, until)


def parse_env(text: str) -> dict:
    return dict(re.findall(r"^([A-Z][A-Z0-9_]*)=(.*)$", text or "", re.M))


def parse_images(text: str) -> list:
    return re.findall(r"(\S+\.bin)\s*$", text or "", re.M)


def _need_bootloader(con) -> tuple:
    out = con.send("", 4, BOOTLOADER_RE)
    mode = classify(out)
    return mode, out


def run_action(con, action: str, image=None) -> dict:
    if action not in ACTIONS:
        return {"success": False, "error": f"Unknown action: {action}"}
    if action == "finish":
        return finish_recovery(con)
    mode, out = _need_bootloader(con)
    last = (out.strip().splitlines() or [""])[-1]
    if action == "detect":
        return {"success": True, "mode": mode, "prompt": last, "output": out}
    if mode != "bootloader":
        return {"success": False, "mode": mode, "error": f"The switch is not at the bootloader prompt (detected: {mode}). Power-cycle it while holding the MODE button until the 'switch:' prompt appears."}

    env = parse_env(con.send("set", 6, BOOTLOADER_RE))
    if action == "info":
        init = con.send("flash_init", 45, BOOTLOADER_RE)
        listing = con.send("dir flash:", 15, BOOTLOADER_RE)
        return {"success": True, "mode": mode, "env": env, "images": parse_images(listing), "output": f"{init}\n{listing}"}

    if action == "boot":
        cmd = "boot"
        if image:
            if not SAFE_FLASH.match(image):
                return {"success": False, "mode": mode, "error": "Image must look like flash:name.bin"}
            cmd = f"boot {image}"
        out = con.send(cmd, 15, None)
        return {"success": True, "mode": mode, "output": out, "message": "The switch is booting. Wait 2–3 minutes before connecting normally."}

    # action == "recover": rename the startup config so IOS boots without passwords
    cfg = env.get("CONFIG_FILE") or "flash:config.text"
    if not SAFE_FLASH.match(cfg):
        return {"success": False, "mode": mode, "error": f"Unexpected CONFIG_FILE value: {cfg!r}"}
    init = con.send("flash_init", 45, BOOTLOADER_RE)
    ren = con.send(f"rename {cfg} {cfg}.old", 15, BOOTLOADER_RE)
    if re.search(r"error|no such|not found|does not exist|invalid", ren, re.I):
        return {"success": False, "mode": mode, "output": f"{init}\n{ren}",
                "error": f"Could not rename {cfg}. The switch was NOT booted. Check 'Read info' for the real config file name."}
    booted = con.send("boot", 15, None)
    return {"success": True, "mode": mode, "output": f"{init}\n{ren}\n{booted}",
            "message": f"{cfg} renamed to {cfg}.old and the switch is booting with a blank config. "
                       "When IOS is up (2–3 minutes), press “Finish recovery”."}


def _step(con, cmd, replies, wait=20):
    """Send a command and answer any follow-up prompts (e.g. 'Destination filename [x]?')."""
    out = con.send(cmd, wait)
    for _ in range(4):
        for rx, rep in replies:
            if re.search(rx, out.rstrip()[-160:], re.I):
                out += con.send(rep, wait)
                break
        else:
            break
    return out


def finish_recovery(con) -> dict:
    """After the blank-config boot: skip the setup dialog, restore the old config, keep passwords open for reset."""
    log = []
    out = con.send("", 6)
    if classify(out) == "bootloader":
        return {"success": False, "mode": "bootloader", "error": "Still in the bootloader – run the recovery step first."}
    for _ in range(4):  # answer "no" to the setup dialog, then wake the prompt
        mode = classify(out)
        if mode == "ios":
            break
        out += con.send("no" if re.search(r"\[yes/no\]", out[-200:]) else "", 10)
    log.append(out)
    if classify(out) != "ios":
        return {"success": False, "mode": classify(out), "output": "\n".join(log),
                "error": "IOS prompt not reached yet. Wait for the switch to finish booting and try again."}
    if out.rstrip().endswith(">"):
        log.append(_step(con, "enable", [(r"password:", "")], 8))
    log.append(_step(con, "rename flash:config.text.old flash:config.text", [(r"destination filename \[.*\]\?$", "")]))
    copy = _step(con, "copy flash:config.text system:running-config", [(r"destination filename \[.*\]\?$", "")], 30)
    log.append(copy)
    ok = bool(re.search(r"\d+ bytes copied", copy, re.I))
    return {"success": ok, "mode": "ios", "output": "\n".join(log),
            "error": None if ok else "The old config could not be copied back – see the output.",
            "message": "Old configuration restored into running-config. NOW set a new enable secret / user password "
                       "(Templates → Security), turn ports back on with 'no shutdown' if they are down, then save with 'write memory'."}
