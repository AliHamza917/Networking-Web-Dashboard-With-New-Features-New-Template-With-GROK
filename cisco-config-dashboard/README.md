# Ali Hamza Cisco Networking Dashboard

Web + Windows desktop GUI for **Cisco IOS / IOS-XE** switches over SSH (Netmiko).

**Author:** Ali Hamza · **Contact:** alihamza51326@gmail.com  
© 2026 Ali Hamza. All rights reserved.

## Features

| Feature | Description |
|---------|-------------|
| **Port Map** | Graphical ports · trunks highlighted · click for MAC/IP |
| **Network Topology** | Interactive CDP/LLDP neighbor map |
| **Track Route** | Traceroute with visual hop map |
| **IP Scanner** | Scan subnet or IP range |
| **Switch Monitor** | Continuous multi-switch ping · saved IPs · disconnect alerts |
| **Config Push** | Multi-line CLI apply + save |
| **VLAN / Interface** | Quick helpers |
| **Backup** | Download running-config |
| **SSH Setup** | Console (serial) only: enable SSH v2 with domain, user, RSA keys and SSH-only VTY lines |
| **Routing** | Route table (parsed), route map, routing terminal, add/remove static routes, default route, OSPF network |
| **Templates** | 44 parameterised command templates (VLAN, Interface, Switching, Routing, Security, System) |
| **Users & Permissions** | Login page; admins create users and tick exactly what each may do |
| **Reboot Switch** | Two-step reboot, enforced by the server: request a one-time token, then type the switch's real name. Optional save-first and delayed reload |
| **Bootloader & Recovery** | Console only. Detects the `switch:` prompt, reads boot variables and images, boots, and runs password recovery (rename config, boot blank, restore config) |
| **Templates** | Five whole-switch templates (access, distribution/L3, branch, lab, secure baseline) plus 44 command snippets |

## Login and permissions

On first start an `admin` account is created with a random password, saved in `data/first_run_credentials.txt`
(or set `DASHBOARD_ADMIN_PASSWORD` before the first start). Delete that file after signing in, then add users
from **Admin → Users & Permissions**.

| Permission | Allows |
|---|---|
| `view` | Port map, topology, show commands, route table, templates |
| `diagnostics` | Ping, monitor, IP scanner, traceroute |
| `config` | Config push, VLANs, interfaces, routing changes, restore |
| `backup` | Download running-config backups |
| `ssh_setup` | Enable SSH through the console cable |
| `reboot` | Reboot the switch (two-step confirmation) |
| `bootloader` | Bootloader tools and password recovery over the console |

Admins have everything, including user management. Permissions are enforced on the server for every API call
(unlisted endpoints are denied), so hiding a button in the browser is never the only protection.
`data/` holds the user database and session key; keep it private and back it up. In Docker, mount it as a volume.
Sessions last 12 hours. Serve the app over HTTPS if it is reachable beyond your own machine.
| **Templates** | Ready-made config snippets |

## Quick start (Windows)

```cmd
python -m pip install -r requirements.txt
python -m pip install paramiko==2.12.0
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open: **http://127.0.0.1:8000**

Desktop: `python desktop_app.py` or `run_desktop.bat`

## Project structure

```
├── app/main.py           # FastAPI + Netmiko backend
├── templates/index.html  # Dashboard UI
├── desktop_app.py        # Desktop window (pywebview)
├── requirements.txt
├── Dockerfile
└── .github/workflows/ci.yml
```

## Security

For lab / trusted networks. Do not expose to the public internet without auth and HTTPS. Always review CLI before production pushes.

## License / rights

Proprietary to **Ali Hamza** (alihamza51326@gmail.com). Unauthorized commercial redistribution without permission is prohibited.

## Reboot and recovery notes

- A reboot needs *both* steps: the server issues a 60-second one-time token for your user and that switch, and only
  accepts it with the switch name typed back exactly. Three wrong names cancel the request.
- If the switch is at `switch:` after a physical reset, pressing **Test connection** on a Console connection opens the
  Bootloader tools automatically. Password recovery needs you to type `RECOVER`; afterwards use **Finish recovery**
  and set new passwords right away. Only one program can use a COM port at a time.
