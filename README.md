# Syslog Retention & SIEM Service

A self-hosted syslog retention and security analysis service designed to receive logs from a **Unifi Dream Machine (UDM)** and other network devices. Logs are stored locally, normalized into structured fields, and analyzed by **Claude AI** for security recommendations. A built-in web console provides an authenticated admin dashboard and a REST API allows Claude Projects to connect programmatically.

Runs on **Raspberry Pi 4/5** (recommended) or **Windows 11**.

---

## Features

- **Syslog receiver** — UDP and TCP on port 514 (RFC 3164 & RFC 5424)
- **Log normalization** — parses UDM firewall blocks, IDS/IPS alerts, DHCP, DNS, auth events, VPN, and threat management into structured fields
- **SQLite storage** — configurable retention policy and automatic daily purge
- **Claude AI analysis** — sends log data to Claude Sonnet for threat detection and security recommendations
- **REST API** — JWT and API-key authentication for web UI and Claude Projects
- **Web admin console** — dark-themed single-page dashboard for log viewing, filtering, AI analysis, user management, and API key management
- **Linux/systemd service** — runs at boot, managed through `install.sh`
- **Windows service** — runs at boot via pywin32, managed through `Setup.ps1`

---

## Platform Requirements

### Raspberry Pi 4 / Linux (Recommended)

| Requirement | Notes |
|---|---|
| Raspberry Pi OS Bookworm or Bullseye | Or any Debian-based distro |
| Python 3.10+ | Pre-installed on Raspberry Pi OS |
| Git | Installed automatically by `install.sh` |

### Windows 11

| Requirement | Notes |
|---|---|
| Windows 11 Pro or Home | |
| Python 3.10+ | From [python.org](https://python.org) — check "Add to PATH" |
| Git | From [git-scm.com](https://git-scm.com) |

---

## Installation

### 1. Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
```

---

## Installation — Raspberry Pi 4 (Recommended)

### 1. Clone the repository

```bash
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
```

### 2. Run the installer

```bash
sudo bash install.sh
```

The menu-driven installer will:

1. Install system dependencies (`python3`, `git`, `ufw`) via apt
2. Walk you through a configuration wizard (admin password, API key, ports, retention)
3. Copy files to `/opt/syslog-retention-service`
4. Create a Python virtual environment and install all dependencies
5. Register and enable a systemd service (starts at boot)
6. Open firewall ports via ufw

Select **option 1 — Install / Repair** from the menu.

### 3. Open the web console

```
http://<pi-ip-address>:8080
```

The installer prints your Pi's IP address at the end. Log in with the admin credentials you set during the wizard.

### Updating (Raspberry Pi)

```bash
sudo bash /opt/syslog-retention-service/install.sh
```

Select **option 2 — Update**, or run the standalone updater:

```bash
sudo bash /opt/syslog-retention-service/update.sh
```

---

## Installation — Windows 11

### 1. Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
```

### 2. Run the installer

From an **Administrator** PowerShell prompt:

```powershell
.\Setup.ps1
```

The menu-driven installer will:

1. Check that Python 3.10+ is installed (must be from python.org, not the Windows Store)
2. Walk you through a configuration wizard (admin password, API key, ports, retention)
3. Create a Python virtual environment and install all dependencies
4. Register and start a Windows service via pywin32
5. Add Windows Firewall rules for syslog (port 514) and the web console (port 8080)

Select **option 1 — Install / Repair** from the menu.

### 3. Open the web console

```
http://localhost:8080
```

### 4. Point your Unifi Dream Machine at this PC

In the UniFi Network controller:

1. Go to **Settings → System → Logging**
2. Enable **Remote Syslog**
3. Set the **Syslog Server IP** to this PC's local IP address
4. Set the **Port** to `514`
5. Save

### 5. Open the web console

```
http://localhost:8080
```

Log in with the `ADMIN_USERNAME` and `ADMIN_PASSWORD` you set in `.env`.

---

## Updating

To pull the latest code and restart the service, run `Setup.ps1` as Administrator and select **option 2 — Update**, or run the standalone updater directly:

```powershell
.\update.ps1
```

The updater will:
- Pull the latest code from GitHub (`main` branch)
- Install any new Python dependencies
- Restart the service (the database migration runs automatically on startup)

---

## Uninstalling

Run `Setup.ps1` as Administrator and select **option 3 — Uninstall**.

This removes the Windows service and firewall rules. Your log database (`data/syslog.db`) and `.env` file are **not** deleted so you can reinstall without losing data.

---

## Connecting Claude Projects

The REST API supports Bearer token authentication using API keys you generate in the web console.

### Generate an API key

1. Open the web console → **API Keys** tab
2. Click **Generate New API Key**, give it a label (e.g. `claude-project-main`), and click Generate
3. **Copy the key immediately** — it is only shown once

### Use the key in Claude Projects

Add this header to all requests:

```
Authorization: Bearer <your-api-key>
```

### Useful endpoints for Claude Projects

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/logs` | Query logs with filters |
| `GET` | `/api/stats` | Counts, top sources, severity breakdown |
| `GET` | `/api/ai/recommendations` | Quick 24-hour security scan |
| `POST` | `/api/ai/analyze` | Custom time window + focus area |
| `GET` | `/api/info` | Service info and configuration |

Full interactive API docs are available at `http://localhost:8080/api/docs`.

### Example: fetch recent firewall blocks

```bash
curl http://localhost:8080/api/logs?event_type=firewall_block&limit=50 \
  -H "Authorization: Bearer <your-api-key>"
```

### Example: run AI analysis (last 24 hours, security focus)

```bash
curl -X POST http://localhost:8080/api/ai/analyze \
  -H "Authorization: Bearer <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"hours": 24, "focus": "security threats and anomalies"}'
```

---

## Log Normalization

Every incoming syslog message is parsed into structured fields. Supported event types:

| Event Type | Source |
|---|---|
| `firewall_block` / `firewall_allow` | UDM kernel iptables/nftables |
| `ids_alert` | Suricata IDS/IPS (JSON or plain text) |
| `threat_block` | Unifi Threat Management |
| `auth_failure` / `auth_success` | SSH, PAM, login |
| `dhcp_ack` / `dhcp_request` / `dhcp_discover` / `dhcp_release` | dnsmasq DHCP |
| `dns_query` / `dns_response` | dnsmasq DNS |
| `vpn_connect` / `vpn_disconnect` | StrongSwan, OpenVPN, WireGuard |
| `port_scan` | Scan detection alerts |

Normalized fields include: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `action` (BLOCK/ALLOW/ALERT), `rule_name`, `mac_address`, `user`, `domain`, and more. All are filterable via the log viewer and API.

---

## Configuration Reference

All settings are in `.env`. Key options:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — | **Required.** JWT signing secret. Generate a random 32+ char string. |
| `ADMIN_USERNAME` | `admin` | Web console admin username |
| `ADMIN_PASSWORD` | `changeme` | Web console admin password — **change this** |
| `ANTHROPIC_API_KEY` | — | Required for AI analysis features |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model used for analysis |
| `SYSLOG_UDP_PORT` | `514` | UDP syslog port (use 5514 if 514 requires elevation issues) |
| `SYSLOG_TCP_PORT` | `514` | TCP syslog port |
| `API_PORT` | `8080` | Web console and REST API port |
| `RETENTION_DAYS` | `90` | Days to retain log entries |
| `MAX_LOG_ENTRIES` | `5000000` | Maximum total log entries before purge |
| `EXTERNAL_API_KEYS` | — | Comma-separated static API keys (alternative to DB-managed keys) |

---

## Project Structure

```
syslog_service/
├── main.py               # FastAPI app + syslog listener startup
├── config.py             # Settings loaded from .env
├── database.py           # SQLite schema, queries, retention, migration
├── syslog_listener.py    # Async UDP + TCP syslog receiver
├── normalizer.py         # Log parsing and field extraction
├── auth.py               # JWT + API key authentication
├── ai_analysis.py        # Claude AI integration
├── api/
│   └── routes.py         # REST API endpoints
├── static/
│   └── index.html        # Web admin dashboard (single-page app)
├── Setup.ps1             # Menu-driven installer / updater / uninstaller
├── update.ps1            # Standalone updater
├── install_service.ps1   # Headless installer (no menu)
├── requirements.txt      # Python dependencies
├── .env.example          # Configuration template
└── data/                 # SQLite database (auto-created, gitignored)
```
