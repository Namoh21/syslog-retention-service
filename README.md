# Syslog Retention & SIEM Service

A self-hosted syslog retention and security analysis service that receives logs from a **Unifi Dream Machine (UDM)** and other network devices. Logs are stored locally, normalized into structured fields, and analyzed by **Claude AI** for security recommendations. A web admin console provides log viewing, retention management, user management, and API key generation. A REST API allows Claude Projects to connect programmatically.

Runs on **Raspberry Pi 4/5** (recommended) or **Windows 11**.

---

## Features

- **Syslog receiver** — UDP and TCP on port 514, RFC 3164 and RFC 5424
- **Log normalization** — parses UDM firewall, IDS/IPS, DHCP, DNS, auth, VPN, and threat management events into structured fields
- **SQLite storage** — configurable retention period and entry limit with automatic daily purge
- **Claude AI analysis** — sends log data to Claude Sonnet and returns structured threat findings with immediate actions and long-term recommendations
- **REST API** — JWT and API-key authentication for the web UI and external Claude Project clients
- **Web admin console** — dark-themed single-page dashboard with log viewer, AI analysis, retention settings, user management, and API key management
- **Linux/systemd** — runs at boot, managed through `install.sh`
- **Windows service** — runs at boot via pywin32, managed through `Setup.ps1`

---

## Requirements

### Raspberry Pi 4 / Linux (Recommended)

| Requirement | Details |
|---|---|
| Hardware | Raspberry Pi 4 (2 GB RAM minimum) or Pi 5 |
| OS | Raspberry Pi OS Bookworm or Bullseye (or any Debian-based distro) |
| Python | 3.10 or newer — pre-installed on Raspberry Pi OS |
| Git | Installed automatically by `install.sh` if missing |
| Network | Static IP or DHCP reservation recommended so the UDM always knows where to send logs |

### Windows 11

| Requirement | Details |
|---|---|
| OS | Windows 11 Pro or Home |
| Python | 3.10 or newer from [python.org](https://python.org) — **not** the Windows Store version. Check "Add python.exe to PATH" during install. |
| Git | From [git-scm.com](https://git-scm.com) |
| PowerShell | Run `Setup.ps1` as Administrator |

### Both Platforms

| Requirement | Details |
|---|---|
| Anthropic API key | Required for AI analysis. Get one at [console.anthropic.com](https://console.anthropic.com) |
| Network access to UDM | The UDM must be able to reach this device on UDP/TCP port 514 |

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

Select **option 1 — Install / Repair**. The wizard will ask for:

- Admin username and password for the web console
- Anthropic API key (optional at install time, can be added later)
- Claude model preference
- Syslog ports (default 514)
- Web console port (default 8080)
- Log retention period and maximum entry count
- External API keys for Claude Projects (optional, can generate in web console later)

The installer then:

1. Installs `python3`, `git`, and `ufw` via apt if missing
2. Copies the app to `/opt/syslog-retention-service`
3. Creates a Python virtual environment and installs all dependencies
4. Registers and enables a systemd service (auto-starts at boot)
5. Opens firewall ports via ufw

### 3. Point your Unifi Dream Machine at the Pi

In the UniFi Network controller:

1. Go to **Settings → System → Logging**
2. Enable **Remote Syslog**
3. Set the **Syslog Server IP** to the Pi's local IP address
4. Set the **Port** to `514`
5. Save

### 4. Open the web console

```
http://<pi-ip-address>:8080
```

The installer prints the Pi's IP at the end of install.

---

## Installation — Windows 11

### 1. Install prerequisites

- Download and install **Python 3.12** from [python.org/downloads](https://python.org/downloads)
  - On the first installer screen, check **"Add python.exe to PATH"**
  - At the end, click **"Disable path length limit"** if prompted
  - Do **not** use the Windows Store Python — it is a stub that does not work
- Download and install **Git** from [git-scm.com](https://git-scm.com)

### 2. Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
```

### 3. Run the installer

Right-click `Setup.ps1` and select **"Run with PowerShell"**, or from an Administrator PowerShell prompt:

```powershell
.\Setup.ps1
```

Select **option 1 — Install / Repair**. The same configuration wizard runs as on the Pi.

### 4. Point your Unifi Dream Machine at this PC

Same steps as the Pi section above — use this PC's local IP address.

### 5. Open the web console

```
http://localhost:8080
```

---

## Updating

### Raspberry Pi

```bash
sudo bash /opt/syslog-retention-service/install.sh
```

Select **option 2 — Update**, or use the standalone script:

```bash
sudo bash /opt/syslog-retention-service/update.sh
```

### Windows

Run `Setup.ps1` as Administrator and select **option 2 — Update**, or:

```powershell
.\update.ps1
```

Both updaters: pull latest code from GitHub, install new dependencies, restart the service. The database migration runs automatically on startup — no data is lost.

---

## Uninstalling

### Raspberry Pi

```bash
sudo bash /opt/syslog-retention-service/install.sh
```

Select **option 3 — Uninstall**. Removes the systemd service and firewall rules. App files and log database are not deleted.

### Windows

Run `Setup.ps1` as Administrator and select **option 3 — Uninstall**. Removes the Windows service and firewall rules. App files and log database are not deleted.

---

## Connecting Claude Projects

### Generate an API key

1. Open the web console → **API Keys** tab
2. Click **Generate New API Key**, give it a label (e.g. `claude-project-main`), choose Read-only
3. **Copy the key immediately** — it is only shown once

### Authenticate

Add this header to all API requests:

```
Authorization: Bearer <your-api-key>
```

### Key endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/logs` | Query logs with filters |
| `GET` | `/api/stats` | Counts, top sources, severity breakdown |
| `GET` | `/api/ai/recommendations` | Quick 24-hour security scan |
| `POST` | `/api/ai/analyze` | Custom time window and focus area |
| `GET` | `/api/info` | Service info and configuration |

Full interactive API docs: `http://<host>:8080/api/docs`

### Examples

```bash
# Fetch recent firewall blocks
curl "http://<host>:8080/api/logs?event_type=firewall_block&limit=50" \
  -H "Authorization: Bearer <your-api-key>"

# Run AI security analysis on the last 24 hours
curl -X POST "http://<host>:8080/api/ai/analyze" \
  -H "Authorization: Bearer <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"hours": 24, "focus": "security threats and anomalies"}'
```

---

## Log Normalization

Every incoming syslog message is parsed into structured fields before storage.

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

Structured fields per event: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `action` (BLOCK/ALLOW/ALERT), `rule_name`, `mac_address`, `user`, `domain`, and more. All filterable via the log viewer and API.

---

## Configuration Reference

All settings live in `.env` in the install directory. The configuration wizard sets these during install; edit them any time with menu option 6.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | auto-generated | JWT signing secret — do not change after install |
| `ADMIN_USERNAME` | `admin` | Web console admin username |
| `ADMIN_PASSWORD` | set during wizard | Web console admin password |
| `ANTHROPIC_API_KEY` | — | Required for AI analysis |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model for analysis |
| `SYSLOG_UDP_PORT` | `514` | UDP syslog listener port |
| `SYSLOG_TCP_PORT` | `514` | TCP syslog listener port |
| `API_HOST` | `0.0.0.0` | Web console bind address |
| `API_PORT` | `8080` | Web console and REST API port |
| `RETENTION_DAYS` | `90` | Days to keep log entries |
| `MAX_LOG_ENTRIES` | `5000000` | Maximum stored entries before purge |
| `EXTERNAL_API_KEYS` | — | Comma-separated static API keys for external clients |

---

## Project Structure

```
syslog-retention-service/
├── main.py                  # FastAPI app entry point and syslog listener startup
├── config.py                # Settings loaded from .env
├── database.py              # SQLite schema, queries, retention purge, migration
├── syslog_listener.py       # Async UDP and TCP syslog receiver
├── normalizer.py            # Log parsing and structured field extraction
├── auth.py                  # JWT and API key authentication
├── ai_analysis.py           # Claude AI integration
├── windows_service.py       # Windows service wrapper (pywin32)
├── api/
│   └── routes.py            # All REST API endpoints
├── static/
│   └── index.html           # Web admin dashboard (single-page app)
├── install.sh               # Raspberry Pi / Linux installer menu
├── update.sh                # Standalone Linux updater
├── Setup.ps1                # Windows installer menu
├── update.ps1               # Standalone Windows updater
├── requirements.txt         # Python dependencies (Windows, includes pywin32)
├── requirements-linux.txt   # Python dependencies (Linux/Pi, no pywin32)
├── syslog_service.service   # systemd unit template
├── .env.example             # Configuration template
└── data/                    # SQLite database (auto-created, gitignored)
```
