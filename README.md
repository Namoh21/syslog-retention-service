# Syslog Retention & SIEM Service

A self-hosted syslog retention and security analysis platform that receives logs from a **Unifi Dream Machine (UDM)** and other network devices. Logs are stored locally, normalized into structured fields, and analyzed by **Claude AI** for security recommendations. A web console provides log viewing, IP investigation, firewall rule analysis, alert rules, and admin management.

Runs on **Raspberry Pi 4/5** (recommended) or **Windows 11**.

---

## Quick Start — Raspberry Pi

```bash
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
sudo bash install.sh        # choose option 1, follow the wizard
```

Then point your UDM syslog to the Pi's IP on port 514 and open `http://<pi-ip>:8080`.

## Quick Start — Windows 11

```powershell
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
.\Setup.ps1                 # run as Administrator, choose option 1
```

Then point your UDM syslog to this PC's IP on port 514 and open `http://localhost:8080`.

---

## Features

### Log Collection & Storage
- **Syslog receiver** — UDP (port 514) and TCP (port 6514), RFC 3164 and RFC 5424
- **Log normalization** — parses UDM firewall, IDS/IPS, DHCP, DNS, auth, VPN, and threat management events into structured fields
- **SQLite storage** — configurable retention period and entry limit with automatic daily purge
- **CSV export** — export filtered log views directly from the web console

### SIEM & Security Analysis
- **Claude AI analysis** — sends log data to Claude and returns structured threat findings with immediate actions and long-term recommendations
- **IP investigation** — pivot on any IP to see all activity, event types, firewall rules triggered, ports targeted, and first/last seen
- **IP reputation enrichment** — AbuseIPDB score and GeoIP data (country, city, ISP) with 24-hour cache
- **Rule hits** — ranked view of which firewall rules have fired most, with top source IPs per rule
- **Traffic matrix** — top destination ports, event/action breakdown, and top source IPs
- **Firewall rule simulator** — test a hypothetical rule against historical logs to see how many events it would match
- **Policy gap analysis** — AI analysis of ALLOWED traffic to find unexpected or suspicious connections
- **Timeline sparkline** — hourly BLOCK/ALLOW chart on the dashboard

### Alerting
- **Alert rules** — configurable conditions: threshold count, log pattern match, severity level, new IP seen
- **Webhook notifications** — POST alert payload to any HTTPS endpoint
- **Email notifications** — SMTP with STARTTLS support
- **Daily digest** — AI-generated 24-hour security summary emailed on demand or on schedule
- **Alert acknowledgement** — unacknowledged alerts shown as a badge in the navigation

### Administration
- **Web admin console** — dark-themed single-page app, no separate frontend build required
- **User management** — create, disable, and reset passwords for multiple users
- **API key management** — generate and revoke bearer tokens for external integrations
- **Audit log** — immutable record of every admin action
- **All settings via web UI** — no need to edit config files after install

### Security Architecture
- **No secrets in config files after first run** — credentials seeded on first startup are immediately moved to encrypted storage and scrubbed from `.env`
- **OS keystore for root secret** — `SECRET_KEY` stored via DPAPI (Windows) or a chmod-600 file in `/etc/syslog-retention/` (Linux), separate from the database. Exfiltrating the database alone is not sufficient to decrypt it.
- **AES-256 encrypted database** — all API keys, SMTP credentials, and sensitive settings encrypted with Fernet before storage
- **Runs as non-root** (Linux) — dedicated `syslog-siem` system user with systemd hardening (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`)
- **JWT authentication** with token version invalidation on password change
- **Login rate limiting** — configurable lockout after repeated failures
- **API keys stored as SHA-256 hashes** — raw keys never retained after generation

---

## Requirements

### Raspberry Pi 4/5 / Linux (Recommended)

| Requirement | Details |
|---|---|
| Hardware | Raspberry Pi 4 (2 GB RAM minimum) or Pi 5 |
| OS | Raspberry Pi OS Bookworm or Bullseye (or any Debian-based distro) |
| Python | **3.10 or newer** — pre-installed on current Raspberry Pi OS |
| Git | Installed automatically by `install.sh` if missing |
| Network | Static IP or DHCP reservation recommended |

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
| UDM network access | The UDM must be able to reach this device on UDP 514 / TCP 6514 |

---

## Installation — Raspberry Pi 4/5 (Recommended)

### 1. Clone the repository

```bash
git clone https://github.com/Namoh21/syslog-retention-service.git
cd syslog-retention-service
```

### 2. Run the installer

```bash
sudo bash install.sh
```

Select **option 1 — Install / Repair**. The wizard asks for:

- Admin username and password for the web console
- Anthropic API key (optional at install time — add it later in Settings)
- Claude model preference
- Syslog ports (UDP default 514, TCP default 6514)
- Web console port (default 8080)
- Log retention period and maximum entry count
- Allowed syslog source CIDRs (optional — leave blank to allow all)

The installer then:

1. Installs `python3`, `git`, and `ufw` via apt if missing
2. Verifies Python 3.10+ (shows install instructions if older)
3. Detects and resolves rsyslog port 514 conflicts
4. Copies the app to `/opt/syslog-retention-service`
5. Creates a `syslog-siem` system user — service never runs as root
6. Creates a Python virtual environment and installs all dependencies
7. Registers and enables a hardened systemd service (auto-starts at boot)
8. Opens firewall ports via ufw

On first startup the service moves `SECRET_KEY` into `/etc/syslog-retention/` and scrubs all credentials from `.env`. From that point on `.env` contains no secrets.

### 3. (Optional) Set up M.2 / NVMe storage

If your Pi has an M.2 HAT, run `sudo bash install.sh` and select **option 8 — M.2 / NVMe storage setup**.

The wizard:
- Detects your Pi model (5 vs 4) and lists compatible HAT types
- **Pi 5**: checks whether PCIe NVMe is enabled in `/boot/firmware/config.txt`; adds `dtparam=pciex1` if needed and prompts for a reboot
- **Pi 4**: guides you to USB 3.0-based M.2 HATs (Argon, GeekPi, Waveshare)
- Scans for drives, shows model and size, excludes the OS drive
- Formats the selected drive as ext4 and mounts it persistently at `/mnt/syslog-data`
- Migrates any existing database to the new location
- Updates `DB_PATH` in `.env` automatically

### 4. Point your Unifi Dream Machine at the Pi

In the UniFi Network controller:

1. Go to **Settings → System → Logging**
2. Enable **Remote Syslog**
3. Set **Syslog Server IP** to the Pi's local IP address
4. Set **Port** to `514` (UDP) — or your custom port if you changed it
5. Save

### 5. Open the web console

```
http://<pi-ip-address>:8080
```

The installer prints the Pi's IP at the end of install.

---

## Installation — Windows 11

### 1. Install prerequisites

- Download **Python 3.12** from [python.org/downloads](https://python.org/downloads)
  - Check **"Add python.exe to PATH"** on the first screen
  - Click **"Disable path length limit"** at the end if prompted
  - Do **not** use the Windows Store Python — it is a stub that opens the Store instead of running
- Download **Git** from [git-scm.com](https://git-scm.com)

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

On first startup `SECRET_KEY` is moved into the Windows DPAPI credential store (tied to your Windows user account) and scrubbed from `.env`.

### 4. Point your Unifi Dream Machine at this PC

Use this PC's local IP address. Same steps as the Pi section above.

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

Select **option 2 — Update**. Pulls latest code from GitHub, installs new dependencies, restarts the service. Database migrations run automatically — no data is lost.

### Windows

Run `Setup.ps1` as Administrator and select **option 2 — Update**.

---

## Uninstalling

### Raspberry Pi

```bash
sudo bash /opt/syslog-retention-service/install.sh
```

Select **option 3 — Uninstall**. Removes the systemd service, firewall rules, and optionally the `syslog-siem` user. App files and database are not deleted — remove them manually with `sudo rm -rf /opt/syslog-retention-service`.

### Windows

Run `Setup.ps1` as Administrator and select **option 3 — Uninstall**. Removes the Windows service and firewall rules. App files and database are not deleted.

---

## Connecting Claude Projects

### Generate an API key

1. Open the web console → **Admin → API Keys**
2. Click **Generate New API Key**, give it a label, choose Read-only
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
| `GET` | `/api/info` | Service info and AI configuration status |
| `GET` | `/api/investigation/{ip}` | All activity for a specific IP |
| `GET` | `/api/analysis/timeline` | Hourly event counts (blocks/allows) |
| `GET` | `/api/analysis/rule-hits` | Top firewall rules with source IPs |
| `GET` | `/api/analysis/traffic-matrix` | Top ports, sources, event breakdown |
| `POST` | `/api/analysis/simulate-rule` | Match a hypothetical rule against history |

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

# Investigate a specific IP
curl "http://<host>:8080/api/investigation/203.0.113.42" \
  -H "Authorization: Bearer <your-api-key>"
```

---

## Log Normalization

Every incoming syslog message is parsed into structured fields before storage.

| Event Type | Source |
|---|---|
| `firewall_block` / `firewall_allow` | UDM kernel iptables/nftables |
| `ids_alert` | Suricata IDS/IPS |
| `threat_block` | Unifi Threat Management |
| `auth_failure` / `auth_success` | SSH, PAM, login |
| `dhcp_ack` / `dhcp_request` / `dhcp_discover` / `dhcp_release` | dnsmasq DHCP |
| `dns_query` / `dns_response` | dnsmasq DNS |
| `vpn_connect` / `vpn_disconnect` | StrongSwan, OpenVPN, WireGuard |
| `port_scan` | Scan detection alerts |

Structured fields per event: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `action` (BLOCK/ALLOW/ALERT), `rule_name`, `mac_address`, `user`, `domain`, and more.

---

## Configuration Reference

### Startup config — `.env` (required at boot, not sensitive after first run)

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | auto-generated | Root encryption key — moved to OS keystore on first startup |
| `ADMIN_USERNAME` | `admin` | Initial admin username (seeded once) |
| `ADMIN_PASSWORD` | set during wizard | Initial admin password (seeded once, then scrubbed) |
| `ANTHROPIC_API_KEY` | — | Initial API key (imported to encrypted DB, then scrubbed) |
| `SYSLOG_UDP_HOST` | `0.0.0.0` | UDP listener bind address |
| `SYSLOG_UDP_PORT` | `514` | UDP syslog port |
| `SYSLOG_TCP_HOST` | `0.0.0.0` | TCP listener bind address |
| `SYSLOG_TCP_PORT` | `6514` | TCP syslog port (non-privileged default) |
| `API_HOST` | `0.0.0.0` | Web console bind address |
| `API_PORT` | `8080` | Web console and REST API port |
| `DB_PATH` | `data/syslog.db` | SQLite database path (updated by M.2 wizard) |

### Runtime config — web console Settings tab (stored encrypted in database)

These are set via **Settings → Service Configuration** — no `.env` editing required.

| Setting | Default | Description |
|---|---|---|
| Anthropic API key | — | Claude AI key (AES-256 encrypted) |
| Claude model | `claude-sonnet-4-6` | Model used for analysis |
| Allowed syslog sources | (all) | Comma-separated CIDRs that may send logs |
| Login max attempts | `10` | Failed logins before lockout |
| Login lockout window | `300 s` | Lockout duration in seconds |
| Session timeout | `480 min` | JWT expiry for new logins |
| Max logs per AI analysis | `500` | Cap on log entries sent per analysis |
| SMTP host/port/user/password | — | For alert email and daily digest |
| AbuseIPDB API key | — | For IP reputation enrichment |

---

## Project Structure

```
syslog-retention-service/
├── main.py                  # FastAPI app entry point, rate limiter, health check
├── config.py                # Settings from .env + OS keystore resolution
├── keystore.py              # OS-native secret storage (DPAPI / protected file)
├── database.py              # SQLite schema, migrations, encrypted settings store
├── syslog_listener.py       # Async UDP and TCP syslog receiver
├── normalizer.py            # Log parsing and structured field extraction
├── auth.py                  # JWT and API key authentication
├── ai_analysis.py           # Claude AI integration
├── enrichment.py            # AbuseIPDB + GeoIP reputation enrichment
├── alert_engine.py          # Background alert rule evaluator and notifications
├── windows_service.py       # Windows service wrapper (pywin32)
├── api/
│   └── routes.py            # All REST API endpoints
├── static/
│   └── index.html           # Web admin dashboard (single-page app)
├── install.sh               # Raspberry Pi / Linux installer (includes M.2 wizard)
├── Setup.ps1                # Windows installer
├── requirements.txt         # Python dependencies (Windows, includes pywin32)
├── requirements-linux.txt   # Python dependencies (Linux/Pi)
└── data/                    # SQLite database (auto-created, gitignored)
```
