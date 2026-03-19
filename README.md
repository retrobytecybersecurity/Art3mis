# ◈ ARTEMIS — External Network Penetration Testing Suite

> Automated external pentest orchestration with live web UI, persistent dashboard, and professional PDF/DOCX reporting.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red?style=flat-square)

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorized security assessments**. Only use Artemis against systems you own or have explicit written permission to test. Unauthorized scanning or exploitation of systems you do not own is illegal. The author assumes no liability for misuse.

---

## Overview

Artemis is a full-stack penetration testing automation suite built for external network assessments. It wraps industry-standard tools into a structured three-phase pipeline, streams live output to a browser-based UI, and generates professional PDF and Word reports at the end of each engagement.

It runs as a persistent web service on a Kali Linux VM, protected by session-based authentication and HTTPS, accessible from any browser after logging in.

---

## Features

- **Browser-based UI** — no desktop required, access from anywhere over HTTPS
- **Session authentication** — login page with persistent sessions, no credentials in the URL
- **Persistent dashboard** — tracks last 5 engagements with client name, date, domain, and phases run
- **Live output streaming** — Server-Sent Events push log lines to the browser in real time as tools run
- **Three-phase pipeline** — Recon/OSINT, Port Scanning, Vulnerability Scanning, all independently toggleable
- **Automated tool management** — checks for all required tools on startup, installs missing ones via apt/go/pip, resolves tools outside PATH automatically
- **PDF + Word reports** — structured pentest summary report exported to both formats at scan completion
- **Assessment Evidence folder** — termshot terminal screenshots and gowitness web screenshots organized per engagement
- **Systemd service** — runs automatically on boot, restarts on failure

---

## Tool Stack

| Phase | Tools |
|-------|-------|
| Recon / OSINT | assetfinder, dnsenum, curl, theHarvester, spoofy, o365spray, pymeta |
| Port Scanning | nmap (TCP full + UDP top-200), gowitness |
| Vulnerability | sslscan, shcheck, nikto, nuclei, ffuf, metasploit |
| Evidence | termshot, gowitness |
| Reporting | reportlab (PDF), python-docx (DOCX) |

---

## Architecture

```
Browser (HTTPS)
      │
   Nginx (443)          ← TLS termination, reverse proxy
      │
   Flask (127.0.0.1:5000)   ← Session auth, API routes, SSE stream
      │
   Scan Engine (thread)      ← Subprocess orchestration
      │
   /opt/artemis/results/     ← Per-engagement output folders
```

---

## Installation

### Prerequisites

- Kali Linux (or Debian-based) with root access
- Go 1.21+ (`sudo apt install golang`)
- Nginx (`sudo apt install nginx`)

### One-command install

```bash
git clone https://github.com/yourusername/artemis.git
cd artemis
sudo bash install.sh
```

`install.sh` handles everything:
- apt packages: nmap, nikto, sslscan, dnsenum, curl, theharvester
- Go tools: nuclei, ffuf, assetfinder, gowitness, termshot
- pip packages: flask, reportlab, python-docx, pymeta3
- git clones: shcheck → `/opt/shcheck`, spoofy → `/opt/spoofy`, o365spray → `/opt/o365spray`
- Nuclei template update
- Deploy to `/opt/artemis/`
- Install and start the systemd service

### Manual tools (not auto-installed)

**Metasploit Framework:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && sudo ./msfinstall
```

---

## Configuration

### Set credentials

Edit `/etc/systemd/system/artemis.service` before starting:

```ini
Environment="ARTEMIS_USER=yourname"
Environment="ARTEMIS_PASSWORD=your-strong-password"
Environment="ARTEMIS_SECRET=long-random-secret-string"
```

Then reload:
```bash
sudo systemctl daemon-reload && sudo systemctl restart artemis
```

### HTTPS setup

**With a domain (Let's Encrypt):**
```bash
sudo certbot --nginx -d yourdomain.com
```

**IP only (self-signed):**
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/artemis.key \
  -out /etc/ssl/certs/artemis.crt \
  -subj "/CN=$(curl -s ifconfig.me)"
```

Copy the provided `nginx_artemis.conf` to `/etc/nginx/sites-available/artemis`, enable it, and reload Nginx.

---

## Usage

### Access

Browse to `https://your-server-ip` and log in with your configured credentials.

### Workflow

1. **Dashboard** — view recent assessments or click **Begin Assessment**
2. **Fill in the form**
   - Client name and date (folder name on disk)
   - Domain (used by OSINT tools)
   - Scope — bare IPs/hostnames, no `https://` (used by nmap, metasploit)
   - URLs — full URLs with `https://` (used by curl, sslscan, shcheck, nikto, nuclei, ffuf)
   - Toggle phases as needed
3. **Submit** — creates the engagement folder, writes target files
4. **Run Scan** — launches the pipeline, live output streams to the browser
5. **Generate Report** — produces PDF and DOCX, available for download
6. **Exit / New Scan** — saves the engagement to the dashboard, resets for the next client

### Output structure

```
/opt/artemis/results/<ClientName>_<Date>/
├── scope.txt
├── urls.txt
├── domain.txt
├── artemis.log
├── msf_scan.rc
├── Assessment_Evidence/       ← termshot + gowitness screenshots
├── 1_recon/                   ← assetfinder, dnsenum, curl sweep, OSINT tools
├── 2_scan/                    ← nmap TCP/UDP, gowitness screenshots
├── 3_vuln/                    ← sslscan, shcheck, nikto, nuclei, ffuf, metasploit
├── Artemis_Report_<client>_<date>.pdf
└── Artemis_Report_<client>_<date>.docx
```

---

## Report Sections

| # | Section | Source |
|---|---------|--------|
| 1 | Vulnerability & Port Summary | Nikto + Nuclei findings, Nmap open ports |
| 2a | Subdomain Enumeration (count) | assetfinder + theHarvester |
| 2b | theHarvester — Emails / IPs | theHarvester output |
| 2c | pymeta — Exposed Files (count) | pymeta output |
| 3a | Email Spoofability | spoofy SPF/DMARC/DKIM output |
| 3b | O365 / Azure Tenant | o365spray findings |
| 4 | Missing HTTP Security Headers (count per host) | shcheck output |
| 5 | Web Content Discovery — HTTP 200 count | ffuf CSV output |
| 6 | Metasploit Auxiliary Findings | msfconsole `[+]` results |

---

## Service Management

```bash
sudo systemctl status  artemis     # check status
sudo systemctl restart artemis     # restart after config changes
sudo systemctl stop    artemis     # stop
sudo journalctl -fu    artemis     # live logs
```

---

## File Reference

| File | Purpose |
|------|---------|
| `artemis_web.py` | Flask web server, scan engine, all API routes |
| `artemis.py` | Original desktop Tkinter version (standalone) |
| `report_generator.py` | PDF and DOCX report builder |
| `templates/login.html` | Login page |
| `templates/dashboard.html` | Dashboard — recent assessments |
| `templates/index.html` | Scan UI — form, confirmed view, live log |
| `artemis.service` | systemd unit file |
| `nginx_artemis.conf` | Nginx reverse proxy config |
| `install.sh` | Full dependency installer and deployment script |
| `requirements.txt` | Python pip dependencies |

---

## Desktop Version

`artemis.py` is the original Tkinter desktop GUI version for use directly on a Kali workstation. It has identical scan functionality but outputs to `~/Desktop/<ClientName>_<Date>/` and does not require Flask or Nginx.

```bash
# Desktop version
xhost +SI:localuser:root && sudo python3 artemis.py
```

---

## Contributing

Issues and pull requests welcome. Please ensure any contributions are tested against authorized lab environments only.

---

## License

MIT License — see `LICENSE` for details.
