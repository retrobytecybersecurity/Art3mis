#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║         ARTEMIS — Dependency Installer                   ║
# ║         Run: sudo bash install.sh                        ║
# ╚══════════════════════════════════════════════════════════╝

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root: sudo bash install.sh"
    exit 1
fi

echo ""
echo "◈ ARTEMIS — Installing dependencies..."
echo "────────────────────────────────────────"

# ── System / apt packages ─────────────────────────────────────────────────
echo "[*] Installing apt packages..."
apt-get update -qq
apt-get install -y \
    python3-tk \
    python3-pip \
    nmap \
    nikto \
    sslscan \
    dnsenum \
    curl \
    golang \
    seclists \
    theharvester \
    git

echo "[✓] apt packages installed"

# ── Python packages ───────────────────────────────────────────────────────
echo "[*] Installing Python packages..."
pip3 install -r requirements.txt --break-system-packages
echo "[✓] Python packages installed"

# ── Go tools ──────────────────────────────────────────────────────────────
echo "[*] Installing Go tools..."
export GOPATH=/root/go
export PATH=$PATH:/root/go/bin

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/sensepost/gowitness@latest
go install github.com/homeport/termshot/cmd/termshot@latest

# Add go/bin to PATH permanently
if ! grep -q "/root/go/bin" /root/.bashrc; then
    echo 'export PATH=$PATH:/root/go/bin' >> /root/.bashrc
fi
echo "[✓] Go tools installed"

# ── shcheck.py ────────────────────────────────────────────────────────────
if [ ! -f /opt/shcheck/shcheck.py ]; then
    echo "[*] Installing shcheck.py..."
    git clone https://github.com/santoru/shcheck /opt/shcheck
    pip3 install -r /opt/shcheck/requirements.txt --break-system-packages 2>/dev/null || true
    echo "[✓] shcheck.py installed to /opt/shcheck"
else
    echo "[✓] shcheck.py already present"
fi

# ── spoofy ────────────────────────────────────────────────────────────────
if [ ! -f /opt/spoofy/spoofy.py ]; then
    echo "[*] Installing spoofy..."
    git clone https://github.com/MattKeeley/Spoofy /opt/spoofy
    pip3 install -r /opt/spoofy/requirements.txt --break-system-packages 2>/dev/null || true
    echo "[✓] spoofy installed to /opt/spoofy"
else
    echo "[✓] spoofy already present"
fi

# ── o365spray ─────────────────────────────────────────────────────────────
if [ ! -f /opt/o365spray/o365spray.py ]; then
    echo "[*] Installing o365spray..."
    git clone https://github.com/0xZDH/o365spray /opt/o365spray
    pip3 install -r /opt/o365spray/requirements.txt --break-system-packages 2>/dev/null || true
    echo "[✓] o365spray installed to /opt/o365spray"
else
    echo "[✓] o365spray already present"
fi

# ── nuclei templates ──────────────────────────────────────────────────────
echo "[*] Updating nuclei templates..."
/root/go/bin/nuclei -update-templates 2>/dev/null || true
echo "[✓] nuclei templates updated"

# ── Results directory ─────────────────────────────────────────────────────
echo "[*] Creating results directory..."
mkdir -p /opt/artemis/results
echo "[✓] Results directory: /opt/artemis/results"

# ── Deploy to /opt/artemis ────────────────────────────────────────────────
echo "[*] Deploying Artemis to /opt/artemis..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/artemis_web.py"    /opt/artemis/
cp "$SCRIPT_DIR/report_generator.py" /opt/artemis/
mkdir -p /opt/artemis/templates
cp "$SCRIPT_DIR/templates/index.html" /opt/artemis/templates/
echo "[✓] Files deployed"

# ── systemd service ───────────────────────────────────────────────────────
echo "[*] Installing systemd service..."
cp "$SCRIPT_DIR/artemis.service" /etc/systemd/system/artemis.service
systemctl daemon-reload
systemctl enable artemis
systemctl restart artemis
echo "[✓] Artemis service installed and started"
echo "    Status: systemctl status artemis"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
echo "◈ Artemis installation complete."
echo ""
echo "  Tool summary:"
echo "    apt  : nmap, nikto, sslscan, dnsenum, curl, theharvester"
echo "    go   : nuclei, ffuf, assetfinder, gowitness, termshot"
echo "    pip  : flask, reportlab, python-docx, pymeta3"
echo "    git  : shcheck → /opt/shcheck"
echo "           spoofy  → /opt/spoofy"
echo "           o365spray → /opt/o365spray"
echo ""
echo "  NOTE: Metasploit Framework must be installed manually."
echo ""
echo "  Access via SSH tunnel:"
echo "    ssh -L 5000:localhost:5000 root@YOUR-LINODE-IP"
echo "    then open: http://localhost:5000"
echo ""
echo "  Service commands:"
echo "    systemctl status  artemis"
echo "    systemctl restart artemis"
echo "    journalctl -fu artemis"
