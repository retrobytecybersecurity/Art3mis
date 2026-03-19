#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   ARTEMIS WEB — External Pentest Automation (Web Mode)   ║
╚══════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import shutil
import threading
import re
import queue
import json
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import (Flask, render_template, request, jsonify,
                   Response, send_file, session, redirect, url_for)

# ── Root check ────────────────────────────────────────────────────────────
if os.geteuid() != 0:
    print("\n[!] Artemis requires root privileges.")
    print("    Run: sudo python3 artemis_web.py\n")
    sys.exit(1)

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════
RESULTS_BASE   = Path("/opt/artemis/results")
HISTORY_FILE   = Path("/opt/artemis/history.json")
RESULTS_BASE.mkdir(parents=True, exist_ok=True)

# ── Credentials — change these before deploying ──────────────────────────
ARTEMIS_USER     = os.environ.get("ARTEMIS_USER",     "artemis")
ARTEMIS_PASSWORD = os.environ.get("ARTEMIS_PASSWORD", "changeme123!")
app.secret_key   = os.environ.get("ARTEMIS_SECRET",   "artemis-secret-key-change-me")

# ══════════════════════════════════════════════════════════════════════════
# TOOL CONSTANTS
# ══════════════════════════════════════════════════════════════════════════
APT_PACKAGES = {
    "nmap":         "nmap",
    "nikto":        "nikto",
    "sslscan":      "sslscan",
    "dnsenum":      "dnsenum",
    "curl":         "curl",
    "theHarvester": "theharvester",
}

GO_TOOLS = {
    "nuclei":      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf":        "github.com/ffuf/ffuf/v2@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "gowitness":   "github.com/sensepost/gowitness@latest",
    "termshot":    "github.com/homeport/termshot/cmd/termshot@latest",
}

PIP_TOOLS = {"pymeta": "pymeta3"}

SHCHECK_SEARCH_PATHS = [
    "/opt/shcheck/shcheck.py", "/usr/local/bin/shcheck.py",
    "/root/shcheck/shcheck.py",
    str(Path.home() / "shcheck" / "shcheck.py"),
    str(Path.home() / "tools"   / "shcheck.py"),
]
SPOOFY_SEARCH_PATHS = [
    "/opt/spoofy/spoofy.py", "/root/spoofy/spoofy.py",
    str(Path.home() / "tools"  / "spoofy.py"),
    str(Path.home() / "spoofy" / "spoofy.py"),
]
O365SCAN_SEARCH_PATHS = [
    "/opt/o365spray/o365spray.py", "/root/o365spray/o365spray.py",
    str(Path.home() / "tools"     / "o365spray.py"),
    str(Path.home() / "o365spray" / "o365spray.py"),
]

# ══════════════════════════════════════════════════════════════════════════
# GLOBAL SCAN STATE
# ══════════════════════════════════════════════════════════════════════════
scan_state = {
    "running":       False,
    "log_queue":     queue.Queue(),
    "results":       {},
    "client_folder": None,
    "tool_paths":    {},
}

# ══════════════════════════════════════════════════════════════════════════
# HISTORY PERSISTENCE  (last 5 assessments)
# ══════════════════════════════════════════════════════════════════════════

def load_history() -> list:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            pass
    return []


def save_assessment(client: str, date: str, domain: str,
                    folder: str, phases: dict):
    """Append this assessment to history, keep only the last 5."""
    history = load_history()
    entry = {
        "client":    client,
        "date":      date,
        "domain":    domain or "—",
        "folder":    folder,
        "phases":    phases,
        "completed": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    # Prepend newest, trim to 5
    history = [entry] + [h for h in history if h.get("folder") != folder]
    history = history[:5]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))


# ══════════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Not authenticated"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════════════
# TOOL HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _add_to_path(directory: str, log_fn):
    if directory and directory not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = os.environ.get("PATH", "") + f":{directory}"
        log_fn(f"↳ Added to PATH: {directory}", "dim")


def _find_tool_on_disk(tool: str) -> str | None:
    SEARCH_DIRS = [
        "/root/go/bin", "/usr/local/bin", "/usr/bin",
        "/opt/metasploit-framework/bin", "/opt/metasploit/bin",
    ]
    for d in SEARCH_DIRS:
        candidate = Path(d) / tool
        if candidate.exists() and os.access(str(candidate), os.X_OK):
            return d
    try:
        result = subprocess.run(
            ["find", "/usr", "/opt", "/root", "/home",
             "-name", tool, "-type", "f", "-maxdepth", "8"],
            capture_output=True, text=True, timeout=15)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and os.access(line, os.X_OK):
                return str(Path(line).parent)
    except Exception:
        pass
    return None


def _find_script(search_paths: list, name: str) -> str | None:
    for p in search_paths:
        if Path(p).exists():
            return p
    try:
        result = subprocess.run(
            ["find", "/", "-name", name, "-maxdepth", "7"],
            capture_output=True, text=True, timeout=10)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines[0] if lines else None
    except Exception:
        return None


def find_shcheck() -> str | None:
    for p in SHCHECK_SEARCH_PATHS:
        if Path(p).exists():
            return p
    try:
        result = subprocess.run(
            ["find", "/", "-name", "shcheck.py", "-maxdepth", "6"],
            capture_output=True, text=True, timeout=10)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines[0] if lines else None
    except Exception:
        return None


def check_and_install_tools(log_fn):
    log_fn("🔍 Checking required tools...", "info")

    for go_bin in ["/root/go/bin", "/usr/local/go/bin"]:
        if Path(go_bin).is_dir():
            _add_to_path(go_bin, log_fn)

    for tool, pkg in APT_PACKAGES.items():
        if shutil.which(tool) is None:
            log_fn(f"  Installing {tool} via apt...", "warn")
            subprocess.run(["apt-get", "install", "-y", pkg], capture_output=True)
        found = shutil.which(tool)
        if found:
            _add_to_path(str(Path(found).parent), log_fn)
            log_fn(f"  ✓ {tool}", "success")
        else:
            disc = _find_tool_on_disk(tool)
            if disc:
                _add_to_path(disc, log_fn)
                log_fn(f"  ✓ {tool} (resolved)", "success")
            else:
                log_fn(f"  ✗ {tool} — not found", "error")

    go_path = shutil.which("go")
    for tool, module in GO_TOOLS.items():
        if shutil.which(tool) is None:
            if go_path:
                log_fn(f"  Installing {tool} via go install...", "warn")
                subprocess.run(["go", "install", module],
                               capture_output=True,
                               env={**os.environ, "GOPATH": "/root/go"})
            else:
                log_fn(f"  ✗ {tool} — Go not found", "error")
        found = shutil.which(tool)
        if found:
            _add_to_path(str(Path(found).parent), log_fn)
            log_fn(f"  ✓ {tool}", "success")
        else:
            disc = _find_tool_on_disk(tool)
            if disc:
                _add_to_path(disc, log_fn)
                log_fn(f"  ✓ {tool} (resolved)", "success")
            else:
                log_fn(f"  ✗ {tool} — not found after install", "error")

    found = shutil.which("msfconsole")
    if found:
        _add_to_path(str(Path(found).parent), log_fn)
        log_fn("  ✓ msfconsole", "success")
    else:
        disc = _find_tool_on_disk("msfconsole")
        if disc:
            _add_to_path(disc, log_fn)
            log_fn("  ✓ msfconsole (resolved)", "success")
        else:
            log_fn("  ✗ msfconsole — install manually", "error")

    if shutil.which("nuclei"):
        log_fn("  Updating nuclei templates...", "info")
        subprocess.run(["nuclei", "-update-templates"], capture_output=True)
        log_fn("  ✓ nuclei templates updated", "success")

    for tool, pkg in PIP_TOOLS.items():
        found = shutil.which(tool)
        if not found:
            log_fn(f"  Installing {tool} via pip...", "warn")
            subprocess.run(["pip3", "install", pkg, "--break-system-packages"],
                           capture_output=True)
            found = shutil.which(tool)
        if found:
            _add_to_path(str(Path(found).parent), log_fn)
            log_fn(f"  ✓ {tool}", "success")
        else:
            log_fn(f"  ✗ {tool} — pip install failed", "error")

    shcheck  = find_shcheck()
    spoofy   = _find_script(SPOOFY_SEARCH_PATHS,   "spoofy.py")
    o365scan = _find_script(O365SCAN_SEARCH_PATHS, "o365spray.py")

    log_fn(f"  {'✓' if shcheck  else '✗'} shcheck.py  {'found' if shcheck  else 'not found'}", "success" if shcheck  else "warn")
    log_fn(f"  {'✓' if spoofy   else '✗'} spoofy.py   {'found' if spoofy   else 'not found'}", "success" if spoofy   else "warn")
    log_fn(f"  {'✓' if o365scan else '✗'} o365spray   {'found' if o365scan else 'not found'}", "success" if o365scan else "warn")

    log_fn("✅ Tool check complete.", "success")
    return {"shcheck": shcheck, "spoofy": spoofy, "o365scan": o365scan}


# ══════════════════════════════════════════════════════════════════════════
# SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════════

def _write_msf_rc(path: Path, scope_list: list[str]):
    rhosts = " ".join(scope_list)
    path.write_text(f"""# Auto-generated by Artemis
setg RHOSTS {rhosts}
setg THREADS 10
use auxiliary/scanner/http/http_version
run
use auxiliary/scanner/ssh/ssh_version
run
use auxiliary/scanner/ftp/ftp_version
run
use auxiliary/scanner/smtp/smtp_version
run
use auxiliary/scanner/ssl/openssl_heartbleed
run
use auxiliary/scanner/smb/smb_version
run
use auxiliary/scanner/smb/smb_ms17_010
run
exit
""")


def run_scan(scope_list, url_list, domain, phases, folder, tool_paths):
    lq = scan_state["log_queue"]

    def log(msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        lq.put({"ts": ts, "msg": msg, "tag": tag})
        if folder and folder.exists():
            with open(folder / "artemis.log", "a") as f:
                f.write(f"[{ts}] {msg}\n")

    def phase(title):
        log("─" * 52, "phase")
        log(f"  {title}", "phase")
        log("─" * 52, "phase")

    def run_tool(cmd, out_file, label, screenshot_name=None):
        log(f"⟶ {label}", "info")
        try:
            with open(out_file, "w") as fh:
                r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                   text=True, timeout=600)
            if r.returncode not in (0, 1):
                log(f"⚠ {label} exited with code {r.returncode}", "warn")
            else:
                log(f"✓ {label} complete", "success")
            if screenshot_name and shutil.which("termshot"):
                try:
                    png = evidence_dir / f"{screenshot_name}.png"
                    subprocess.run(["termshot", "-f", str(png), "--"] + cmd,
                                   capture_output=True, timeout=120)
                except Exception:
                    pass
            return r.returncode
        except subprocess.TimeoutExpired:
            log(f"✗ {label} timed out", "error")
            return -1
        except FileNotFoundError:
            log(f"✗ {label} — tool not found in PATH", "error")
            return 127

    shcheck_path  = tool_paths.get("shcheck")
    spoofy_path   = tool_paths.get("spoofy")
    o365scan_path = tool_paths.get("o365scan")

    evidence_dir = folder / "Assessment_Evidence"
    evidence_dir.mkdir(exist_ok=True)

    results = {
        "client":           scan_state["results"].get("client", ""),
        "date":             scan_state["results"].get("date", ""),
        "domain":           domain,
        "targets":          scope_list,
        "scope_list":       scope_list,
        "url_list":         url_list,
        "subdomains":       [],
        "open_ports":       {},
        "vulnerabilities":  {},
        "missing_headers":  {},
        "ffuf_findings":    {},
        "msf_findings":     [],
        "o365_findings":    {},
        "harvester":        {},
        "pymeta":           [],
    }

    if phases.get("recon"):
        phase("PHASE 1 — Reconnaissance / OSINT")
        p1 = folder / "1_recon"; p1.mkdir(exist_ok=True)
        subdomains_found = []

        osint_targets = [domain] if domain else scope_list
        for target in osint_targets:
            safe_t = re.sub(r"[^\w\-]", "_", target)
            log(f"  OSINT target: {target}", "dim")
            run_tool(["assetfinder", "--subs-only", target],
                     p1 / f"assetfinder_{target}.txt",
                     f"assetfinder [{target}]",
                     screenshot_name=f"phase1_assetfinder_{safe_t}")
            sf = p1 / f"assetfinder_{target}.txt"
            if sf.exists():
                subdomains_found.extend(
                    [l.strip() for l in sf.read_text().splitlines() if l.strip()])

            run_tool(["dnsenum", "--enum", "--noreverse", target],
                     p1 / f"dnsenum_{target}.txt",
                     f"dnsenum [{target}]",
                     screenshot_name=f"phase1_dnsenum_{safe_t}")

        log("⟶ curl security header sweep...", "info")
        sweep_file = p1 / "security_headers_sweep.txt"
        with open(sweep_file, "w") as hsf:
            for url in url_list:
                hsf.write(f"\n{'='*60}\n{url}\n{'='*60}\n")
                try:
                    r = subprocess.run(
                        ["curl", "-s", "-I", "--max-time", "10", "-L",
                         "-A", "Mozilla/5.0", url],
                        capture_output=True, text=True, timeout=15)
                    hsf.write(r.stdout)
                except Exception as ex:
                    hsf.write(f"ERROR: {ex}\n")
        log("✓ curl header sweep complete", "success")

        results["subdomains"] = list(set(subdomains_found))

        if domain and spoofy_path:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            run_tool(["python3", spoofy_path, "-d", domain],
                     p1 / f"spoofy_{safe_d}.txt",
                     f"spoofy [{domain}]",
                     screenshot_name=f"phase1_spoofy_{safe_d}")
        elif domain:
            log("⚠ spoofy.py not found — skipping", "warn")

        if domain and o365scan_path:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            o365_out = p1 / f"o365scan_{safe_d}.txt"
            run_tool(["python3", o365scan_path,
                      "--validate", "--domain", domain, "--output", str(p1)],
                     o365_out, f"o365spray [{domain}]",
                     screenshot_name=f"phase1_o365scan_{safe_d}")
            if o365_out.exists():
                raw = o365_out.read_text()
                results["o365_findings"] = {
                    "domain": domain, "raw": raw[:4000],
                    "o365":     "Microsoft 365" in raw or "True" in raw,
                    "adfs":     "ADFS" in raw,
                    "exchange": "Exchange" in raw,
                }
        elif domain:
            log("⚠ o365spray not found — skipping", "warn")

        if domain:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            run_tool(["theHarvester", "-d", domain, "-b", "all", "-l", "500"],
                     p1 / f"theharvester_{safe_d}.txt",
                     f"theHarvester [{domain}]",
                     screenshot_name=f"phase1_theharvester_{safe_d}")
            h_txt = p1 / f"theharvester_{safe_d}.txt"
            hdata = {"emails": [], "ips": [], "subdomains": []}
            if h_txt.exists():
                content = h_txt.read_text()
                hdata["emails"]     = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", content)
                hdata["ips"]        = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
                hdata["subdomains"] = [l.strip() for l in content.splitlines()
                                       if l.strip().endswith(f".{domain}") and " " not in l.strip()]
            results["harvester"] = hdata
            results["subdomains"] = list(set(results["subdomains"] + hdata["subdomains"]))
        else:
            log("⚠ No domain — skipping theHarvester", "warn")

        if domain:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            pymeta_exts = (
                "txt,pdf,xls,xlsx,csv,doc,docx,ppt,config,log,bat,env,ini,"
                "yaml,py,php,bak,old,tmp,swp,asp,aspx,jsp,go,java,c,debug,"
                "trace,sql,db,git,dump,mdb,sqlite,hg,svn,zip,tar,rar,7z,tgz,"
                "rst,pem,key,crt,pfx,json,html"
            )
            pymeta_out = p1 / f"pymeta_{safe_d}.txt"
            run_tool(["pymeta", "-d", domain, "-t", pymeta_exts, "-o", str(pymeta_out)],
                     pymeta_out, f"pymeta [{domain}]",
                     screenshot_name=f"phase1_pymeta_{safe_d}")
            if pymeta_out.exists():
                results["pymeta"] = [l.strip() for l in pymeta_out.read_text().splitlines()
                                     if l.strip() and not l.startswith("#")]
        else:
            log("⚠ No domain — skipping pymeta", "warn")

    if phases.get("scan"):
        phase("PHASE 2 — Port & Service Scanning")
        p2 = folder / "2_scan"; p2.mkdir(exist_ok=True)
        open_ports     = {}
        gowitness_urls = []

        for target in scope_list:
            safe_t = re.sub(r"[^\w\-]", "_", target)
            log(f"  nmap target: {target}", "dim")
            run_tool(["nmap", "-sS", "-sV", "-sC", "-p-", "--open",
                      "-T4", "--min-rate", "1000",
                      "-oN", str(p2 / f"nmap_tcp_{target}.txt"), target],
                     p2 / f"nmap_tcp_{target}.txt",
                     f"nmap TCP [{target}]",
                     screenshot_name=f"phase2_nmap_tcp_{safe_t}")

            txt_file = p2 / f"nmap_tcp_{target}.txt"
            ports = []
            if txt_file.exists():
                ports = re.findall(r"(\d+)/tcp\s+open", txt_file.read_text())
                open_ports[target] = ports
                web_ports = {"80","443","8080","8443","8000","8888","9090","3000","4443","4080"}
                for p in ports:
                    scheme = "https" if p in {"443","8443","4443"} else "http"
                    if p in web_ports:
                        gowitness_urls.append(f"{scheme}://{target}:{p}")
                    elif p not in {"80","443"}:
                        gowitness_urls.append(f"http://{target}:{p}")
                gowitness_urls += [f"http://{target}", f"https://{target}"]

            run_tool(["nmap", "-sU", "--top-ports", "200", "-T4",
                      "-oN", str(p2 / f"nmap_udp_{target}.txt"), target],
                     p2 / f"nmap_udp_{target}.txt",
                     f"nmap UDP [{target}]",
                     screenshot_name=f"phase2_nmap_udp_{safe_t}")

        results["open_ports"] = open_ports

        if shutil.which("gowitness") and gowitness_urls:
            log("⟶ gowitness — screenshotting web ports...", "info")
            gw_dir = p2 / "gowitness"; gw_dir.mkdir(exist_ok=True)
            unique_urls = list(dict.fromkeys(gowitness_urls))
            urls_file = gw_dir / "urls.txt"
            urls_file.write_text("\n".join(unique_urls))
            try:
                with open(gw_dir / "gowitness.log", "w") as gwl:
                    subprocess.run(
                        ["gowitness", "file", "-f", str(urls_file),
                         "-P", str(gw_dir / "screenshots"), "--threads", "5"],
                        stdout=gwl, stderr=subprocess.STDOUT,
                        text=True, timeout=900)
                log("✓ gowitness complete", "success")
                screenshots_src = gw_dir / "screenshots"
                if screenshots_src.exists():
                    for img in screenshots_src.glob("*.png"):
                        shutil.copy2(str(img), str(evidence_dir / f"gowitness_{img.name}"))
            except Exception as ex:
                log(f"✗ gowitness error: {ex}", "error")
        elif not shutil.which("gowitness"):
            log("⚠ gowitness not found — skipping screenshots", "warn")

    if phases.get("vuln"):
        phase("PHASE 3 — Vulnerability Scanning")
        p3 = folder / "3_vuln"; p3.mkdir(exist_ok=True)
        vulnerabilities = {}
        missing_headers = {}
        ffuf_findings   = {}
        msf_findings    = []

        for url in url_list:
            target_key = re.sub(r"^https?://", "", url).rstrip("/")
            safe_t     = re.sub(r"[^\w\-]", "_", target_key)
            vulnerabilities[target_key] = []
            log(f"  Vuln target: {url}", "dim")

            host = re.sub(r"^https?://", "", url).rstrip("/")
            run_tool(["sslscan", "--show-certificate", host],
                     p3 / f"sslscan_{safe_t}.txt",
                     f"sslscan [{host}]",
                     screenshot_name=f"phase3_sslscan_{safe_t}")

            if shcheck_path:
                run_tool(["python3", shcheck_path, url, "-v"],
                         p3 / f"shcheck_{safe_t}.txt",
                         f"shcheck [{url}]",
                         screenshot_name=f"phase3_shcheck_{safe_t}")
                sf = p3 / f"shcheck_{safe_t}.txt"
                if sf.exists():
                    missing = re.findall(r"Missing security header:\s*(.+)", sf.read_text())
                    if missing:
                        missing_headers[target_key] = missing
            else:
                log("⚠ shcheck.py not found — skipping", "warn")

            run_tool(["nikto", "-h", url,
                      "-o", str(p3 / f"nikto_{safe_t}.xml"),
                      "-Format", "xml", "-nointeractive"],
                     p3 / f"nikto_{safe_t}.txt",
                     f"nikto [{url}]",
                     screenshot_name=f"phase3_nikto_{safe_t}")
            nf = p3 / f"nikto_{safe_t}.txt"
            if nf.exists():
                findings = re.findall(r"\+ (.+)", nf.read_text())
                vulnerabilities[target_key].extend(findings[:20])

            run_tool(["nuclei", "-u", url,
                      "-severity", "low,medium,high,critical",
                      "-o", str(p3 / f"nuclei_{safe_t}.txt"), "-silent"],
                     p3 / f"nuclei_raw_{safe_t}.txt",
                     f"nuclei [{url}]",
                     screenshot_name=f"phase3_nuclei_{safe_t}")
            nuf = p3 / f"nuclei_{safe_t}.txt"
            if nuf.exists():
                nlines = [l.strip() for l in nuf.read_text().splitlines() if l.strip()]
                vulnerabilities[target_key].extend(nlines[:30])

            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not Path(wordlist).exists():
                wordlist = "/usr/share/wordlists/dirb/common.txt"
            if Path(wordlist).exists():
                ffuf_txt = p3 / f"ffuf_{safe_t}.txt"
                run_tool(["ffuf", "-u", f"{url}/FUZZ",
                          "-w", wordlist, "-o", str(ffuf_txt), "-of", "csv",
                          "-mc", "200,201,301,302,403", "-t", "50", "-s"],
                         ffuf_txt, f"ffuf [{url}]",
                         screenshot_name=f"phase3_ffuf_{safe_t}")
                if ffuf_txt.exists():
                    try:
                        found_200 = []
                        for line in ffuf_txt.read_text().splitlines():
                            parts = line.split(",")
                            if len(parts) >= 4:
                                try:
                                    if int(parts[3].strip()) == 200:
                                        found_200.append({"url": parts[0].strip(), "status": 200})
                                except ValueError:
                                    pass
                        ffuf_findings[target_key] = found_200
                    except Exception:
                        pass
            else:
                log(f"⚠ No wordlist found for ffuf [{url}]", "warn")

        msf_rc = folder / "msf_scan.rc"
        if not msf_rc.exists():
            _write_msf_rc(msf_rc, scope_list)
        run_tool(["msfconsole", "-q", "-r", str(msf_rc)],
                 p3 / "metasploit.txt", "metasploit auxiliary scanners",
                 screenshot_name="phase3_metasploit")
        msf_txt = p3 / "metasploit.txt"
        if msf_txt.exists():
            msf_findings = re.findall(r"\[\+\].*", msf_txt.read_text())

        results.update({
            "vulnerabilities": vulnerabilities,
            "missing_headers": missing_headers,
            "ffuf_findings":   ffuf_findings,
            "msf_findings":    msf_findings,
        })

    scan_state["results"].update(results)

    log("", "info")
    log("╔══════════════════════════════════════╗", "phase")
    log("║   ✅  SCAN COMPLETE                  ║", "phase")
    log("╚══════════════════════════════════════╝", "phase")
    log("__SCAN_COMPLETE__", "control")
    scan_state["running"] = False


# ══════════════════════════════════════════════════════════════════════════
# FLASK ROUTES — AUTH
# ══════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ARTEMIS_USER and password == ARTEMIS_PASSWORD:
            session["logged_in"] = True
            session.permanent = True
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════════════════
# FLASK ROUTES — DASHBOARD
# ══════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def dashboard():
    history = load_history()
    return render_template("dashboard.html", history=history)


# ══════════════════════════════════════════════════════════════════════════
# FLASK ROUTES — SCAN
# ══════════════════════════════════════════════════════════════════════════

@app.route("/scan")
@login_required
def scan_page():
    return render_template("index.html")


@app.route("/api/startup-status")
@login_required
def startup_status():
    tp = scan_state.get("tool_paths", {})
    return jsonify({
        "shcheck":  bool(tp.get("shcheck")),
        "spoofy":   bool(tp.get("spoofy")),
        "o365scan": bool(tp.get("o365scan")),
        "ready":    True,
    })


@app.route("/api/submit", methods=["POST"])
@login_required
def submit():
    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan already in progress."}), 409

    data      = request.get_json()
    client    = data.get("client", "").strip()
    date      = data.get("date", datetime.now().strftime("%Y-%m-%d")).strip()
    domain    = re.sub(r"^https?://", "", data.get("domain", "").strip()).rstrip("/").lower()
    scope_raw = data.get("scope", "").strip()
    urls_raw  = data.get("urls", "").strip()

    if not client:
        return jsonify({"ok": False, "error": "Client name is required."}), 400
    if not scope_raw and not urls_raw and not domain:
        return jsonify({"ok": False, "error": "Enter at least one target."}), 400

    scope_list = [re.sub(r"^https?://", "", l).rstrip("/").strip()
                  for l in scope_raw.splitlines() if l.strip()]
    url_list   = [l.strip() for l in urls_raw.splitlines() if l.strip()]

    safe   = re.sub(r"[^\w\-_ ]", "_", client)
    folder = RESULTS_BASE / f"{safe}_{date}"
    folder.mkdir(parents=True, exist_ok=True)

    if scope_list: (folder / "scope.txt").write_text("\n".join(scope_list))
    if url_list:   (folder / "urls.txt").write_text("\n".join(url_list))
    if domain:     (folder / "domain.txt").write_text(domain)

    scan_state["client_folder"] = folder
    scan_state["results"] = {
        "client": client, "date": date,
        "domain": domain, "scope_list": scope_list, "url_list": url_list,
    }

    return jsonify({
        "ok": True, "folder": str(folder),
        "scope_count": len(scope_list),
        "url_count":   len(url_list),
        "domain":      domain,
    })


@app.route("/api/start", methods=["POST"])
@login_required
def start_scan():
    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan already running."}), 409

    folder = scan_state.get("client_folder")
    if not folder:
        return jsonify({"ok": False, "error": "Submit engagement details first."}), 400

    data   = request.get_json()
    phases = {
        "recon": data.get("recon", True),
        "scan":  data.get("scan",  True),
        "vuln":  data.get("vuln",  True),
    }

    results    = scan_state["results"]
    scope_list = results.get("scope_list", [])
    url_list   = results.get("url_list",   [])
    domain     = results.get("domain",     "")
    tool_paths = scan_state.get("tool_paths", {})

    while not scan_state["log_queue"].empty():
        scan_state["log_queue"].get_nowait()

    scan_state["running"] = True
    t = threading.Thread(
        target=run_scan,
        args=(scope_list, url_list, domain, phases, folder, tool_paths),
        daemon=True,
    )
    t.start()
    return jsonify({"ok": True})


@app.route("/api/stream")
@login_required
def stream():
    def event_generator():
        while True:
            try:
                item = scan_state["log_queue"].get(timeout=30)
                yield f"data: {item['tag']}|{item['ts']}|{item['msg']}\n\n"
                if item.get("tag") == "control" and item.get("msg") == "__SCAN_COMPLETE__":
                    break
            except queue.Empty:
                yield ": keepalive\n\n"

    return Response(event_generator(),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/report", methods=["POST"])
@login_required
def generate_report():
    folder  = scan_state.get("client_folder")
    results = scan_state.get("results", {})

    if not folder or not results.get("client"):
        return jsonify({"ok": False, "error": "No scan data available."}), 400

    try:
        from report_generator import generate_reports
        pdf_path, docx_path = generate_reports(
            results, Path(folder),
            log_fn=lambda m, t="info": scan_state["log_queue"].put(
                {"ts": datetime.now().strftime("%H:%M:%S"), "msg": m, "tag": t}
            )
        )
        return jsonify({
            "ok":   True,
            "pdf":  f"/api/download/{pdf_path.name}",
            "docx": f"/api/download/{docx_path.name}",
        })
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


@app.route("/api/download/<filename>")
@login_required
def download_file(filename):
    folder = scan_state.get("client_folder")
    if not folder:
        return "No active session", 404
    file_path = Path(folder) / filename
    if not file_path.exists():
        return "File not found", 404
    return send_file(str(file_path), as_attachment=True)


@app.route("/api/save-assessment", methods=["POST"])
@login_required
def save_assessment_route():
    """Called when the user clicks Exit — saves to dashboard history."""
    results = scan_state.get("results", {})
    folder  = scan_state.get("client_folder")

    if not results.get("client"):
        return jsonify({"ok": False, "error": "No assessment to save."}), 400

    data   = request.get_json() or {}
    phases = data.get("phases", {"recon": True, "scan": True, "vuln": True})

    save_assessment(
        client  = results.get("client", "Unknown"),
        date    = results.get("date",   ""),
        domain  = results.get("domain", ""),
        folder  = str(folder) if folder else "",
        phases  = phases,
    )

    # Reset state
    scan_state["client_folder"] = None
    scan_state["results"]       = {}
    while not scan_state["log_queue"].empty():
        scan_state["log_queue"].get_nowait()

    return jsonify({"ok": True, "redirect": "/"})


@app.route("/api/reset", methods=["POST"])
@login_required
def reset():
    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan still running."}), 409
    scan_state["client_folder"] = None
    scan_state["results"]       = {}
    while not scan_state["log_queue"].empty():
        scan_state["log_queue"].get_nowait()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def startup():
    q = scan_state["log_queue"]

    def log_fn(msg, tag="info"):
        q.put({"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg, "tag": tag})
        print(f"[{tag.upper()}] {msg}")

    log_fn("╔══════════════════════════════════════╗", "phase")
    log_fn("║   ARTEMIS WEB — Starting up...       ║", "phase")
    log_fn("╚══════════════════════════════════════╝", "phase")
    tool_paths = check_and_install_tools(log_fn)
    scan_state["tool_paths"] = tool_paths
    log_fn("🌐 Artemis Web ready on http://localhost:5000", "success")


if __name__ == "__main__":
    startup_thread = threading.Thread(target=startup, daemon=True)
    startup_thread.start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


import os
import sys
import subprocess
import shutil
import threading
import re
import queue
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, send_file

# ── Root check ────────────────────────────────────────────────────────────
if os.geteuid() != 0:
    print("\n[!] Artemis requires root privileges.")
    print("    Run: sudo python3 artemis_web.py\n")
    sys.exit(1)

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════
RESULTS_BASE = Path("/opt/artemis/results")
RESULTS_BASE.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════
# TOOL CONSTANTS  (identical to desktop version)
# ══════════════════════════════════════════════════════════════════════════
APT_PACKAGES = {
    "nmap":         "nmap",
    "nikto":        "nikto",
    "sslscan":      "sslscan",
    "dnsenum":      "dnsenum",
    "curl":         "curl",
    "theHarvester": "theharvester",
}

GO_TOOLS = {
    "nuclei":      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf":        "github.com/ffuf/ffuf/v2@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "gowitness":   "github.com/sensepost/gowitness@latest",
    "termshot":    "github.com/homeport/termshot/cmd/termshot@latest",
}

PIP_TOOLS = {"pymeta": "pymeta3"}

SHCHECK_SEARCH_PATHS = [
    "/opt/shcheck/shcheck.py",
    "/usr/local/bin/shcheck.py",
    "/root/shcheck/shcheck.py",
    str(Path.home() / "shcheck" / "shcheck.py"),
    str(Path.home() / "tools"   / "shcheck.py"),
]
SPOOFY_SEARCH_PATHS = [
    "/opt/spoofy/spoofy.py",
    "/root/spoofy/spoofy.py",
    str(Path.home() / "tools"  / "spoofy.py"),
    str(Path.home() / "spoofy" / "spoofy.py"),
]
O365SCAN_SEARCH_PATHS = [
    "/opt/o365spray/o365spray.py",
    "/root/o365spray/o365spray.py",
    str(Path.home() / "tools"    / "o365spray.py"),
    str(Path.home() / "o365spray" / "o365spray.py"),
]

# ══════════════════════════════════════════════════════════════════════════
# GLOBAL SCAN STATE
# ══════════════════════════════════════════════════════════════════════════
scan_state = {
    "running":       False,
    "log_queue":     queue.Queue(),
    "results":       {},
    "client_folder": None,
    "tool_paths":    {},
}


# ══════════════════════════════════════════════════════════════════════════
# TOOL HELPERS  (shared with desktop version)
# ══════════════════════════════════════════════════════════════════════════

def _add_to_path(directory: str, log_fn):
    if directory and directory not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = os.environ.get("PATH", "") + f":{directory}"
        log_fn(f"↳ Added to PATH: {directory}", "dim")


def _find_tool_on_disk(tool: str) -> str | None:
    SEARCH_DIRS = [
        "/root/go/bin", "/usr/local/bin", "/usr/bin",
        "/opt/metasploit-framework/bin", "/opt/metasploit/bin",
    ]
    for d in SEARCH_DIRS:
        candidate = Path(d) / tool
        if candidate.exists() and os.access(str(candidate), os.X_OK):
            return d
    try:
        result = subprocess.run(
            ["find", "/usr", "/opt", "/root", "/home",
             "-name", tool, "-type", "f", "-maxdepth", "8"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and os.access(line, os.X_OK):
                return str(Path(line).parent)
    except Exception:
        pass
    return None


def _find_script(search_paths: list, name: str) -> str | None:
    for p in search_paths:
        if Path(p).exists():
            return p
    try:
        result = subprocess.run(
            ["find", "/", "-name", name, "-maxdepth", "7"],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines[0] if lines else None
    except Exception:
        return None


def find_shcheck() -> str | None:
    for p in SHCHECK_SEARCH_PATHS:
        if Path(p).exists():
            return p
    try:
        result = subprocess.run(
            ["find", "/", "-name", "shcheck.py", "-maxdepth", "6"],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines[0] if lines else None
    except Exception:
        return None


def check_and_install_tools(log_fn):
    """Identical logic to desktop version — returns tool_paths dict."""
    log_fn("🔍 Checking required tools...", "info")

    for go_bin in ["/root/go/bin", "/usr/local/go/bin"]:
        if Path(go_bin).is_dir():
            _add_to_path(go_bin, log_fn)

    for tool, pkg in APT_PACKAGES.items():
        if shutil.which(tool) is None:
            log_fn(f"  Installing {tool} via apt...", "warn")
            subprocess.run(["apt-get", "install", "-y", pkg], capture_output=True)
        found = shutil.which(tool)
        if found:
            _add_to_path(str(Path(found).parent), log_fn)
            log_fn(f"  ✓ {tool}", "success")
        else:
            disc = _find_tool_on_disk(tool)
            if disc:
                _add_to_path(disc, log_fn)
                log_fn(f"  ✓ {tool} (resolved)", "success")
            else:
                log_fn(f"  ✗ {tool} — not found", "error")

    go_path = shutil.which("go")
    for tool, module in GO_TOOLS.items():
        if shutil.which(tool) is None:
            if go_path:
                log_fn(f"  Installing {tool} via go install...", "warn")
                subprocess.run(["go", "install", module],
                               capture_output=True,
                               env={**os.environ, "GOPATH": "/root/go"})
            else:
                log_fn(f"  ✗ {tool} — Go not found", "error")
        found = shutil.which(tool)
        if found:
            _add_to_path(str(Path(found).parent), log_fn)
            log_fn(f"  ✓ {tool}", "success")
        else:
            disc = _find_tool_on_disk(tool)
            if disc:
                _add_to_path(disc, log_fn)
                log_fn(f"  ✓ {tool} (resolved)", "success")
            else:
                log_fn(f"  ✗ {tool} — not found after install", "error")

    found = shutil.which("msfconsole")
    if found:
        _add_to_path(str(Path(found).parent), log_fn)
        log_fn("  ✓ msfconsole", "success")
    else:
        disc = _find_tool_on_disk("msfconsole")
        if disc:
            _add_to_path(disc, log_fn)
            log_fn("  ✓ msfconsole (resolved)", "success")
        else:
            log_fn("  ✗ msfconsole — install manually", "error")

    if shutil.which("nuclei"):
        log_fn("  Updating nuclei templates...", "info")
        subprocess.run(["nuclei", "-update-templates"], capture_output=True)
        log_fn("  ✓ nuclei templates updated", "success")

    for tool, pkg in PIP_TOOLS.items():
        found = shutil.which(tool)
        if not found:
            log_fn(f"  Installing {tool} via pip...", "warn")
            subprocess.run(["pip3", "install", pkg, "--break-system-packages"],
                           capture_output=True)
            found = shutil.which(tool)
        if found:
            _add_to_path(str(Path(found).parent), log_fn)
            log_fn(f"  ✓ {tool}", "success")
        else:
            log_fn(f"  ✗ {tool} — pip install failed", "error")

    shcheck  = find_shcheck()
    spoofy   = _find_script(SPOOFY_SEARCH_PATHS,   "spoofy.py")
    o365scan = _find_script(O365SCAN_SEARCH_PATHS, "o365spray.py")

    log_fn(f"  {'✓' if shcheck  else '✗'} shcheck.py  {'found' if shcheck  else 'not found'}", "success" if shcheck  else "warn")
    log_fn(f"  {'✓' if spoofy   else '✗'} spoofy.py   {'found' if spoofy   else 'not found'}", "success" if spoofy   else "warn")
    log_fn(f"  {'✓' if o365scan else '✗'} o365spray   {'found' if o365scan else 'not found'}", "success" if o365scan else "warn")

    log_fn("✅ Tool check complete.", "success")
    return {"shcheck": shcheck, "spoofy": spoofy, "o365scan": o365scan}


# ══════════════════════════════════════════════════════════════════════════
# SCAN ENGINE  (ported directly from desktop _run_scan)
# ══════════════════════════════════════════════════════════════════════════

def _write_msf_rc(path: Path, scope_list: list[str]):
    rhosts = " ".join(scope_list)
    path.write_text(f"""# Auto-generated by Artemis
setg RHOSTS {rhosts}
setg THREADS 10
use auxiliary/scanner/http/http_version
run
use auxiliary/scanner/ssh/ssh_version
run
use auxiliary/scanner/ftp/ftp_version
run
use auxiliary/scanner/smtp/smtp_version
run
use auxiliary/scanner/ssl/openssl_heartbleed
run
use auxiliary/scanner/smb/smb_version
run
use auxiliary/scanner/smb/smb_ms17_010
run
exit
""")


def run_scan(scope_list, url_list, domain,
             phases, folder, tool_paths):
    """
    Main scan engine — runs in a background thread.
    All output goes through scan_state['log_queue'] for SSE streaming.
    """
    lq = scan_state["log_queue"]

    def log(msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        lq.put({"ts": ts, "msg": msg, "tag": tag})
        # Also write to log file if folder exists
        if folder and folder.exists():
            with open(folder / "artemis.log", "a") as f:
                f.write(f"[{ts}] {msg}\n")

    def phase(title):
        log("─" * 52, "phase")
        log(f"  {title}", "phase")
        log("─" * 52, "phase")

    def run_tool(cmd, out_file, label, screenshot_name=None):
        log(f"⟶ {label}", "info")
        try:
            with open(out_file, "w") as fh:
                r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                   text=True, timeout=600)
            if r.returncode not in (0, 1):
                log(f"⚠ {label} exited with code {r.returncode}", "warn")
            else:
                log(f"✓ {label} complete", "success")
            if screenshot_name and shutil.which("termshot"):
                try:
                    png = evidence_dir / f"{screenshot_name}.png"
                    subprocess.run(["termshot", "-f", str(png), "--"] + cmd,
                                   capture_output=True, timeout=120)
                except Exception:
                    pass
            return r.returncode
        except subprocess.TimeoutExpired:
            log(f"✗ {label} timed out", "error")
            return -1
        except FileNotFoundError:
            log(f"✗ {label} — tool not found in PATH", "error")
            return 127

    shcheck_path  = tool_paths.get("shcheck")
    spoofy_path   = tool_paths.get("spoofy")
    o365scan_path = tool_paths.get("o365scan")

    evidence_dir = folder / "Assessment_Evidence"
    evidence_dir.mkdir(exist_ok=True)

    results = {
        "client":        scan_state["results"].get("client", ""),
        "date":          scan_state["results"].get("date", ""),
        "domain":        domain,
        "targets":       scope_list,
        "scope_list":    scope_list,
        "url_list":      url_list,
        "subdomains":    [],
        "open_ports":    {},
        "vulnerabilities":  {},
        "missing_headers":  {},
        "ffuf_findings":    {},
        "msf_findings":     [],
        "o365_findings":    {},
        "harvester":        {},
        "pymeta":           [],
    }

    # ── PHASE 1 ────────────────────────────────────────────────────────
    if phases.get("recon"):
        phase("PHASE 1 — Reconnaissance / OSINT")
        p1 = folder / "1_recon"; p1.mkdir(exist_ok=True)
        subdomains_found = []

        osint_targets = [domain] if domain else scope_list
        for target in osint_targets:
            safe_t = re.sub(r"[^\w\-]", "_", target)
            log(f"  OSINT target: {target}", "dim")

            run_tool(["assetfinder", "--subs-only", target],
                     p1 / f"assetfinder_{target}.txt",
                     f"assetfinder [{target}]",
                     screenshot_name=f"phase1_assetfinder_{safe_t}")
            sf = p1 / f"assetfinder_{target}.txt"
            if sf.exists():
                subdomains_found.extend(
                    [l.strip() for l in sf.read_text().splitlines() if l.strip()])

            run_tool(["dnsenum", "--enum", "--noreverse", target],
                     p1 / f"dnsenum_{target}.txt",
                     f"dnsenum [{target}]",
                     screenshot_name=f"phase1_dnsenum_{safe_t}")

        # curl header sweep
        log("⟶ curl security header sweep...", "info")
        sweep_file = p1 / "security_headers_sweep.txt"
        with open(sweep_file, "w") as hsf:
            for url in url_list:
                hsf.write(f"\n{'='*60}\n{url}\n{'='*60}\n")
                try:
                    r = subprocess.run(
                        ["curl", "-s", "-I", "--max-time", "10", "-L",
                         "-A", "Mozilla/5.0", url],
                        capture_output=True, text=True, timeout=15)
                    hsf.write(r.stdout)
                except Exception as ex:
                    hsf.write(f"ERROR: {ex}\n")
        log("✓ curl header sweep complete", "success")

        results["subdomains"] = list(set(subdomains_found))

        if domain and spoofy_path:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            run_tool(["python3", spoofy_path, "-d", domain],
                     p1 / f"spoofy_{safe_d}.txt",
                     f"spoofy [{domain}]",
                     screenshot_name=f"phase1_spoofy_{safe_d}")
        elif domain:
            log("⚠ spoofy.py not found — skipping", "warn")

        if domain and o365scan_path:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            o365_out = p1 / f"o365scan_{safe_d}.txt"
            run_tool(["python3", o365scan_path,
                      "--validate", "--domain", domain, "--output", str(p1)],
                     o365_out,
                     f"o365spray [{domain}]",
                     screenshot_name=f"phase1_o365scan_{safe_d}")
            if o365_out.exists():
                raw = o365_out.read_text()
                results["o365_findings"] = {
                    "domain": domain, "raw": raw[:4000],
                    "o365":     "Microsoft 365" in raw or "True" in raw,
                    "adfs":     "ADFS" in raw,
                    "exchange": "Exchange" in raw,
                }
        elif domain:
            log("⚠ o365spray not found — skipping", "warn")

        if domain:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            run_tool(["theHarvester", "-d", domain, "-b", "all", "-l", "500"],
                     p1 / f"theharvester_{safe_d}.txt",
                     f"theHarvester [{domain}]",
                     screenshot_name=f"phase1_theharvester_{safe_d}")
            h_txt = p1 / f"theharvester_{safe_d}.txt"
            hdata = {"emails": [], "ips": [], "subdomains": []}
            if h_txt.exists():
                content = h_txt.read_text()
                hdata["emails"] = re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", content)
                hdata["ips"]    = re.findall(
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
                hdata["subdomains"] = [
                    l.strip() for l in content.splitlines()
                    if l.strip().endswith(f".{domain}") and " " not in l.strip()]
            results["harvester"] = hdata
            results["subdomains"] = list(set(
                results["subdomains"] + hdata["subdomains"]))
        else:
            log("⚠ No domain — skipping theHarvester", "warn")

        if domain:
            safe_d = re.sub(r"[^\w\-]", "_", domain)
            pymeta_exts = (
                "txt,pdf,xls,xlsx,csv,doc,docx,ppt,config,log,bat,env,ini,"
                "yaml,py,php,bak,old,tmp,swp,asp,aspx,jsp,go,java,c,debug,"
                "trace,sql,db,git,dump,mdb,sqlite,hg,svn,zip,tar,rar,7z,tgz,"
                "rst,pem,key,crt,pfx,json,html"
            )
            pymeta_out = p1 / f"pymeta_{safe_d}.txt"
            run_tool(["pymeta", "-d", domain, "-t", pymeta_exts, "-o", str(pymeta_out)],
                     pymeta_out,
                     f"pymeta [{domain}]",
                     screenshot_name=f"phase1_pymeta_{safe_d}")
            if pymeta_out.exists():
                results["pymeta"] = [
                    l.strip() for l in pymeta_out.read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
        else:
            log("⚠ No domain — skipping pymeta", "warn")

    # ── PHASE 2 ────────────────────────────────────────────────────────
    if phases.get("scan"):
        phase("PHASE 2 — Port & Service Scanning")
        p2 = folder / "2_scan"; p2.mkdir(exist_ok=True)
        open_ports     = {}
        gowitness_urls = []

        for target in scope_list:
            safe_t = re.sub(r"[^\w\-]", "_", target)
            log(f"  nmap target: {target}", "dim")

            run_tool(["nmap", "-sS", "-sV", "-sC", "-p-", "--open",
                      "-T4", "--min-rate", "1000",
                      "-oN", str(p2 / f"nmap_tcp_{target}.txt"), target],
                     p2 / f"nmap_tcp_{target}.txt",
                     f"nmap TCP [{target}]",
                     screenshot_name=f"phase2_nmap_tcp_{safe_t}")

            txt_file = p2 / f"nmap_tcp_{target}.txt"
            ports = []
            if txt_file.exists():
                ports = re.findall(r"(\d+)/tcp\s+open", txt_file.read_text())
                open_ports[target] = ports
                web_ports = {"80","443","8080","8443","8000","8888",
                             "9090","3000","4443","4080"}
                for p in ports:
                    scheme = "https" if p in {"443","8443","4443"} else "http"
                    if p in web_ports:
                        gowitness_urls.append(f"{scheme}://{target}:{p}")
                    elif p not in {"80","443"}:
                        gowitness_urls.append(f"http://{target}:{p}")
                gowitness_urls += [f"http://{target}", f"https://{target}"]

            run_tool(["nmap", "-sU", "--top-ports", "200", "-T4",
                      "-oN", str(p2 / f"nmap_udp_{target}.txt"), target],
                     p2 / f"nmap_udp_{target}.txt",
                     f"nmap UDP [{target}]",
                     screenshot_name=f"phase2_nmap_udp_{safe_t}")

        results["open_ports"] = open_ports

        if shutil.which("gowitness") and gowitness_urls:
            log("⟶ gowitness — screenshotting web ports...", "info")
            gw_dir = p2 / "gowitness"; gw_dir.mkdir(exist_ok=True)
            unique_urls = list(dict.fromkeys(gowitness_urls))
            urls_file = gw_dir / "urls.txt"
            urls_file.write_text("\n".join(unique_urls))
            log(f"  ↳ {len(unique_urls)} URLs queued", "dim")
            try:
                with open(gw_dir / "gowitness.log", "w") as gwl:
                    subprocess.run(
                        ["gowitness", "file",
                         "-f", str(urls_file),
                         "-P", str(gw_dir / "screenshots"),
                         "--threads", "5"],
                        stdout=gwl, stderr=subprocess.STDOUT,
                        text=True, timeout=900)
                log("✓ gowitness complete", "success")
                screenshots_src = gw_dir / "screenshots"
                if screenshots_src.exists():
                    for img in screenshots_src.glob("*.png"):
                        shutil.copy2(str(img),
                                     str(evidence_dir / f"gowitness_{img.name}"))
                    log("📸 gowitness screenshots copied to Assessment_Evidence/", "dim")
            except Exception as ex:
                log(f"✗ gowitness error: {ex}", "error")
        elif not shutil.which("gowitness"):
            log("⚠ gowitness not found — skipping screenshots", "warn")

    # ── PHASE 3 ────────────────────────────────────────────────────────
    if phases.get("vuln"):
        phase("PHASE 3 — Vulnerability Scanning")
        p3 = folder / "3_vuln"; p3.mkdir(exist_ok=True)
        vulnerabilities = {}
        missing_headers = {}
        ffuf_findings   = {}
        msf_findings    = []

        for url in url_list:
            target_key = re.sub(r"^https?://", "", url).rstrip("/")
            safe_t     = re.sub(r"[^\w\-]", "_", target_key)
            vulnerabilities[target_key] = []
            log(f"  Vuln target: {url}", "dim")

            host = re.sub(r"^https?://", "", url).rstrip("/")
            run_tool(["sslscan", "--show-certificate", host],
                     p3 / f"sslscan_{safe_t}.txt",
                     f"sslscan [{host}]",
                     screenshot_name=f"phase3_sslscan_{safe_t}")

            if shcheck_path:
                run_tool(["python3", shcheck_path, url, "-v"],
                         p3 / f"shcheck_{safe_t}.txt",
                         f"shcheck [{url}]",
                         screenshot_name=f"phase3_shcheck_{safe_t}")
                sf = p3 / f"shcheck_{safe_t}.txt"
                if sf.exists():
                    missing = re.findall(
                        r"Missing security header:\s*(.+)", sf.read_text())
                    if missing:
                        missing_headers[target_key] = missing
            else:
                log("⚠ shcheck.py not found — skipping", "warn")

            run_tool(["nikto", "-h", url,
                      "-o", str(p3 / f"nikto_{safe_t}.xml"),
                      "-Format", "xml", "-nointeractive"],
                     p3 / f"nikto_{safe_t}.txt",
                     f"nikto [{url}]",
                     screenshot_name=f"phase3_nikto_{safe_t}")
            nf = p3 / f"nikto_{safe_t}.txt"
            if nf.exists():
                findings = re.findall(r"\+ (.+)", nf.read_text())
                vulnerabilities[target_key].extend(findings[:20])

            run_tool(["nuclei", "-u", url,
                      "-severity", "low,medium,high,critical",
                      "-o", str(p3 / f"nuclei_{safe_t}.txt"), "-silent"],
                     p3 / f"nuclei_raw_{safe_t}.txt",
                     f"nuclei [{url}]",
                     screenshot_name=f"phase3_nuclei_{safe_t}")
            nuf = p3 / f"nuclei_{safe_t}.txt"
            if nuf.exists():
                nlines = [l.strip() for l in nuf.read_text().splitlines() if l.strip()]
                vulnerabilities[target_key].extend(nlines[:30])

            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not Path(wordlist).exists():
                wordlist = "/usr/share/wordlists/dirb/common.txt"
            if Path(wordlist).exists():
                ffuf_txt = p3 / f"ffuf_{safe_t}.txt"
                run_tool(["ffuf", "-u", f"{url}/FUZZ",
                          "-w", wordlist,
                          "-o", str(ffuf_txt), "-of", "csv",
                          "-mc", "200,201,301,302,403",
                          "-t", "50", "-s"],
                         ffuf_txt,
                         f"ffuf [{url}]",
                         screenshot_name=f"phase3_ffuf_{safe_t}")
                if ffuf_txt.exists():
                    try:
                        found_200 = []
                        for line in ffuf_txt.read_text().splitlines():
                            parts = line.split(",")
                            if len(parts) >= 4:
                                try:
                                    if int(parts[3].strip()) == 200:
                                        found_200.append({"url": parts[0].strip(),
                                                          "status": 200})
                                except ValueError:
                                    pass
                        ffuf_findings[target_key] = found_200
                    except Exception:
                        pass
            else:
                log(f"⚠ No wordlist found for ffuf [{url}]", "warn")

        msf_rc = folder / "msf_scan.rc"
        if not msf_rc.exists():
            _write_msf_rc(msf_rc, scope_list)
        run_tool(["msfconsole", "-q", "-r", str(msf_rc)],
                 p3 / "metasploit.txt",
                 "metasploit auxiliary scanners",
                 screenshot_name="phase3_metasploit")
        msf_txt = p3 / "metasploit.txt"
        if msf_txt.exists():
            msf_findings = re.findall(r"\[\+\].*", msf_txt.read_text())

        results.update({
            "vulnerabilities": vulnerabilities,
            "missing_headers": missing_headers,
            "ffuf_findings":   ffuf_findings,
            "msf_findings":    msf_findings,
        })

    scan_state["results"].update(results)

    log("", "info")
    log("╔══════════════════════════════════════╗", "phase")
    log("║   ✅  SCAN COMPLETE                  ║", "phase")
    log("╚══════════════════════════════════════╝", "phase")
    log("__SCAN_COMPLETE__", "control")
    scan_state["running"] = False


# ══════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/startup-status")
def startup_status():
    """Return current tool path state for UI display."""
    tp = scan_state.get("tool_paths", {})
    return jsonify({
        "shcheck":  bool(tp.get("shcheck")),
        "spoofy":   bool(tp.get("spoofy")),
        "o365scan": bool(tp.get("o365scan")),
        "ready":    True,
    })


@app.route("/api/submit", methods=["POST"])
def submit():
    """Validate inputs, create folder, write target files."""
    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan already in progress."}), 409

    data       = request.get_json()
    client     = data.get("client", "").strip()
    date       = data.get("date", datetime.now().strftime("%Y-%m-%d")).strip()
    domain     = re.sub(r"^https?://", "", data.get("domain", "").strip()).rstrip("/").lower()
    scope_raw  = data.get("scope", "").strip()
    urls_raw   = data.get("urls", "").strip()

    if not client:
        return jsonify({"ok": False, "error": "Client name is required."}), 400
    if not scope_raw and not urls_raw and not domain:
        return jsonify({"ok": False, "error": "Enter at least one target."}), 400

    scope_list = [re.sub(r"^https?://", "", l).rstrip("/").strip()
                  for l in scope_raw.splitlines() if l.strip()]
    url_list   = [l.strip() for l in urls_raw.splitlines() if l.strip()]

    safe   = re.sub(r"[^\w\-_ ]", "_", client)
    folder = RESULTS_BASE / f"{safe}_{date}"
    folder.mkdir(parents=True, exist_ok=True)

    if scope_list: (folder / "scope.txt").write_text("\n".join(scope_list))
    if url_list:   (folder / "urls.txt").write_text("\n".join(url_list))
    if domain:     (folder / "domain.txt").write_text(domain)

    scan_state["client_folder"] = folder
    scan_state["results"] = {
        "client":     client,
        "date":       date,
        "domain":     domain,
        "scope_list": scope_list,
        "url_list":   url_list,
    }

    return jsonify({
        "ok":          True,
        "folder":      str(folder),
        "scope_count": len(scope_list),
        "url_count":   len(url_list),
        "domain":      domain,
    })


@app.route("/api/start", methods=["POST"])
def start_scan():
    """Launch the scan in a background thread."""
    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan already running."}), 409

    folder = scan_state.get("client_folder")
    if not folder:
        return jsonify({"ok": False, "error": "Submit engagement details first."}), 400

    data   = request.get_json()
    phases = {
        "recon": data.get("recon", True),
        "scan":  data.get("scan",  True),
        "vuln":  data.get("vuln",  True),
    }

    results      = scan_state["results"]
    scope_list   = results.get("scope_list", [])
    url_list     = results.get("url_list",   [])
    domain       = results.get("domain",     "")
    tool_paths   = scan_state.get("tool_paths", {})

    # Clear the log queue for this new run
    while not scan_state["log_queue"].empty():
        scan_state["log_queue"].get_nowait()

    scan_state["running"] = True
    t = threading.Thread(
        target=run_scan,
        args=(scope_list, url_list, domain, phases, folder, tool_paths),
        daemon=True,
    )
    t.start()
    return jsonify({"ok": True})


@app.route("/api/stream")
def stream():
    """Server-Sent Events endpoint — streams log lines to the browser."""
    def event_generator():
        while True:
            try:
                item = scan_state["log_queue"].get(timeout=30)
                data = (f"data: {item['tag']}|{item['ts']}|{item['msg']}\n\n")
                yield data
                if item.get("tag") == "control" and item.get("msg") == "__SCAN_COMPLETE__":
                    break
            except queue.Empty:
                # Send keepalive comment
                yield ": keepalive\n\n"

    return Response(event_generator(),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/report", methods=["POST"])
def generate_report():
    """Generate PDF and DOCX reports and return download links."""
    folder = scan_state.get("client_folder")
    results = scan_state.get("results", {})

    if not folder or not results.get("client"):
        return jsonify({"ok": False, "error": "No scan data available."}), 400

    try:
        from report_generator import generate_reports
        pdf_path, docx_path = generate_reports(
            results, Path(folder),
            log_fn=lambda m, t="info": scan_state["log_queue"].put(
                {"ts": datetime.now().strftime("%H:%M:%S"), "msg": m, "tag": t}
            )
        )
        return jsonify({
            "ok":   True,
            "pdf":  f"/api/download/{pdf_path.name}",
            "docx": f"/api/download/{docx_path.name}",
        })
    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 500


@app.route("/api/download/<filename>")
def download_file(filename):
    folder = scan_state.get("client_folder")
    if not folder:
        return "No active session", 404
    file_path = Path(folder) / filename
    if not file_path.exists():
        return "File not found", 404
    return send_file(str(file_path), as_attachment=True)


@app.route("/api/reset", methods=["POST"])
def reset():
    """Reset state for a new scan."""
    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan still running."}), 409
    scan_state["client_folder"] = None
    scan_state["results"] = {}
    while not scan_state["log_queue"].empty():
        scan_state["log_queue"].get_nowait()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def startup():
    """Run tool checks on launch — populates scan_state['tool_paths']."""
    q = scan_state["log_queue"]

    def log_fn(msg, tag="info"):
        q.put({"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg, "tag": tag})
        print(f"[{tag.upper()}] {msg}")

    log_fn("╔══════════════════════════════════════╗", "phase")
    log_fn("║   ARTEMIS WEB — Starting up...       ║", "phase")
    log_fn("╚══════════════════════════════════════╝", "phase")
    tool_paths = check_and_install_tools(log_fn)
    scan_state["tool_paths"] = tool_paths
    log_fn("🌐 Artemis Web ready on http://localhost:5000", "success")


if __name__ == "__main__":
    startup_thread = threading.Thread(target=startup, daemon=True)
    startup_thread.start()
    # Bind to localhost only — access via SSH tunnel
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
