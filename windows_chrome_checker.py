import subprocess
import logging
import socket
import platform
import os
import sys
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

# --- Configuration (injected via Intune script parameters in production) ---
ITSM_API_URL = os.environ.get("ITSM_API_URL", "https://api.itsm.local/v1/tickets")
ITSM_API_KEY = os.environ.get("ITSM_API_KEY", "mock_key")
CHROME_ID    = "Google.Chrome"
LOG_FILE     = os.path.join(os.environ.get("TEMP", r"C:\ProgramData\IT"), "chrome_compliance.log")

# --- Logging: file for Intune log collection + stdout for run output ---
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


def device_info():
    """Collect endpoint metadata for audit context."""
    return {
        "hostname":  socket.gethostname(),
        "os":        platform.platform(),
        "user":      os.environ.get("USERNAME", "SYSTEM"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def log_ticket(subject, description, priority="low"):
    """POST audit or incident ticket to ITSM API using zero-dependency urllib."""
    ctx = device_info()
    payload = {
        "subject":     subject,
        "description": f"{description}\n\nHost: {ctx['hostname']} | User: {ctx['user']} | {ctx['timestamp']}",
        "priority":    priority,
        "source":      "intune-proactive-remediation",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        ITSM_API_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {ITSM_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status in (200, 201):
                log.info(f"Ticket created — priority: {priority}")
            else:
                log.warning(f"Unexpected API response: {response.status}")
    except urllib.error.URLError as e:
        # Device may be offline — log locally for Intune log collection
        log.warning(f"ITSM unreachable. Pending ticket: [{priority}] {subject}. Error: {e.reason}")
    except Exception as e:
        log.error(f"Ticket creation failed: {e}")


def is_chrome_installed():
    """Check Chrome via winget with filesystem fallback."""
    try:
        # SYSTEM context winget needs accept flags to behave correctly
        result = subprocess.run(
            ["winget", "list", "--id", CHROME_ID, "--accept-source-agreements"],
            capture_output=True, text=True, timeout=30,
        )
        if CHROME_ID.lower() in result.stdout.lower():
            return True
    except FileNotFoundError:
        log.warning("winget not found, falling back to filesystem check.")
    except subprocess.TimeoutExpired:
        log.warning("winget timed out, falling back to filesystem check.")

    # Fallback: known install paths
    paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    return any(os.path.isfile(p) for p in paths)


def install_chrome():
    """Silent Chrome install via winget. 3-min timeout for slow connections."""
    log.info("Installing Chrome via winget...")
    try:
        result = subprocess.run(
            ["winget", "install", "--id", CHROME_ID, "--silent",
             "--accept-package-agreements", "--accept-source-agreements", "--force"],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode == 0:
            return True
        log.error(f"winget failed (exit {result.returncode}): {result.stderr[:200]}")
    except FileNotFoundError:
        log.error("winget not available.")
    except subprocess.TimeoutExpired:
        log.error("Install timed out after 180s.")
    except Exception as e:
        log.error(f"Unexpected error: {e}")
    return False


def main():
    ctx = device_info()
    log.info(f"Chrome compliance check | {ctx['hostname']} | {ctx['timestamp']}")

    # 1. Check current state
    if is_chrome_installed():
        log.info("COMPLIANT: Chrome is installed.")
        log_ticket(f"[AUDIT] Chrome compliant: {ctx['hostname']}",
                   "Chrome is installed. No action required.")
        sys.exit(0)

    # 2. Attempt remediation
    log.warning("Chrome missing. Attempting remediation.")
    if install_chrome() and is_chrome_installed():
        log.info("REMEDIATED: Chrome installed and verified.")
        log_ticket(f"[REMEDIATED] Chrome installed: {ctx['hostname']}",
                   "Chrome was missing and has been installed via winget.", priority="medium")
        sys.exit(0)

    # 3. Escalate to IT
    log.error("FAILED: Remediation unsuccessful. Escalating to IT.")
    log_ticket(
        f"[MANUAL REQUIRED] Chrome install failed: {ctx['hostname']}",
        "Automated remediation failed. Manual intervention required.\n"
        "Check: winget availability, AppLocker/WDAC policy, Intune Win32 app fallback.\n"
        f"Logs: {LOG_FILE}",
        priority="high",
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
