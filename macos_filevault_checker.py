import subprocess
import csv
import logging
import socket
import os
import sys
import tempfile
import shutil
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

# --- Configuration (injected via Jamf script parameters $4-$6 in production) ---
ITSM_API_URL  = os.environ.get("ITSM_API_URL",  "https://api.itsm.local/v1/tickets")
ITSM_API_KEY  = os.environ.get("ITSM_API_KEY",  "mock_key")
EMAIL_API_URL = os.environ.get("EMAIL_API_URL",  "https://api.mailer.local/v1/send")
EMAIL_API_KEY = os.environ.get("EMAIL_API_KEY",  "mock_email_key")
EMAIL_FROM    = os.environ.get("EMAIL_FROM",     "it-ops@wave.com")
CSV_PATH      = os.environ.get("ASSET_CSV",      "/var/log/mock_asset_db.csv")
LOG_FILE      = "/var/log/filevault_compliance.log"

# --- Logging: file for Jamf log collection + stdout for policy output ---
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

CSV_FIELDS = ["serial", "hostname", "user", "os_version", "fv_state", "last_check"]


def device_info():
    """Collect endpoint metadata. Serial number is the primary asset key."""
    # Console user: script runs as root, we want the logged-in user
    try:
        user = subprocess.run(["stat", "-f", "%Su", "/dev/console"],
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        user = os.environ.get("USER", "unknown")

    # Serial number: survives reimages, more reliable than hostname
    serial = "unknown"
    try:
        out = subprocess.run(["system_profiler", "SPHardwareDataType"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            if "Serial Number" in line:
                serial = line.split(":")[-1].strip()
                break
    except Exception:
        pass

    # OS version
    try:
        os_ver = subprocess.run(["sw_vers", "-productVersion"],
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        os_ver = "unknown"

    return {
        "serial":     serial,
        "hostname":   socket.gethostname(),
        "user":       user,
        "user_email": f"{user}@wave.com",  # Production: query Google Workspace Directory API
        "os_version": os_ver,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }


def check_filevault():
    """Query FileVault state via fdesetup. Returns True if enabled."""
    result = subprocess.run(["fdesetup", "status"], capture_output=True, text=True, timeout=15)
    log.info(f"fdesetup: {result.stdout.strip()}")
    if "FileVault is On" in result.stdout:
        return True
    if "FileVault is Off" in result.stdout:
        return False
    raise RuntimeError(f"Unexpected fdesetup output: {result.stdout.strip()}")


def update_csv(device, fv_enabled):
    """Update asset CSV record by serial number. Atomic write to prevent corruption."""
    fv_str = "Enabled" if fv_enabled else "Disabled"

    # Initialise CSV if it does not exist
    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_FIELDS).writeheader()

    rows, found = [], False
    with open(CSV_PATH, "r", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("serial") == device["serial"]:
                row.update({"hostname": device["hostname"], "user": device["user"],
                            "os_version": device["os_version"], "fv_state": fv_str,
                            "last_check": device["timestamp"]})
                found = True
            rows.append(row)

    if not found:
        rows.append({"serial": device["serial"], "hostname": device["hostname"],
                     "user": device["user"], "os_version": device["os_version"],
                     "fv_state": fv_str, "last_check": device["timestamp"]})

    # Atomic write: temp file then rename to prevent partial writes
    with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(CSV_PATH),
                                     delete=False, suffix=".tmp", newline="") as tmp:
        w = csv.DictWriter(tmp, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    shutil.move(tmp.name, CSV_PATH)
    log.info(f"Asset CSV updated: {device['serial']} | FV: {fv_str}")


def api_post(url, key, payload, label):
    """Shared POST helper using zero-dependency urllib."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status in (200, 201, 202):
                log.info(f"{label} API call succeeded.")
                return True
            log.warning(f"{label} API unexpected status: {response.status}")
            return False
    except urllib.error.URLError as e:
        log.warning(f"{label} API unreachable. Logged locally. Error: {e.reason}")
        return False
    except Exception as e:
        log.error(f"{label} API error: {e}")
        return False


def send_email(device):
    """Notify user that FileVault is disabled and IT will follow up."""
    payload = {
        "from":    {"email": EMAIL_FROM, "name": "IT Operations"},
        "to":      [{"email": device["user_email"]}],
        "subject": "Action Required: Disk Encryption Not Enabled on Your Mac",
        "text":    (f"Hi {device['user']},\n\n"
                    f"FileVault disk encryption is currently disabled on your Mac "
                    f"({device['hostname']}). This is required on all company devices.\n\n"
                    "A member of the IT team will be in contact shortly. "
                    "No action is needed from you right now.\n\n"
                    "Questions? Reach us at #it-support on Slack.\n\nIT Operations"),
    }
    return api_post(EMAIL_API_URL, EMAIL_API_KEY, payload, "Email")


def create_ticket(device, subject, body, priority):
    """Create ITSM ticket for audit or remediation."""
    payload = {
        "subject":     subject,
        "description": body,
        "priority":    priority,
        "source":      "jamf-policy-script",
        "device":      device,
    }
    return api_post(ITSM_API_URL, ITSM_API_KEY, payload, "ITSM")


def main():
    device = device_info()
    log.info(f"FileVault compliance check | {device['hostname']} | {device['serial']} | {device['timestamp']}")

    # 1. Check FileVault state
    try:
        fv_enabled = check_filevault()
    except Exception as e:
        log.error(f"FileVault check failed: {e}")
        create_ticket(device, f"[ERROR] FileVault check failed: {device['hostname']}",
                      f"Could not determine FileVault state: {e}", priority="high")
        sys.exit(1)

    # 2. Update asset record regardless of outcome
    update_csv(device, fv_enabled)

    # 3. Branch on result
    if fv_enabled:
        log.info("COMPLIANT: FileVault is enabled.")
        create_ticket(device, f"[AUDIT] FileVault compliant: {device['hostname']}",
                      "FileVault is enabled. Asset record updated.", priority="low")
        sys.exit(0)

    # FileVault disabled: notify user and escalate to IT
    log.warning("NON-COMPLIANT: FileVault is disabled.")
    send_email(device)
    create_ticket(
        device,
        f"[COMPLIANCE] FileVault disabled: {device['hostname']}",
        f"FileVault is DISABLED.\n\n"
        f"Host: {device['hostname']} | Serial: {device['serial']}\n"
        f"User: {device['user']} ({device['user_email']})\n"
        f"macOS: {device['os_version']} | Checked: {device['timestamp']}\n\n"
        "Remediation options:\n"
        "  1. Push FileVault enablement via Jamf Pro policy\n"
        "  2. Guide user via System Settings > Privacy & Security > FileVault\n"
        "  3. Verify bootstrap token escrowed to Jamf after enablement",
        priority="high",
    )
    sys.exit(1)  # Signals Jamf non-compliance for smart group scoping


if __name__ == "__main__":
    main()
