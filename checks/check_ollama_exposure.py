"""
Check: ollama_exposure
Detects whether the Ollama REST API is reachable from beyond this machine.

The Ollama API has no authentication: anyone who can reach the port can list,
pull, delete and run models. It must be bound to loopback only.

PASS - nothing listening on the Ollama port, or every listener is loopback
       (127.0.0.1 / [::1]) and OLLAMA_HOST, wherever it is set, is loopback.
FAIL - a listener bound to 0.0.0.0 (IPv4 wildcard), [::] (IPv6 wildcard) or a
       LAN/public address; or OLLAMA_HOST set to a non-loopback host in the
       process, user or machine environment (takes effect on next Ollama start).

v2 changes vs v1:
  - IPv6 wildcard [::] and LAN-IP bindings now FAIL (v1 only caught 0.0.0.0)
  - Parses the netstat local-address column instead of substring matching
  - Reads OLLAMA_HOST from the user and machine registry, not just this
    process's environment (Ollama on Windows reads the user/system variable)
  - Checks the port named in OLLAMA_HOST as well as the default 11434
  - No longer depends on the ollama.exe process name
"""

from __future__ import annotations

import ipaddress
import os
import subprocess

from engine import CheckResult

CHECK_ID = "ollama_exposure"
DEFAULT_PORT = 11434


# --- Pure helpers (unit-tested) ----------------------------------------------

def is_loopback(host: str) -> bool:
    """True for 127.0.0.0/8, ::1 and 'localhost'."""
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def host_is_exposed(host: str) -> bool:
    """An empty host means 'all interfaces' (Go net.Listen on ':port')."""
    if host == "":
        return True
    return not is_loopback(host)


def parse_ollama_host(value: str) -> tuple[str, int]:
    """
    Return (host, port) from an OLLAMA_HOST value.
    Handles: '0.0.0.0', '0.0.0.0:8080', 'http://127.0.0.1:11434', ':11434',
             '[::]:11434', '::', 'localhost:11434'.
    An unset/blank value means Ollama's default of 127.0.0.1:11434.
    """
    v = value.strip()
    if not v:
        return "127.0.0.1", DEFAULT_PORT
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]

    # Bare IP (incl. unbracketed IPv6 such as '::')
    try:
        return str(ipaddress.ip_address(v.strip("[]"))), DEFAULT_PORT
    except ValueError:
        pass

    if v.startswith("["):
        host, _, rest = v[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, sep, port = v.rpartition(":")
        if not sep:
            host, port = v, ""
    try:
        port_n = int(port) if port else DEFAULT_PORT
    except ValueError:
        port_n = DEFAULT_PORT
    return host, port_n


def parse_listeners(netstat_text: str, port: int) -> list[tuple[str, str]]:
    """
    Return [(local_host, pid), ...] for TCP listeners on `port` from
    `netstat -ano` output. Listening is detected by state LISTENING or by a
    foreign address of 0.0.0.0:0 / [::]:0 (locale-independent).
    """
    found = []
    for line in netstat_text.splitlines():
        cols = line.split()
        if len(cols) < 4 or cols[0].upper() != "TCP":
            continue
        local, foreign = cols[1], cols[2]
        listening = cols[3].upper() == "LISTENING" or foreign in ("0.0.0.0:0", "[::]:0")
        if not listening:
            continue
        host, _, p = local.rpartition(":")
        if p == str(port):
            pid = cols[4] if len(cols) >= 5 else "?"
            found.append((host.strip("[]"), pid))
    return found


def describe_binding(host: str) -> str:
    if host == "0.0.0.0":
        return "IPv4 wildcard - all network interfaces"
    if host == "::":
        return "IPv6 wildcard - all network interfaces"
    return "non-loopback address - reachable from the network"


# --- System access (patched in tests) ----------------------------------------

def run_netstat() -> str:
    # Plain -ano lists IPv4 and IPv6 sockets together (both shown as "TCP")
    result = subprocess.run(["netstat", "-ano"], capture_output=True,
                            text=True, timeout=15)
    return result.stdout


def read_ollama_host_values() -> dict[str, str]:
    """OLLAMA_HOST from this process, the user registry and the machine registry."""
    values = {}
    if os.environ.get("OLLAMA_HOST") is not None:
        values["process"] = os.environ["OLLAMA_HOST"]
    try:
        import winreg
    except ImportError:
        return values
    sources = (
        ("user", winreg.HKEY_CURRENT_USER, r"Environment"),
        ("machine", winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    )
    for label, root, path in sources:
        try:
            with winreg.OpenKey(root, path) as key:
                val, _ = winreg.QueryValueEx(key, "OLLAMA_HOST")
                values[label] = str(val)
        except OSError:
            pass
    return values


# --- Check entry point -------------------------------------------------------

def run(config: dict) -> CheckResult:
    severity = config.get("checks", {}).get(CHECK_ID, {}).get("severity", "HIGH")
    details, issues = [], []

    # 1. OLLAMA_HOST in every environment scope
    host_values = read_ollama_host_values()
    ports = {DEFAULT_PORT}
    if not host_values:
        details.append("OLLAMA_HOST not set (Ollama default: 127.0.0.1:11434)")
    for scope, raw in host_values.items():
        host, port = parse_ollama_host(raw)
        ports.add(port)
        shown = host if host else "(empty = all interfaces)"
        details.append(f"OLLAMA_HOST [{scope}] = {raw!r} -> host {shown}, port {port}")
        if host_is_exposed(host):
            issues.append(
                f"OLLAMA_HOST in {scope} environment is {raw!r} - Ollama will listen "
                f"on a non-loopback address (applies on next Ollama start)"
            )

    # 2. Actual listeners
    try:
        netstat_text = run_netstat()
    except Exception as e:
        return CheckResult(
            check_id=CHECK_ID, status="ERROR", severity=severity,
            message=f"Could not run netstat: {e}", details=details,
        )

    listener_count = 0
    for port in sorted(ports):
        for host, pid in parse_listeners(netstat_text, port):
            listener_count += 1
            label = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            if is_loopback(host):
                details.append(f"Listener {label} (PID {pid}) - loopback only, OK")
            else:
                issues.append(f"Listener {label} (PID {pid}) - {describe_binding(host)}")

    if listener_count == 0:
        details.append(f"Nothing listening on port(s) {', '.join(map(str, sorted(ports)))}")

    if issues:
        return CheckResult(
            check_id=CHECK_ID, status="FAIL", severity=severity,
            message=f"Ollama API exposed ({len(issues)} issue(s)): {issues[0]}",
            details=details + [f"⚠ {i}" for i in issues],
            remediation=(
                "1. Set OLLAMA_HOST to loopback (or remove it) in BOTH scopes:\n"
                "   [Environment]::SetEnvironmentVariable('OLLAMA_HOST','127.0.0.1','User')\n"
                "   (admin) [Environment]::SetEnvironmentVariable('OLLAMA_HOST',$null,'Machine')\n"
                "2. Quit Ollama from the tray icon and start it again.\n"
                "3. Verify: netstat -ano | findstr 11434  -> only 127.0.0.1:11434\n"
                "4. Defence in depth: Windows Firewall inbound block rule for TCP 11434."
            ),
        )

    if listener_count == 0:
        msg = "Ollama API not listening"
    else:
        msg = "Ollama API bound to loopback only"
    return CheckResult(check_id=CHECK_ID, status="PASS", severity=severity,
                       message=msg, details=details)
