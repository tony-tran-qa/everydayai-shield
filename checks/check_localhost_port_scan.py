"""
Check: localhost_port_scan
Detects unexpected services on localhost that may have been
spawned by AI tool processes (MCP servers, Claude Code, etc.)

Compares active listeners against a known-safe baseline.
"""

import subprocess
import re
from engine import CheckResult


# Ports that are expected and safe on a developer laptop
DEFAULT_SAFE_PORTS = {
    # Web / dev
    80, 443, 3000, 3001, 4000, 5000, 8000, 8080, 8443,
    # Node / debugger
    1080, 9229,
    # Common DBs
    5432, 3306, 5984, 27017,
    # Windows core system ports (always present, not suspicious)
    135,    # RPC Endpoint Mapper (svchost)
    139,    # NetBIOS Session (svchost)
    445,    # SMB (System)
    # Windows ephemeral/dynamic service ports (lsass, wininit, svchost, services.exe)
    # These are assigned dynamically by Windows RPC in the 49152-65535 range
    # We whitelist the entire ephemeral range for known Windows system processes
    # (filtered by process name below, not port number alone)
    5040,   # svchost (Windows Runtime Broker / CDPSvc)
    7680,   # svchost (Windows Update Delivery Optimization)
    # Ollama (checked in detail by its own dedicated check)
    11434,  60104,
    # Lenovo system software (SmartConnect, Nahimic audio)
    50715, 9080,
}

# Windows system processes that legitimately hold ephemeral ports
WINDOWS_SYSTEM_PROCS = {
    "svchost.exe", "lsass.exe", "wininit.exe", "services.exe",
    "System", "smss.exe", "csrss.exe", "winlogon.exe",
    "spoolsv.exe", "dashost.exe", "RuntimeBroker.exe",
    "SearchIndexer.exe", "MsMpEng.exe",
    # Lenovo
    "SmartConnect.exe", "NahimicService.exe", "LenovoVantageService.exe",
    # McAfee
    "McAfee", "mcshield.exe", "mfemms.exe",
}
AI_TOOL_PORTS = {
    11434: "Ollama",
    3000: "MCP/Dev server",
    8765: "Claude MCP default",
    5678: "n8n",
    7860: "Gradio (Hugging Face)",
    7861: "Gradio alt",
    8501: "Streamlit",
    11111: "Generic MCP bridge",
    50000: "Jupyter kernel",
    8888: "Jupyter Notebook",
    8889: "Jupyter alt",
    4040: "ngrok tunnel (!)",
    4041: "ngrok alt (!)",
}


def get_listening_ports() -> list[dict]:
    """Return list of {port, pid, process} for all LISTENING TCP ports on localhost."""
    listeners = []
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "LISTENING" not in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local_addr = parts[1]
            pid = parts[-1]
            # Only localhost/all-interface bindings
            match = re.match(r'(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]|\[::1\]):(\d+)', local_addr)
            if match:
                port = int(match.group(1))
                is_all_iface = "0.0.0.0" in local_addr or "[::]" in local_addr
                listeners.append({
                    "port": port,
                    "pid": pid,
                    "all_interfaces": is_all_iface,
                    "addr": local_addr
                })
    except Exception as e:
        listeners.append({"error": str(e)})
    return listeners


def get_process_name(pid: str) -> str:
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=5
        )
        parts = result.stdout.strip().split(",")
        if parts:
            return parts[0].strip('"')
    except Exception:
        pass
    return "unknown"


def run(config: dict) -> CheckResult:
    check_id = "localhost_port_scan"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "HIGH")
    safe_ports = set(config.get("known_safe_ports", [])) | DEFAULT_SAFE_PORTS
    details = []
    issues = []
    warnings = []

    listeners = get_listening_ports()

    if any("error" in l for l in listeners):
        return CheckResult(
            check_id=check_id, status="ERROR", severity=severity,
            message="Could not enumerate localhost ports",
            details=[l.get("error", "") for l in listeners if "error" in l]
        )

    # Enrich with process names
    for listener in listeners:
        if "port" not in listener:
            continue
        port = listener["port"]
        pid = listener.get("pid", "?")
        proc = get_process_name(pid)
        listener["process"] = proc

        label = AI_TOOL_PORTS.get(port, "")
        flag = f"Port {port} ({proc}, PID {pid}){' [' + label + ']' if label else ''}"
        details.append(flag)

        # ngrok / tunnel detection — always an issue
        if port in (4040, 4041) or "ngrok" in proc.lower():
            issues.append(f"ngrok tunnel detected on port {port} — external tunnel active!")

        # Bound to all interfaces on unexpected port — skip system processes
        is_system_proc = any(s.lower() in proc.lower() for s in WINDOWS_SYSTEM_PROCS)
        if listener.get("all_interfaces") and port not in safe_ports and port > 1024 and not is_system_proc:
            issues.append(
                f"Service on port {port} ({proc}) bound to 0.0.0.0 — network-accessible"
            )

        # AI-tool ports that are unexpected
        if port in AI_TOOL_PORTS and port not in safe_ports:
            warnings.append(
                f"AI-tool-associated port {port} active ({AI_TOOL_PORTS[port]}, proc: {proc})"
            )

        # Completely unknown high port — only flag if NOT a Windows system process
        if port > 49152 and port not in safe_ports:
            is_system_proc = any(
                s.lower() in proc.lower() for s in WINDOWS_SYSTEM_PROCS
            )
            if not is_system_proc:
                warnings.append(f"Ephemeral-range listener on {port} ({proc}) — review if unexpected")

    details.insert(0, f"Total localhost listeners: {len(listeners)}")

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} suspicious local service(s) detected",
            details=details,
            remediation=(
                "1. Kill unexpected processes: taskkill /PID <pid> /F\n"
                "2. If ngrok: remove it and block port 4040 in Windows Firewall\n"
                "3. Services bound to 0.0.0.0 should be restricted to 127.0.0.1"
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"{len(warnings)} port(s) worth reviewing",
            details=details,
            remediation="Review flagged ports and confirm they are intentionally running"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message=f"Localhost services look normal ({len(listeners)} listeners)",
        details=details
    )
