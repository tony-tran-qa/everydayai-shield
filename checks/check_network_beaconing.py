"""
Check: network_beaconing
Detects suspicious outbound network connections from AI tool processes.

Red flags:
- AI process connecting to paste/tunnel sites
- Node/Python processes beaconing to unexpected IPs
- Connections from ollama/claude to non-Anthropic/OpenAI endpoints
"""

import subprocess
import re
import socket
from engine import CheckResult


KNOWN_SAFE_DOMAINS = [
    "anthropic.com", "claude.ai", "openai.com", "chatgpt.com",
    "ollama.ai", "huggingface.co", "github.com", "npmjs.com",
    "registry.npmjs.org", "pypi.org", "raw.githubusercontent.com",
    "api.anthropic.com", "api.openai.com", "sentry.io",
    "microsoft.com", "windows.com", "windowsupdate.com",
    "localhost", "127.0.0.1", "::1",
]

SUSPICIOUS_DOMAINS = [
    "pastebin.com", "paste.ee", "hastebin.com",
    "ngrok.io", "ngrok-free.app", "serveo.net", "localhost.run",
    "webhook.site", "requestbin.com", "pipedream.net",
    "transfer.sh", "file.io", "0x0.st",
    "discord.com/api/webhooks",  # common exfil target
]


def reverse_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def get_ai_connections(ai_processes: list[str]) -> list[dict]:
    """Get established outbound connections from AI-related processes."""
    connections = []
    try:
        # Get all established connections with PIDs
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=10
        )
        # Get process list
        proc_result = subprocess.run(
            ["tasklist", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=10
        )
        # Build PID -> process name map
        pid_map = {}
        for line in proc_result.stdout.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                pid_map[parts[1]] = parts[0]

        for line in result.stdout.splitlines():
            if "ESTABLISHED" not in line and "CLOSE_WAIT" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[1]
            remote = parts[2]
            pid = parts[-1]
            proc_name = pid_map.get(pid, "unknown")

            # Only care about AI-adjacent processes
            if not any(ai in proc_name.lower() for ai in ai_processes):
                continue

            # Skip localhost connections
            if remote.startswith("127.") or remote.startswith("[::1]"):
                continue

            remote_ip = remote.rsplit(":", 1)[0].strip("[]")
            remote_port = remote.rsplit(":", 1)[-1]

            connections.append({
                "process": proc_name,
                "pid": pid,
                "local": local,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "remote_host": ""  # resolved later
            })

    except Exception as e:
        connections.append({"error": str(e)})

    return connections


def run(config: dict) -> CheckResult:
    check_id = "network_beaconing"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "HIGH")
    ai_processes = config.get("known_ai_processes", ["ollama", "claude", "node", "python"])
    suspicious_domains = config.get("suspicious_domains", []) + SUSPICIOUS_DOMAINS
    details = []
    issues = []
    warnings = []

    connections = get_ai_connections(ai_processes)

    if any("error" in c for c in connections):
        return CheckResult(
            check_id=check_id, status="ERROR", severity=severity,
            message="Could not enumerate network connections",
            details=[c.get("error", "") for c in connections if "error" in c]
        )

    ai_conns = [c for c in connections if "error" not in c]

    if not ai_conns:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="No AI tool processes with active external connections",
            details=["No established connections from AI processes detected"]
        )

    details.append(f"Active AI process connections: {len(ai_conns)}")

    for conn in ai_conns:
        remote = conn["remote_ip"]
        proc = conn["process"]
        port = conn["remote_port"]

        # Try reverse lookup (non-blocking, timeout handled)
        hostname = reverse_lookup(remote)
        conn["remote_host"] = hostname

        conn_str = f"{proc} (PID {conn['pid']}) → {hostname} [{remote}]:{port}"
        details.append(f"  {conn_str}")

        # Check against suspicious domain list
        for sus_domain in suspicious_domains:
            if sus_domain.lower() in hostname.lower():
                issues.append(f"Connection to suspicious domain: {sus_domain} from {proc}")
                break

        # Check if it's a known-safe domain
        is_safe = any(safe in hostname.lower() for safe in KNOWN_SAFE_DOMAINS)
        if not is_safe and hostname != remote:
            # Unknown domain — warn
            warnings.append(f"AI process {proc} connecting to unrecognized host: {hostname}")
        elif not is_safe and hostname == remote:
            # Raw IP — worth noting
            warnings.append(f"AI process {proc} connecting to raw IP {remote}:{port} (no domain)")

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"Suspicious outbound connection(s) from AI processes: {len(issues)} detected",
            details=details + [f"⚠ {i}" for i in issues],
            remediation=(
                "1. Identify the process: tasklist /FI \"PID eq <pid>\"\n"
                "2. Kill if unauthorized: taskkill /PID <pid> /F\n"
                "3. Block domain in Windows Firewall or hosts file\n"
                "4. If from an MCP server, remove it immediately and audit source code"
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"AI processes have connections to {len(warnings)} unrecognized host(s)",
            details=details + [f"⚡ {w}" for w in warnings],
            remediation="Review unrecognized connections — they may be legitimate CDNs or telemetry endpoints"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message=f"AI process network connections look normal ({len(ai_conns)} conn(s))",
        details=details
    )
