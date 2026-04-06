"""
Check: ollama_exposure
Detects if the Ollama REST API is bound to 0.0.0.0 (all interfaces)
instead of localhost only — which would expose local LLM access to
any device on your network or via a misconfigured firewall.
"""

import socket
import subprocess
from engine import CheckResult


def run(config: dict) -> CheckResult:
    check_id = "ollama_exposure"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "HIGH")
    details = []
    issues = []

    # 1. Check if ollama process is running
    ollama_running = False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq ollama.exe", "/NH"],
            capture_output=True, text=True, timeout=5
        )
        if "ollama.exe" in result.stdout:
            ollama_running = True
            details.append("Ollama process is running")
    except Exception as e:
        details.append(f"Could not check ollama process: {e}")

    if not ollama_running:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="Ollama is not running",
            details=details
        )

    # 2. Check what address port 11434 is bound to
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if ":11434" in line and "LISTENING" in line:
                details.append(f"Ollama listener: {line.strip()}")
                if "0.0.0.0:11434" in line:
                    issues.append("Ollama is bound to 0.0.0.0 — accessible from ANY network interface")
                elif "127.0.0.1:11434" in line or "[::1]:11434" in line:
                    details.append("Ollama is correctly bound to localhost only")
    except Exception as e:
        details.append(f"netstat error: {e}")

    # 3. Check OLLAMA_HOST env var
    import os
    ollama_host = os.environ.get("OLLAMA_HOST", "")
    if ollama_host:
        details.append(f"OLLAMA_HOST env var set to: {ollama_host}")
        if "0.0.0.0" in ollama_host:
            issues.append(f"OLLAMA_HOST is set to {ollama_host} — exposes API to all interfaces")

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"Ollama exposure risk: {issues[0]}",
            details=details + issues,
            remediation=(
                "Set OLLAMA_HOST=127.0.0.1 in your environment, or unset it. "
                "Restart Ollama after changing. Ensure Windows Firewall blocks port 11434 externally."
            )
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="Ollama is running and bound to localhost only",
        details=details
    )
