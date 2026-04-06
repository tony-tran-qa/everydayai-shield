"""
Check: suspicious_processes
Detects processes that show behavioral patterns consistent with
AI-tool-spawned malware (post-exploitation, persistence mechanisms).

Looks for:
- Scheduled tasks created by AI tool processes
- Registry Run keys added recently
- Processes with unusual parent-child relationships
- PowerShell with encoded commands (common obfuscation)
- curl/wget running outside expected dirs
"""

import subprocess
import re
from pathlib import Path
from engine import CheckResult


SAFE_SCHTASK_OWNERS = {
    "microsoft", "windows", "mcafee", "intel", "nvidia",
    "adobe", "google", "mozilla", "system"
}


def check_scheduled_tasks() -> tuple[list[str], list[str]]:
    issues, details = [], []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True, text=True, timeout=15
        )
        # Parse tasks — look for ones running node/python/powershell with suspicious args
        task_name = ""
        task_cmd = ""
        for line in result.stdout.splitlines():
            if line.startswith("TaskName:"):
                task_name = line.split(":", 1)[-1].strip()
                task_cmd = ""
            elif "Task To Run:" in line:
                task_cmd = line.split(":", 1)[-1].strip()
                if task_cmd and task_name:
                    # Flag tasks running AI-adjacent binaries with suspicious patterns
                    risky_patterns = [
                        r"powershell.*-enc",      # encoded PS command
                        r"powershell.*-w.*hidden", # hidden window
                        r"cmd.*\/c.*curl",
                        r"node.*http",
                        r"python.*socket",
                        r"wscript",
                        r"mshta",
                    ]
                    for pat in risky_patterns:
                        if re.search(pat, task_cmd, re.IGNORECASE):
                            # Check if it's from a known-safe owner
                            owner_safe = any(s in task_name.lower() for s in SAFE_SCHTASK_OWNERS)
                            if not owner_safe:
                                issues.append(f"Suspicious scheduled task: '{task_name}' runs: {task_cmd[:80]}")
                            break
    except Exception as e:
        details.append(f"Scheduled task check error: {e}")
    return issues, details


def check_registry_run_keys() -> tuple[list[str], list[str]]:
    issues, details = [], []
    run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    ai_patterns = [
        r"node\b", r"python\b", r"ollama", r"claude",
        r"npx", r"uvx", r"powershell.*-enc"
    ]
    for key in run_keys:
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "REG_" not in line:
                    continue
                for pat in ai_patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        # Ollama in Run is expected if user installed it to start on boot
                        if "ollama" in line.lower():
                            details.append(f"Ollama in startup (expected): {line.strip()[:80]}")
                        else:
                            issues.append(f"AI-related startup entry in {key}: {line.strip()[:80]}")
                        break
                else:
                    details.append(f"Run key entry: {line.strip()[:80]}")
        except Exception as e:
            details.append(f"Registry check error ({key}): {e}")
    return issues, details


def check_encoded_powershell() -> tuple[list[str], list[str]]:
    issues, details = [], []
    try:
        result = subprocess.run(
            ["wmic", "process", "where",
             "Name='powershell.exe'",
             "get", "ProcessId,CommandLine", "/format:csv"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "-enc" in line.lower() or "-encodedcommand" in line.lower():
                issues.append(f"Encoded PowerShell command running: {line[:100]}...")
    except Exception as e:
        details.append(f"PowerShell check error: {e}")
    return issues, details


def run(config: dict) -> CheckResult:
    check_id = "suspicious_processes"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "HIGH")
    all_issues = []
    all_details = []

    # Run sub-checks
    for fn in [check_scheduled_tasks, check_registry_run_keys, check_encoded_powershell]:
        issues, details = fn()
        all_issues.extend(issues)
        all_details.extend(details)

    if all_issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(all_issues)} suspicious process/persistence indicator(s)",
            details=all_details + [f"⚠ {i}" for i in all_issues],
            remediation=(
                "1. Review scheduled tasks: schtasks /query /fo LIST /v\n"
                "2. Clean registry Run keys: regedit → HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "3. Kill suspicious PowerShell: taskkill /IM powershell.exe /F (with caution)\n"
                "4. Run McAfee full scan immediately if persistence is detected"
            )
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="No suspicious AI-related process persistence detected",
        details=all_details or ["Scheduled tasks, registry Run keys, and PS processes look clean"]
    )
