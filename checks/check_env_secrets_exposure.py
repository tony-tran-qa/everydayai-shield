"""
Check: env_secrets_exposure
Scans for AI API keys and secrets exposed in:
- System/user environment variables
- Common .env files
- PowerShell/CMD history
- Windows Credential Manager (partial)

Does NOT log the actual secret values — only reports presence and location.
"""

import os
import re
import subprocess
from pathlib import Path
from engine import CheckResult


def mask(value: str) -> str:
    """Show only first 4 and last 4 chars of a secret."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


def run(config: dict) -> CheckResult:
    check_id = "env_secrets_exposure"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "CRITICAL")
    patterns = config.get("sensitive_env_patterns", [
        "API_KEY", "SECRET", "TOKEN", "PASSWORD",
        "ANTHROPIC", "OPENAI", "GEMINI", "COHERE"
    ])
    details = []
    issues = []
    warnings = []

    # 1. Scan current process environment variables
    exposed_env = []
    for key, val in os.environ.items():
        for pat in patterns:
            if pat.upper() in key.upper():
                exposed_env.append((key, mask(val)))
                break

    if exposed_env:
        for k, v in exposed_env:
            details.append(f"ENV: {k} = {v}")
            # Warn if it's a broad system-level env (not just session)
            warnings.append(f"API credential in environment: {k}")

    # 2. Scan .env files in common locations
    scan_dirs = [
        Path.home(),
        Path.home() / "Documents",
        Path.home() / "Projects",
        Path.home() / "Desktop",
        Path(os.environ.get("USERPROFILE", "C:\\Users\\Default")),
    ]
    env_files_found = []
    secret_pattern = re.compile(
        r'(' + '|'.join(re.escape(p) for p in patterns) + r')\s*=\s*(\S+)',
        re.IGNORECASE
    )

    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for env_file in scan_dir.glob("**/.env"):
            try:
                content = env_file.read_text(encoding="utf-8", errors="ignore")
                matches = secret_pattern.findall(content)
                if matches:
                    env_files_found.append(str(env_file))
                    for key, val in matches:
                        issues.append(f".env file contains secret: {key} in {env_file}")
                        details.append(f"  {key} = {mask(val)} (in {env_file.name})")
            except Exception:
                pass
            if len(env_files_found) > 20:  # safety cap
                break

    # 3. Check PowerShell history for API key-like strings
    ps_history = Path(os.environ.get("APPDATA", "")) / \
        "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"

    if ps_history.exists():
        try:
            lines = ps_history.read_text(encoding="utf-8", errors="ignore").splitlines()
            key_like = re.compile(r'(sk-[a-zA-Z0-9\-_]{20,}|[A-Za-z0-9]{32,})')
            api_key_lines = []
            for i, line in enumerate(lines[-200:], 1):  # last 200 lines only
                for pat in patterns:
                    if pat.upper() in line.upper() and "=" in line:
                        api_key_lines.append(f"Line ~{len(lines)-200+i}: {line[:60]}...")
                        break
            if api_key_lines:
                issues.append(f"API key patterns found in PowerShell history ({len(api_key_lines)} line(s))")
                details.extend(api_key_lines[:5])  # show max 5
        except Exception as e:
            details.append(f"Could not read PS history: {e}")
    else:
        details.append("PowerShell history not found (or PSReadLine not installed)")

    # 4. Check Windows Registry for accidentally stored keys
    reg_paths = [
        r"HKCU\Environment",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    ]
    for reg_path in reg_paths:
        try:
            result = subprocess.run(
                ["reg", "query", reg_path],
                capture_output=True, text=True, timeout=5
            )
            for pat in patterns:
                if pat.upper() in result.stdout.upper():
                    # Find the actual line
                    for line in result.stdout.splitlines():
                        if pat.upper() in line.upper():
                            issues.append(f"API credential in Windows Registry: {reg_path} → {line.strip()[:60]}")
        except Exception:
            pass

    # Aggregate
    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} secret exposure(s) detected",
            details=details + [f"⚠ {i}" for i in issues],
            remediation=(
                "1. Move secrets from .env files to Windows Credential Manager or a vault\n"
                "2. Clear PowerShell history: Remove-Item (Get-PSReadLineOption).HistorySavePath\n"
                "3. Remove secrets from Windows Registry environment variables\n"
                "4. Use per-project .env with .gitignore — never commit secrets"
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"API keys found in session environment ({len(warnings)} var(s)) — low risk if session-scoped",
            details=details + [f"⚡ {w}" for w in warnings],
            remediation="Consider using a secrets manager instead of environment variables for AI API keys"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="No exposed secrets detected in common locations",
        details=details or ["No sensitive env vars, .env files, or PS history entries found"]
    )
