"""
Check: clipboard_exfil
Monitors clipboard for sensitive data patterns that could be
accidentally exposed when using AI tools (copy-pasting API keys,
credentials, or PII into chat interfaces).

Does NOT store clipboard content — only checks for pattern matches
and immediately discards. Returns WARN, not FAIL (user-driven risk).
"""

import re
import subprocess
from engine import CheckResult

# Patterns for sensitive data that should never be pasted into AI tools
SENSITIVE_PATTERNS = [
    (r'sk-[a-zA-Z0-9\-_]{40,}', "OpenAI API key"),
    (r'sk-ant-[a-zA-Z0-9\-_]{40,}', "Anthropic API key"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API key"),
    (r'(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'[A-Za-z0-9/+]{40}(?:[A-Za-z0-9/+]{8})?', None),  # generic long base64 (below)
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private key"),
    (r'(?:password|passwd|pwd)\s*[=:]\s*\S{8,}', "Password in config format"),
    (r'\b\d{3}-\d{2}-\d{4}\b', "SSN-pattern"),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "Credit card number"),
    (r'ghp_[A-Za-z0-9_]{36}', "GitHub Personal Access Token"),
    (r'ghs_[A-Za-z0-9_]{36}', "GitHub App Token"),
    (r'xox[baprs]-[0-9a-zA-Z\-]+', "Slack token"),
]


def get_clipboard_text() -> str | None:
    """Read clipboard text using PowerShell — returns None on failure."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return None


def run(config: dict) -> CheckResult:
    check_id = "clipboard_exfil"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "MEDIUM")
    details = []
    warnings = []

    clipboard = get_clipboard_text()
    if clipboard is None:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="Could not read clipboard (may be empty or inaccessible)",
            details=["Clipboard access requires PowerShell and a clipboard with content"]
        )

    if not clipboard:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="Clipboard is empty",
            details=[]
        )

    clip_len = len(clipboard)
    details.append(f"Clipboard content length: {clip_len} chars")

    # Check for each sensitive pattern
    matches_found = []
    for pattern, label in SENSITIVE_PATTERNS:
        if label is None:
            continue  # skip the generic base64 for now
        match = re.search(pattern, clipboard, re.IGNORECASE)
        if match:
            matched_text = match.group(0)
            # Mask most of it
            masked = matched_text[:4] + "..." + matched_text[-4:] if len(matched_text) > 8 else "***"
            matches_found.append(f"{label} pattern detected in clipboard: {masked}")

    if matches_found:
        for m in matches_found:
            warnings.append(m)

        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"Sensitive data in clipboard — {len(matches_found)} pattern(s) matched",
            details=details + [f"⚡ {w}" for w in warnings],
            remediation=(
                "1. Clear clipboard: Win+R → cmd → echo off | clip\n"
                "   Or PowerShell: Set-Clipboard -Value ''\n"
                "2. Do NOT paste this content into Claude.ai, ChatGPT, or any AI chat\n"
                "3. If pasted accidentally, rotate the exposed credential immediately"
            )
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="Clipboard content shows no sensitive data patterns",
        details=details
    )
