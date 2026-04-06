"""
Check: claude_code_permissions
Audits Claude Code CLI configuration for over-permissive settings.

Risks:
- allowedTools with bash unrestricted
- No file path restrictions
- Auto-approve mode enabled
- Running as admin/elevated
"""

import json
import os
import subprocess
import ctypes
from pathlib import Path
from engine import CheckResult


def expand(p: str) -> Path:
    return Path(os.path.expandvars(p))


CLAUDE_CODE_CONFIG_PATHS = [
    "%USERPROFILE%\\.claude\\settings.json",
    "%USERPROFILE%\\.claude\\config.json",
    "%APPDATA%\\claude-code\\settings.json",
    "%USERPROFILE%\\.config\\claude-code\\settings.json",
]


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run(config: dict) -> CheckResult:
    check_id = "claude_code_permissions"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "HIGH")
    details = []
    issues = []
    warnings = []

    # 1. Check if Claude Code is installed
    claude_found = False
    try:
        result = subprocess.run(
            ["where", "claude"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            claude_found = True
            details.append(f"Claude Code CLI found: {result.stdout.strip()}")
    except Exception:
        pass

    if not claude_found:
        # Also check npm global
        try:
            result = subprocess.run(
                ["npm", "list", "-g", "--depth=0"],
                capture_output=True, text=True, timeout=10
            )
            if "@anthropic-ai/claude-code" in result.stdout or "claude-code" in result.stdout:
                claude_found = True
                details.append("Claude Code found via npm global")
        except Exception:
            pass

    if not claude_found:
        return CheckResult(
            check_id=check_id, status="PASS", severity=severity,
            message="Claude Code CLI not detected on this machine",
            details=details
        )

    # 2. Check config files
    configs_found = []
    for path_template in CLAUDE_CODE_CONFIG_PATHS:
        path = expand(path_template)
        if path.exists():
            configs_found.append(path)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                details.append(f"Config found: {path}")

                # Check for dangerous settings
                allowed_tools = cfg.get("allowedTools", [])
                if "Bash" in allowed_tools or "bash" in str(allowed_tools).lower():
                    warnings.append(
                        f"Bash tool enabled in {path.name} — Claude can run arbitrary shell commands"
                    )

                if cfg.get("autoApprove") or cfg.get("auto_approve"):
                    issues.append(f"autoApprove=true in {path.name} — Claude acts without user confirmation")

                trust_dirs = cfg.get("trustedDirectories", cfg.get("trust", {}).get("directories", []))
                if any(d in ["C:\\", "C:/", "/", "~", str(Path.home())] for d in trust_dirs):
                    issues.append(f"Trusted directory includes root/home — unrestricted file access")

                details.append(f"  Allowed tools: {allowed_tools or 'default'}")

            except json.JSONDecodeError as e:
                details.append(f"  Could not parse {path}: {e}")

    if not configs_found:
        details.append("No Claude Code config files found — using defaults")

    # 3. Check if running as admin (Claude Code + admin = elevated risk)
    if is_admin():
        issues.append(
            "Current session is running as Administrator — Claude Code can modify system files"
        )

    # 4. Check for .claude/CLAUDE.md project context files with suspicious content
    project_roots = [Path.home(), Path.home() / "Documents", Path.home() / "Projects"]
    for root in project_roots:
        claude_md = root / "CLAUDE.md"
        if claude_md.exists():
            try:
                content = claude_md.read_text(encoding="utf-8", errors="ignore")
                risky_patterns = ["rm -rf", "del /f", "format c:", "net user", "reg delete"]
                for pat in risky_patterns:
                    if pat.lower() in content.lower():
                        issues.append(f"Dangerous command pattern '{pat}' found in {claude_md}")
            except Exception:
                pass

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} high-risk Claude Code configuration(s) detected",
            details=details + [f"⚠ {i}" for i in issues] + [f"⚡ {w}" for w in warnings],
            remediation=(
                "1. Disable autoApprove in settings.json\n"
                "2. Remove 'Bash' from allowedTools unless required per-project\n"
                "3. Run Claude Code as standard user, not Administrator\n"
                "4. Restrict trustedDirectories to specific project folders only"
            )
        )

    if warnings:
        return CheckResult(
            check_id=check_id, status="WARN", severity=severity,
            message=f"Claude Code config has elevated-risk settings",
            details=details + [f"⚡ {w}" for w in warnings],
            remediation="Review Bash tool access — restrict to specific projects using /allowed-tools flag"
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="Claude Code permissions look reasonable",
        details=details
    )
