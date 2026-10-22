"""
Check: mcp_injection_exposure
Expectation: high-privilege MCP servers are OFF unless a session needs them.

Why: an MCP server that can run shell commands, edit the registry or write
files turns a prompt injection (hidden instructions inside a web page, job
posting, email or document the model reads) into real actions on this PC.
With the server off, the worst outcome of an injection is a bad answer. With
it on, the injected text can act through the server's tools. Turn such
servers on only for the session that needs them, then off again.

Sources scanned:
  1. Claude Desktop extensions   - <ext settings dir>/<id>.json  ("isEnabled")
  2. Manual MCP configs          - config["mcp_paths"] files, "mcpServers"
                                   (always active while the client runs)
  3. Claude Code                 - ~/.claude.json "mcpServers" (user scope and
                                   per-project scope, minus disabledMcpServers)
  4. Claude Code auto-approval   - permissions.allow rules in ~/.claude/settings.json
                                   that pre-approve a high-privilege server's tools
                                   (removes the human approval gate)

FAIL - any high-privilege server enabled, or auto-approved in Claude Code.
PASS - none enabled.

"High-privilege" = server name, extension id, command or args contains one of
config["checks"]["mcp_injection_exposure"]["high_privilege_patterns"].
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from engine import CheckResult

CHECK_ID = "mcp_injection_exposure"

DEFAULT_PATTERNS = [
    "windows-mcp", "windows_mcp", "filesystem", "desktop-commander",
    "desktop_commander", "powershell", "shell", "terminal",
]
DEFAULT_EXT_DIR = r"%APPDATA%\Claude\Claude Extensions Settings"
DEFAULT_CC_CONFIG = r"%USERPROFILE%\.claude.json"
DEFAULT_CC_SETTINGS = r"%USERPROFILE%\.claude\settings.json"


def expand(p: str) -> Path:
    return Path(os.path.expandvars(p))


def matches_high_priv(text: str, patterns: list[str]) -> str | None:
    """Return the first pattern found in text (case-insensitive), else None."""
    t = text.lower()
    for pat in patterns:
        if pat.lower() in t:
            return pat
    return None


def _load_json(path: Path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def _server_text(name: str, cfg: dict) -> str:
    cmd = str(cfg.get("command", ""))
    args = " ".join(str(a) for a in cfg.get("args", []) or [])
    url = str(cfg.get("url", ""))
    return f"{name} {cmd} {args} {url}"


# --- Source scanners: each returns (issues, details) -------------------------

def scan_desktop_extensions(ext_dir: Path, patterns: list[str]):
    issues, details = [], []
    if not ext_dir.is_dir():
        details.append(f"Claude Desktop extension settings not found: {ext_dir}")
        return issues, details
    for f in sorted(ext_dir.glob("*.json")):          # skips *.json.backup
        ext_id = f.stem
        try:
            enabled = bool(_load_json(f).get("isEnabled", False))
        except Exception as e:
            details.append(f"Extension {ext_id}: could not parse ({e})")
            continue
        hit = matches_high_priv(ext_id, patterns)
        state = "ENABLED" if enabled else "disabled"
        if hit and enabled:
            issues.append(f"Claude Desktop extension '{ext_id}' is ENABLED "
                          f"(high-privilege: '{hit}')")
        else:
            tag = " [high-privilege]" if hit else ""
            details.append(f"Extension {ext_id}: {state}{tag}")
    return issues, details


def scan_mcp_server_files(paths: list[str], patterns: list[str]):
    issues, details = [], []
    for template in paths:
        p = expand(template)
        if not p.exists():
            continue
        try:
            servers = _load_json(p).get("mcpServers", {}) or {}
        except Exception as e:
            details.append(f"{p}: could not parse ({e})")
            continue
        details.append(f"{p}: {len(servers)} manual MCP server(s)")
        for name, cfg in servers.items():
            hit = matches_high_priv(_server_text(name, cfg or {}), patterns)
            if hit:
                issues.append(f"Manual MCP server '{name}' in {p.name} is configured "
                              f"(always on while the client runs; high-privilege: '{hit}')")
    return issues, details


def scan_claude_code_config(path: Path, patterns: list[str]):
    issues, details = [], []
    if not path.exists():
        details.append(f"Claude Code config not found: {path}")
        return issues, details
    try:
        data = _load_json(path)
    except Exception as e:
        details.append(f"{path}: could not parse ({e})")
        return issues, details

    scopes = [("user scope", data.get("mcpServers", {}) or {}, set())]
    for proj, pcfg in (data.get("projects", {}) or {}).items():
        pcfg = pcfg or {}
        scopes.append((f"project {proj}", pcfg.get("mcpServers", {}) or {},
                       set(pcfg.get("disabledMcpServers", []) or [])))

    total = 0
    for scope, servers, disabled in scopes:
        for name, cfg in servers.items():
            total += 1
            if name in disabled:
                continue
            hit = matches_high_priv(_server_text(name, cfg or {}), patterns)
            if hit:
                issues.append(f"Claude Code MCP server '{name}' ({scope}) is configured "
                              f"(high-privilege: '{hit}')")
    details.append(f"Claude Code: {total} MCP server(s) configured across scopes")
    return issues, details


def scan_claude_code_allow_rules(path: Path, patterns: list[str]):
    issues, details = [], []
    if not path.exists():
        return issues, details
    try:
        allow = (_load_json(path).get("permissions", {}) or {}).get("allow", []) or []
    except Exception as e:
        details.append(f"{path}: could not parse ({e})")
        return issues, details
    for rule in allow:
        r = str(rule)
        if not r.startswith("mcp__"):
            continue
        server = r[len("mcp__"):].split("__", 1)[0]
        hit = matches_high_priv(server, patterns)
        if hit:
            issues.append(f"Claude Code auto-approves '{r}' - no human approval "
                          f"before high-privilege MCP tool calls ('{hit}')")
    return issues, details


# --- Check entry point -------------------------------------------------------

def run(config: dict) -> CheckResult:
    check_cfg = config.get("checks", {}).get(CHECK_ID, {})
    severity = check_cfg.get("severity", "HIGH")
    patterns = check_cfg.get("high_privilege_patterns", DEFAULT_PATTERNS)

    issues, details = [], []
    for i, d in (
        scan_desktop_extensions(expand(check_cfg.get("extension_settings_dir", DEFAULT_EXT_DIR)), patterns),
        scan_mcp_server_files(config.get("mcp_paths", []), patterns),
        scan_claude_code_config(expand(check_cfg.get("claude_code_config", DEFAULT_CC_CONFIG)), patterns),
        scan_claude_code_allow_rules(expand(check_cfg.get("claude_code_settings", DEFAULT_CC_SETTINGS)), patterns),
    ):
        issues.extend(i)
        details.extend(d)

    if issues:
        return CheckResult(
            check_id=CHECK_ID, status="FAIL", severity=severity,
            message=f"{len(issues)} high-privilege MCP server(s) active - "
                    f"prompt injection can act on this PC: {issues[0]}",
            details=details + [f"⚠ {i}" for i in issues],
            remediation=(
                "1. Claude Desktop: Settings > Extensions > toggle the flagged extension OFF. "
                "Turn it on only for a session that needs it, and off again after.\n"
                "2. Keep it off whenever Claude reads untrusted content "
                "(web pages, job postings, emails, downloaded documents).\n"
                "3. Never choose 'Always allow' for PowerShell, Registry or FileSystem tools.\n"
                "4. Manual entries: remove from claude_desktop_config.json; "
                "Claude Code: 'claude mcp remove <name>' and delete mcp__<server> allow rules."
            ),
        )

    return CheckResult(
        check_id=CHECK_ID, status="PASS", severity=severity,
        message="No high-privilege MCP servers enabled",
        details=details,
    )
