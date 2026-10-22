# 🛡 EverydayAI-Shield — AI Tool Security Monitor

A modular Windows security tool that monitors your laptop for threats
specific to AI tools: Claude, ChatGPT, MCP servers, Ollama, and Claude Code.

Designed to complement McAfee (not replace it) — focuses on AI-specific
attack surfaces McAfee doesn't know about.

---

## What It Checks

| Check | Severity | What it catches |
|-------|----------|-----------------|
| `mcp_package_integrity` | CRITICAL | Supply chain RAT attacks (axios-style), malicious npm postinstall hooks, suspicious MCP server packages |
| `env_secrets_exposure` | CRITICAL | API keys in .env files, PowerShell history, Windows Registry, environment variables |
| `ollama_exposure` | HIGH | Ollama API reachable beyond this PC: bound to 0.0.0.0, `[::]` (IPv6 wildcard) or a LAN IP, or `OLLAMA_HOST` set to a non-loopback host in process/user/machine env |
| `mcp_injection_exposure` | HIGH | High-privilege MCP servers (shell, registry, file-write) left ON — see [MCP injection exposure](#mcp-injection-exposure-expected-status-off) |
| `claude_code_permissions` | HIGH | autoApprove mode, unrestricted Bash tool, admin-elevated sessions |
| `localhost_port_scan` | HIGH | ngrok tunnels, unexpected AI-spawned local services, 0.0.0.0 binding |
| `network_beaconing` | HIGH | AI processes connecting to paste/tunnel sites (pastebin, ngrok, webhook.site) |
| `suspicious_processes` | HIGH | Encoded PowerShell, persistence in scheduled tasks and registry Run keys |
| `browser_extension_audit` | MEDIUM | Extensions with clipboard read, debugger, native messaging, or <all_urls> permissions |
| `clipboard_exfil` | MEDIUM | Sensitive data (API keys, private keys, SSN, credit cards) in clipboard before pasting to AI |

---

## MCP injection exposure: expected status OFF

**Expected state:** high-privilege MCP servers (e.g. Windows-MCP, filesystem,
desktop-commander, any shell/PowerShell/terminal server) are **disabled** unless a
specific session needs them, and disabled again afterwards.

**Why:** an MCP server runs with your full Windows user rights and no sandbox.
The risk is not the model deciding to do harm — it is **prompt injection**:
hidden instructions inside content the model reads (a web page, job posting,
email, PDF) are just more text in its context. With no high-privilege server
connected, the worst outcome is a bad answer. With one connected, the injected
text can run PowerShell, edit the registry or write files on this PC.

| Result | Meaning |
|--------|---------|
| PASS | No high-privilege MCP server enabled anywhere scanned |
| FAIL | At least one is enabled, configured, or auto-approved |

**Sources scanned:** Claude Desktop extension toggles
(`%APPDATA%\Claude\Claude Extensions Settings\*.json`, `isEnabled`), manual
`mcpServers` in the files listed in `mcp_paths`, Claude Code servers in
`~/.claude.json` (user and project scope), and Claude Code `permissions.allow`
rules that pre-approve a high-privilege server's tools (no human gate).

**Fix on FAIL:** Claude Desktop → Settings → Extensions → toggle the flagged
server off. Never choose "Always allow" for PowerShell / Registry / FileSystem
tools. The pattern list is configurable via
`checks.mcp_injection_exposure.high_privilege_patterns`.

## Ollama exposure: expected status loopback only

**Expected state:** `netstat -ano | findstr 11434` shows only `127.0.0.1:11434`
(or `[::1]:11434`). The Ollama API has no authentication, so any other binding lets
anyone who can reach the port list, pull, delete and run models.

FAIL on: `0.0.0.0` (IPv4 wildcard), `[::]` (IPv6 wildcard), a LAN/public IP, or
`OLLAMA_HOST` set to a non-loopback value in the process, **user or machine**
environment (flagged before it takes effect on the next Ollama restart). A custom
port in `OLLAMA_HOST` is checked too.

---

## Quick Start

### 1. Install

```bash
# Option A: Run setup script
setup.bat

# Option B: Manual
pip install pystray Pillow pywin32
python everydayai-shield.py
```

### 2. Run GUI Dashboard
```bash
python everydayai-shield.py
```
- Runs in system tray (shield icon: green=clean, orange=warnings, red=issues)
- Click tray icon to open dashboard
- Auto-scans every 60 seconds (configurable)

### 3. Run as Windows Service (background, no window)
```bash
# Admin PowerShell required
python everydayai-shield_service.py install
python everydayai-shield_service.py start

# To stop
python everydayai-shield_service.py stop
python everydayai-shield_service.py remove
```

### 4. Run Headless (CLI/terminal)
```bash
python everydayai-shield_service.py
# Ctrl+C to stop
```

---

## Adding Custom Checks

1. Create `checks/check_<yourname>.py`
2. Implement the `run(config: dict) -> CheckResult` function:

```python
from engine import CheckResult

def run(config: dict) -> CheckResult:
    check_id = "my_check"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "MEDIUM")

    # Your logic here
    issues = []

    if issues:
        return CheckResult(
            check_id=check_id,
            status="FAIL",
            severity=severity,
            message=f"{len(issues)} issues found",
            details=issues,
            remediation="How to fix..."
        )

    return CheckResult(
        check_id=check_id,
        status="PASS",
        severity=severity,
        message="All clear"
    )
```

3. Add to `config.json` under `"checks"`:
```json
"my_check": {
    "enabled": true,
    "severity": "HIGH",
    "description": "What this check does"
}
```

4. Click **↺ Reload All Checks** in the dashboard → **+ Add Check** tab

---

## Configuration (`config.json`)

```json
{
  "scan_interval_seconds": 60,      // How often to scan
  "log_retention_days": 30,         // Log file rotation
  "checks": {
    "check_name": {
      "enabled": true,              // Toggle without deleting
      "severity": "HIGH"            // LOW / MEDIUM / HIGH / CRITICAL
    }
  },
  "suspicious_npm_packages": [...], // Add new known-bad packages here
  "suspicious_domains": [...],      // Add domains to block/alert on
  "mcp_paths": [...]                // Add MCP config locations to scan
}
```

---

## Architecture

```
EverydayAI-Shield/
├── everydayai-shield.py              # GUI + system tray (main entry point)
├── everydayai-shield_service.py      # Windows service wrapper / headless runner
├── engine.py                # CheckResult model, CheckRegistry, ScanEngine, Logger
├── config.json              # All configuration
├── requirements.txt
├── setup.bat
├── checks/
│   ├── check_mcp_package_integrity.py    # Supply chain (RAT detection)
│   ├── check_env_secrets_exposure.py     # Credentials in wrong places
│   ├── check_ollama_exposure.py          # Ollama network binding
│   ├── check_mcp_injection_exposure.py   # High-privilege MCP servers ON (prompt-injection reach)
│   ├── check_claude_code_permissions.py  # Claude Code CLI config audit
│   ├── check_localhost_port_scan.py      # Unexpected local services
│   ├── check_network_beaconing.py        # AI process outbound connections
│   ├── check_suspicious_processes.py     # Persistence mechanisms
│   ├── check_browser_extension_audit.py  # Chrome/Edge extension risks
│   └── check_clipboard_exfil.py         # Credential in clipboard warning
└── logs/
    └── everydayai-shield.log                      # Rotating daily log
```

---

## McAfee + EverydayAI-Shield: Division of Labour

| Threat | McAfee | EverydayAI-Shield |
|--------|--------|----------|
| Known malware signatures | ✅ | — |
| Ransomware behavior | ✅ | — |
| MCP supply chain packages | ❌ | ✅ |
| Ollama network exposure | ❌ | ✅ |
| Prompt-injection reach via MCP | ❌ | ✅ |
| Claude Code config risks | ❌ | ✅ |
| API keys in clipboard/env | ❌ | ✅ |
| ngrok tunnels | Partial | ✅ |
| Browser extension audit | ❌ | ✅ |
| AI process beaconing | Partial | ✅ (AI-focused) |

---

## Log Location

`EverydayAI-Shield/logs/everydayai-shield.log` — rotates daily, 30-day retention by default.
Open from dashboard: **Live Log** tab → **Open Log File**.

---

## Requirements

- Windows 10/11
- Python 3.11+
- Optional: `pystray` + `Pillow` for tray icon
- Optional: `pywin32` for Windows service mode
