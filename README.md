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
| `ollama_exposure` | HIGH | Ollama bound to 0.0.0.0 (network-accessible instead of localhost-only) |
| `claude_code_permissions` | HIGH | autoApprove mode, unrestricted Bash tool, admin-elevated sessions |
| `localhost_port_scan` | HIGH | ngrok tunnels, unexpected AI-spawned local services, 0.0.0.0 binding |
| `network_beaconing` | HIGH | AI processes connecting to paste/tunnel sites (pastebin, ngrok, webhook.site) |
| `suspicious_processes` | HIGH | Encoded PowerShell, persistence in scheduled tasks and registry Run keys |
| `browser_extension_audit` | MEDIUM | Extensions with clipboard read, debugger, native messaging, or <all_urls> permissions |
| `clipboard_exfil` | MEDIUM | Sensitive data (API keys, private keys, SSN, credit cards) in clipboard before pasting to AI |

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
