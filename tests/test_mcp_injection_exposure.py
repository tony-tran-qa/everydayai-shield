"""
Tests for checks/check_mcp_injection_exposure.py. Uses fake config files in
tmp_path - never reads the real Claude Desktop / Claude Code settings.
Expectation under test: high-privilege MCP servers OFF -> PASS, ON -> FAIL.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_mcp_injection_exposure", ROOT / "checks" / "check_mcp_injection_exposure.py")
mie = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mie)


@pytest.fixture
def env(tmp_path):
    """Isolated fake machine: returns (config, paths) with nothing configured."""
    ext_dir = tmp_path / "Claude Extensions Settings"
    ext_dir.mkdir()
    paths = {
        "ext_dir": ext_dir,
        "desktop_cfg": tmp_path / "claude_desktop_config.json",
        "cc_config": tmp_path / ".claude.json",
        "cc_settings": tmp_path / "settings.json",
    }
    config = {
        "mcp_paths": [str(paths["desktop_cfg"])],
        "checks": {"mcp_injection_exposure": {
            "enabled": True, "severity": "HIGH",
            "extension_settings_dir": str(ext_dir),
            "claude_code_config": str(paths["cc_config"]),
            "claude_code_settings": str(paths["cc_settings"]),
        }},
    }
    return config, paths


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def ext(paths, ext_id, enabled):
    write(paths["ext_dir"] / f"{ext_id}.json", {"isEnabled": enabled, "userConfig": {}})


# --- Expected state: OFF -> PASS ---------------------------------------------

class TestExpectedOff:
    def test_nothing_configured_passes(self, env):
        config, _ = env
        assert mie.run(config).status == "PASS"

    def test_windows_mcp_disabled_passes(self, env):
        config, paths = env
        ext(paths, "ant.dir.cursortouch.windows-mcp", False)
        ext(paths, "ant.dir.ant.anthropic.filesystem", False)
        r = mie.run(config)
        assert r.status == "PASS"
        assert any("disabled [high-privilege]" in d for d in r.details)

    def test_backup_file_ignored(self, env):
        """*.json.backup must not count as live state."""
        config, paths = env
        write(paths["ext_dir"] / "ant.dir.ant.anthropic.filesystem.json.backup",
              {"isEnabled": True})
        assert mie.run(config).status == "PASS"

    def test_low_privilege_extension_enabled_passes(self, env):
        config, paths = env
        ext(paths, "ant.dir.example.weather", True)
        assert mie.run(config).status == "PASS"


# --- Deviation: ON -> FAIL ---------------------------------------------------

class TestEnabledFails:
    def test_windows_mcp_enabled_fails(self, env):
        config, paths = env
        ext(paths, "ant.dir.cursortouch.windows-mcp", True)
        r = mie.run(config)
        assert r.status == "FAIL"
        assert "windows-mcp" in r.message
        assert "Extensions" in r.remediation

    def test_filesystem_extension_enabled_fails(self, env):
        config, paths = env
        ext(paths, "ant.dir.ant.anthropic.filesystem", True)
        assert mie.run(config).status == "FAIL"

    def test_manual_desktop_config_server_fails(self, env):
        config, paths = env
        write(paths["desktop_cfg"], {"mcpServers": {"files": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\TNY"]}}})
        r = mie.run(config)
        assert r.status == "FAIL"
        assert "always on" in r.message

    def test_claude_code_user_scope_server_fails(self, env):
        config, paths = env
        write(paths["cc_config"], {"mcpServers": {"win": {"command": "uvx", "args": ["windows-mcp"]}}})
        assert mie.run(config).status == "FAIL"

    def test_claude_code_project_server_fails(self, env):
        config, paths = env
        write(paths["cc_config"], {"projects": {"C:/proj": {
            "mcpServers": {"desktop-commander": {"command": "npx", "args": []}}}}})
        assert mie.run(config).status == "FAIL"

    def test_claude_code_project_server_disabled_passes(self, env):
        config, paths = env
        write(paths["cc_config"], {"projects": {"C:/proj": {
            "mcpServers": {"desktop-commander": {"command": "npx", "args": []}},
            "disabledMcpServers": ["desktop-commander"]}}})
        assert mie.run(config).status == "PASS"

    def test_auto_approve_rule_fails(self, env):
        config, paths = env
        write(paths["cc_settings"], {"permissions": {"allow": ["mcp__windows-mcp__PowerShell"]}})
        r = mie.run(config)
        assert r.status == "FAIL"
        assert "auto-approves" in r.message

    def test_auto_approve_low_priv_server_passes(self, env):
        config, paths = env
        write(paths["cc_settings"], {"permissions": {"allow": ["mcp__github__get_issue", "Bash(npm test)"]}})
        assert mie.run(config).status == "PASS"

    def test_multiple_issues_counted(self, env):
        config, paths = env
        ext(paths, "ant.dir.cursortouch.windows-mcp", True)
        ext(paths, "ant.dir.ant.anthropic.filesystem", True)
        assert mie.run(config).message.startswith("2 ")


# --- Robustness --------------------------------------------------------------

class TestRobustness:
    def test_corrupt_extension_file_does_not_crash(self, env):
        config, paths = env
        (paths["ext_dir"] / "broken.json").write_text("{not json", encoding="utf-8")
        r = mie.run(config)
        assert r.status == "PASS"
        assert any("could not parse" in d for d in r.details)

    def test_utf8_bom_config_parsed(self, env):
        config, paths = env
        (paths["ext_dir"] / "ant.dir.cursortouch.windows-mcp.json").write_bytes(
            b"\xef\xbb\xbf" + json.dumps({"isEnabled": True}).encode())
        assert mie.run(config).status == "FAIL"

    def test_custom_patterns_from_config(self, env):
        config, paths = env
        config["checks"]["mcp_injection_exposure"]["high_privilege_patterns"] = ["weather"]
        ext(paths, "ant.dir.example.weather", True)
        assert mie.run(config).status == "FAIL"

    def test_shield_name_not_matched_as_shell(self):
        assert mie.matches_high_priv("everydayai-shield", mie.DEFAULT_PATTERNS) is None
