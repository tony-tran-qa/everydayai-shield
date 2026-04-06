"""
Tests for EverydayAI-Shield core engine.
Covers: CheckResult model, config loading, ScanEngine status aggregation,
and CheckRegistry discovery — all without triggering real system checks.
"""

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ─── Path setup ───────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from engine import CheckResult, load_config, save_config, ScanEngine, CheckRegistry


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def minimal_config():
    return {
        "scan_interval_seconds": 5,
        "log_retention_days": 7,
        "checks": {
            "ollama_exposure": {"enabled": True, "severity": "HIGH"},
            "clipboard_exfil": {"enabled": False, "severity": "MEDIUM"},
        }
    }


@pytest.fixture
def config_file(tmp_path, minimal_config):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(minimal_config), encoding="utf-8")
    return p


@pytest.fixture
def mock_logger():
    return MagicMock()


# ─── CheckResult model ────────────────────────────────────────────────────────

class TestCheckResult:
    def test_pass_result(self):
        r = CheckResult(check_id="test", status="PASS", severity="LOW", message="All clear")
        assert r.status == "PASS"
        assert r.details == []
        assert r.remediation == ""

    def test_fail_result_with_details(self):
        r = CheckResult(
            check_id="test", status="FAIL", severity="HIGH",
            message="2 issues found", details=["issue A", "issue B"],
            remediation="Fix it"
        )
        assert r.status == "FAIL"
        assert len(r.details) == 2
        assert r.remediation == "Fix it"

    def test_timestamp_auto_set(self):
        r = CheckResult(check_id="x", status="PASS", severity="LOW", message="ok")
        assert r.timestamp  # non-empty

    @pytest.mark.parametrize("status", ["PASS", "WARN", "FAIL", "ERROR", "SKIP"])
    def test_valid_statuses(self, status):
        r = CheckResult(check_id="x", status=status, severity="LOW", message="test")
        assert r.status == status

    @pytest.mark.parametrize("severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_valid_severities(self, severity):
        r = CheckResult(check_id="x", status="PASS", severity=severity, message="test")
        assert r.severity == severity


# ─── Config loading ───────────────────────────────────────────────────────────

class TestConfig:
    def test_load_config(self, config_file, minimal_config):
        loaded = load_config(config_file)
        assert loaded["scan_interval_seconds"] == minimal_config["scan_interval_seconds"]
        assert "checks" in loaded

    def test_save_and_reload(self, config_file, minimal_config):
        minimal_config["scan_interval_seconds"] = 999
        save_config(minimal_config, config_file)
        reloaded = load_config(config_file)
        assert reloaded["scan_interval_seconds"] == 999

    def test_missing_config_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.json")


# ─── ScanEngine status aggregation ───────────────────────────────────────────

class TestScanEngineStatus:
    def _make_engine(self, results, config, mock_logger):
        registry = MagicMock()
        registry.run_all.return_value = results
        engine = ScanEngine(registry=registry, config=config, logger=mock_logger)
        engine.last_results = results
        return engine

    def test_unknown_when_no_results(self, minimal_config, mock_logger):
        engine = self._make_engine([], minimal_config, mock_logger)
        assert engine.overall_status == "UNKNOWN"

    def test_pass_when_all_pass(self, minimal_config, mock_logger):
        results = [
            CheckResult("a", "PASS", "LOW", "ok"),
            CheckResult("b", "PASS", "MEDIUM", "ok"),
        ]
        engine = self._make_engine(results, minimal_config, mock_logger)
        assert engine.overall_status == "PASS"

    def test_fail_dominates(self, minimal_config, mock_logger):
        results = [
            CheckResult("a", "PASS", "LOW", "ok"),
            CheckResult("b", "WARN", "MEDIUM", "warning"),
            CheckResult("c", "FAIL", "HIGH", "failed"),
        ]
        engine = self._make_engine(results, minimal_config, mock_logger)
        assert engine.overall_status == "FAIL"

    def test_warn_when_no_fail(self, minimal_config, mock_logger):
        results = [
            CheckResult("a", "PASS", "LOW", "ok"),
            CheckResult("b", "WARN", "MEDIUM", "warning"),
        ]
        engine = self._make_engine(results, minimal_config, mock_logger)
        assert engine.overall_status == "WARN"

    def test_error_treated_as_warn(self, minimal_config, mock_logger):
        results = [
            CheckResult("a", "PASS", "LOW", "ok"),
            CheckResult("b", "ERROR", "HIGH", "crashed"),
        ]
        engine = self._make_engine(results, minimal_config, mock_logger)
        assert engine.overall_status == "WARN"


# ─── CheckRegistry — disabled check becomes SKIP ─────────────────────────────

class TestCheckRegistry:
    def test_disabled_check_returns_skip(self, tmp_path, mock_logger):
        """A check disabled in config should produce a SKIP result."""
        # Create a minimal check file
        checks_dir = tmp_path / "checks"
        checks_dir.mkdir()
        check_file = checks_dir / "check_dummy.py"
        check_file.write_text(
            "from engine import CheckResult\n"
            "def run(config):\n"
            "    return CheckResult('dummy', 'PASS', 'LOW', 'ok')\n",
            encoding="utf-8"
        )

        config = {
            "checks": {
                "dummy": {"enabled": False, "severity": "LOW"}
            }
        }

        registry = CheckRegistry(checks_dir=checks_dir, config=config, logger=mock_logger)
        results = registry.run_all()

        assert len(results) == 1
        assert results[0].status == "SKIP"
        assert results[0].check_id == "dummy"

    def test_enabled_check_runs(self, tmp_path, mock_logger):
        """A check enabled in config should produce its actual result."""
        checks_dir = tmp_path / "checks"
        checks_dir.mkdir()
        check_file = checks_dir / "check_enabled.py"
        check_file.write_text(
            "from engine import CheckResult\n"
            "def run(config):\n"
            "    return CheckResult('enabled', 'PASS', 'LOW', 'all good')\n",
            encoding="utf-8"
        )

        config = {
            "checks": {
                "enabled": {"enabled": True, "severity": "LOW"}
            }
        }

        registry = CheckRegistry(checks_dir=checks_dir, config=config, logger=mock_logger)
        results = registry.run_all()

        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_crashing_check_returns_error(self, tmp_path, mock_logger):
        """A check that raises an exception should return ERROR, not crash the engine."""
        checks_dir = tmp_path / "checks"
        checks_dir.mkdir()
        check_file = checks_dir / "check_broken.py"
        check_file.write_text(
            "def run(config):\n"
            "    raise RuntimeError('boom')\n",
            encoding="utf-8"
        )

        config = {
            "checks": {
                "broken": {"enabled": True, "severity": "HIGH"}
            }
        }

        registry = CheckRegistry(checks_dir=checks_dir, config=config, logger=mock_logger)
        results = registry.run_all()

        assert len(results) == 1
        assert results[0].status == "ERROR"
        assert "boom" in results[0].message
