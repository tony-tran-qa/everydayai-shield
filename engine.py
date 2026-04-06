"""
EverydayAI-Shield - Core Engine
Handles check registration, scheduling, logging, and result aggregation.
"""

import json
import logging
import os
import importlib
import time
import threading
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from logging.handlers import TimedRotatingFileHandler

# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    check_id: str
    status: str          # "PASS", "WARN", "FAIL", "ERROR", "SKIP"
    severity: str        # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    message: str
    details: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    remediation: str = ""


# ─── Logger Setup ─────────────────────────────────────────────────────────────

def setup_logger(log_dir: Path, retention_days: int = 30) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "everydayai-shield.log"

    logger = logging.getLogger("EverydayAI-Shield")
    logger.setLevel(logging.DEBUG)

    # File handler - rotates daily
    fh = TimedRotatingFileHandler(
        log_file, when="midnight", interval=1,
        backupCount=retention_days, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)-8s | %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ─── Check Registry ───────────────────────────────────────────────────────────

class CheckRegistry:
    """Auto-discovers and loads check modules from the checks/ directory."""

    def __init__(self, checks_dir: Path, config: dict, logger: logging.Logger):
        self.checks_dir = checks_dir
        self.config = config
        self.logger = logger
        self._checks = {}
        self._load_checks()

    def _load_checks(self):
        for py_file in sorted(self.checks_dir.glob("check_*.py")):
            module_name = py_file.stem
            check_id = module_name.replace("check_", "")
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "run"):
                    self._checks[check_id] = module
                    self.logger.info(f"Loaded check: {check_id}")
                else:
                    self.logger.warning(f"Check {module_name} has no run() function - skipped")
            except Exception as e:
                self.logger.error(f"Failed to load check {module_name}: {e}")

    def reload(self):
        """Hot-reload all checks (call after adding a new check file)."""
        self._checks.clear()
        self._load_checks()

    def run_all(self) -> list[CheckResult]:
        results = []
        enabled_checks = self.config.get("checks", {})

        for check_id, module in self._checks.items():
            check_cfg = enabled_checks.get(check_id, {})
            if not check_cfg.get("enabled", True):
                results.append(CheckResult(
                    check_id=check_id,
                    status="SKIP",
                    severity=check_cfg.get("severity", "LOW"),
                    message="Check disabled in config"
                ))
                continue

            try:
                self.logger.debug(f"Running check: {check_id}")
                result = module.run(self.config)
                results.append(result)
                self.logger.info(f"[{result.status}] {check_id}: {result.message}")
                if result.details:
                    for d in result.details:
                        self.logger.debug(f"  └─ {d}")
            except Exception as e:
                self.logger.error(f"Check {check_id} raised exception: {e}")
                results.append(CheckResult(
                    check_id=check_id,
                    status="ERROR",
                    severity=check_cfg.get("severity", "MEDIUM"),
                    message=f"Check crashed: {e}"
                ))

        return results

    def run_one(self, check_id: str) -> Optional[CheckResult]:
        module = self._checks.get(check_id)
        if not module:
            return None
        try:
            return module.run(self.config)
        except Exception as e:
            return CheckResult(
                check_id=check_id, status="ERROR",
                severity="MEDIUM", message=str(e)
            )

    @property
    def check_ids(self) -> list[str]:
        return list(self._checks.keys())


# ─── Scan Engine ──────────────────────────────────────────────────────────────

class ScanEngine:
    """Runs checks on a timer, maintains last results, fires callbacks."""

    def __init__(self, registry: CheckRegistry, config: dict, logger: logging.Logger):
        self.registry = registry
        self.config = config
        self.logger = logger
        self.interval = config.get("scan_interval_seconds", 60)
        self.last_results: list[CheckResult] = []
        self.last_scan_time: Optional[str] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks = []  # fn(results) called after each scan

    def add_callback(self, fn):
        self._callbacks.append(fn)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ScanThread")
        self._thread.start()
        self.logger.info(f"Scan engine started (interval: {self.interval}s)")

    def stop(self):
        self._running = False
        self.logger.info("Scan engine stopped")

    def run_now(self):
        """Trigger an immediate scan (non-blocking)."""
        t = threading.Thread(target=self._scan, daemon=True)
        t.start()

    def _loop(self):
        while self._running:
            self._scan()
            time.sleep(self.interval)

    def _scan(self):
        self.logger.info("─── Scan started ───────────────────────────────")
        results = self.registry.run_all()
        self.last_results = results
        self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        fails = [r for r in results if r.status == "FAIL"]
        warns = [r for r in results if r.status == "WARN"]
        self.logger.info(f"Scan complete: {len(results)} checks | "
                         f"{len(fails)} FAIL | {len(warns)} WARN")

        for cb in self._callbacks:
            try:
                cb(results)
            except Exception as e:
                self.logger.error(f"Scan callback error: {e}")

    @property
    def overall_status(self) -> str:
        if not self.last_results:
            return "UNKNOWN"
        statuses = {r.status for r in self.last_results}
        if "FAIL" in statuses:
            return "FAIL"
        if "WARN" in statuses:
            return "WARN"
        if "ERROR" in statuses:
            return "WARN"
        return "PASS"


# ─── Config Loader ────────────────────────────────────────────────────────────

def load_config(config_path: Path) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_config(config: dict, config_path: Path):
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
