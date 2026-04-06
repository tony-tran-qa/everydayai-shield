"""
EverydayAI-Shield Windows Service
Runs the scan engine as a Windows service (background, no UI).
The GUI (everydayai-shield.py) connects to results via shared log files.

Install:  python everydayai-shield_service.py install
Start:    python everydayai-shield_service.py start
Stop:     python everydayai-shield_service.py stop
Remove:   python everydayai-shield_service.py remove

Requires: pip install pywin32
"""

import sys
import os
import time
import logging
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

from engine import load_config, setup_logger, CheckRegistry, ScanEngine

CONFIG_PATH = BASE_DIR / "config.json"
CHECKS_DIR  = BASE_DIR / "checks"
LOG_DIR     = BASE_DIR / "logs"


class EverydayAIShieldService(win32serviceutil.ServiceFramework if PYWIN32_AVAILABLE else object):
    _svc_name_ = "EverydayAIShieldSvc"
    _svc_display_name_ = "EverydayAI-Shield - AI Tool Security Monitor"
    _svc_description_ = (
        "Monitors AI tool security risks including MCP supply chain attacks, "
        "Ollama exposure, credential leaks, and suspicious processes."
    )

    def __init__(self, args):
        if PYWIN32_AVAILABLE:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.engine = None
        self.logger = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        if self.engine:
            self.engine.stop()
        self.logger.info("EverydayAI-Shield service stopping")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        self._run()

    def _run(self):
        config = load_config(CONFIG_PATH)
        self.logger = setup_logger(LOG_DIR, config.get("log_retention_days", 30))
        self.logger.info("EverydayAI-Shield service started")

        registry = CheckRegistry(CHECKS_DIR, config, self.logger)
        self.engine = ScanEngine(registry, config, self.logger)
        self.engine.start()

        if PYWIN32_AVAILABLE:
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        else:
            # Standalone mode (non-service)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        self.engine.stop()
        self.logger.info("EverydayAI-Shield service stopped")


def run_standalone():
    """Run scan engine in terminal without installing as a service."""
    print("EverydayAI-Shield - Standalone Mode (Ctrl+C to stop)")
    config = load_config(CONFIG_PATH)
    logger = setup_logger(LOG_DIR, config.get("log_retention_days", 30))

    registry = CheckRegistry(CHECKS_DIR, config, logger)
    engine = ScanEngine(registry, config, logger)

    def on_scan(results):
        fails = [r for r in results if r.status == "FAIL"]
        warns = [r for r in results if r.status == "WARN"]
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE: {len(results)} checks | {len(fails)} FAIL | {len(warns)} WARN")
        for r in results:
            status_sym = {"PASS": "✓", "WARN": "⚡", "FAIL": "✗", "ERROR": "!", "SKIP": "-"}.get(r.status, "?")
            print(f"  {status_sym} [{r.status:5}] {r.check_id}: {r.message}")
        print(f"{'='*60}")

    engine.add_callback(on_scan)
    engine.start()
    engine.run_now()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
        print("\nEverydayAI-Shield stopped.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No args: run standalone in terminal
        run_standalone()
    elif PYWIN32_AVAILABLE:
        win32serviceutil.HandleCommandLine(EverydayAIShieldService)
    else:
        print("ERROR: pywin32 not installed. Cannot manage Windows service.")
        print("Install it: pip install pywin32")
        print("Or run without args for standalone mode: python everydayai-shield_service.py")
        sys.exit(1)
