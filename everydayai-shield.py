"""
EverydayAI-Shield - Main Application
System tray icon + Tkinter dashboard GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
import sys
import os
import importlib
from pathlib import Path
from datetime import datetime

# ─── Path Setup ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CHECKS_DIR = BASE_DIR / "checks"
LOG_DIR = BASE_DIR / "logs"
CONFIG_PATH = BASE_DIR / "config.json"

sys.path.insert(0, str(BASE_DIR))
from engine import load_config, save_config, setup_logger, CheckRegistry, ScanEngine, CheckResult

# ─── Colors (dark theme) ──────────────────────────────────────────────────────
BG_MAIN = "#0a0a0f"
BG_SURFACE = "#13131a"
BG_CARD = "#1c1c28"
BORDER = "#2a2a3d"
ACCENT = "#7c6af7"
ACCENT2 = "#3de8c8"

STATUS_COLORS = {
    "PASS":    "#22c55e",
    "WARN":    "#f59e0b",
    "FAIL":    "#ef4444",
    "ERROR":   "#f97316",
    "SKIP":    "#6b7280",
    "UNKNOWN": "#6b7280",
}

TRAY_COLORS = {
    "PASS":    "green",
    "WARN":    "orange",
    "FAIL":    "red",
    "UNKNOWN": "gray",
}

FONT_MONO = ("Consolas", 9)
FONT_BODY = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 9)
FONT_TITLE = ("Segoe UI Semibold", 12)
FONT_HEAD  = ("Segoe UI Semibold", 10)


# ─── Tray Icon (optional, gracefully degrades) ────────────────────────────────
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


def create_tray_image(color: str, size=64) -> "Image":
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Shield shape
    margin = 4
    w, h = size - margin * 2, size - margin * 2
    x0, y0 = margin, margin
    # Shield polygon
    pts = [
        (x0 + w//2, y0),           # top center
        (x0 + w, y0 + h//3),       # top right
        (x0 + w, y0 + int(h*0.6)), # mid right
        (x0 + w//2, y0 + h),       # bottom center
        (x0, y0 + int(h*0.6)),     # mid left
        (x0, y0 + h//3),           # top left
    ]
    draw.polygon(pts, fill=color)
    return img


class TrayIcon:
    def __init__(self, app):
        self.app = app
        self.icon = None

    def start(self):
        if not TRAY_AVAILABLE:
            return
        img = create_tray_image("gray")
        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", self._open, default=True),
            pystray.MenuItem("Run Scan Now", self._scan_now),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit EverydayAI-Shield", self._quit),
        )
        self.icon = pystray.Icon("EverydayAI-Shield", img, "EverydayAI-Shield — Initializing", menu)
        threading.Thread(target=self.icon.run, daemon=True).start()

    def update(self, status: str):
        if not TRAY_AVAILABLE or not self.icon:
            return
        color = TRAY_COLORS.get(status, "gray")
        self.icon.icon = create_tray_image(color)
        self.icon.title = f"EverydayAI-Shield — {status}"

    def _open(self):
        self.app.show_window()

    def _scan_now(self):
        self.app.run_scan_now()

    def _quit(self):
        self.app.quit_app()


# ─── Main Dashboard Window ─────────────────────────────────────────────────────

class EverydayAIShieldApp:
    def __init__(self):
        self.config = load_config(CONFIG_PATH)
        self.logger = setup_logger(LOG_DIR, self.config.get("log_retention_days", 30))
        self.registry = CheckRegistry(CHECKS_DIR, self.config, self.logger)
        self.engine = ScanEngine(self.registry, self.config, self.logger)
        self.engine.add_callback(self._on_scan_complete)

        self.root = tk.Tk()
        self.root.title("EverydayAI-Shield — AI Tool Security Monitor")
        self.root.geometry("1020x700")
        self.root.minsize(800, 560)
        self.root.configure(bg=BG_MAIN)
        self.root.protocol("WM_DELETE_WINDOW", self._hide_window)

        self._build_ui()

        self.tray = TrayIcon(self)
        self.tray.start()

        self.engine.start()
        self.logger.info("EverydayAI-Shield started")

        # Initial scan
        self.engine.run_now()

    # ─── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

    def _build_header(self):
        header = tk.Frame(self.root, bg=BG_SURFACE, pady=10)
        header.pack(fill="x", side="top")

        # Logo / title
        tk.Label(header, text="🛡 EverydayAI-Shield", font=("Segoe UI Semibold", 16),
                 fg=ACCENT, bg=BG_SURFACE).pack(side="left", padx=16)
        tk.Label(header, text="AI Tool Security Monitor", font=FONT_BODY,
                 fg="#a0a0c0", bg=BG_SURFACE).pack(side="left")

        # Status badge
        self.status_badge = tk.Label(header, text="  INITIALIZING  ",
                                     font=("Segoe UI Semibold", 10),
                                     fg="#000", bg="#6b7280",
                                     padx=8, pady=4, relief="flat")
        self.status_badge.pack(side="right", padx=16)

        # Last scan time
        self.last_scan_lbl = tk.Label(header, text="Last scan: —",
                                      font=FONT_LABEL, fg="#6b7280", bg=BG_SURFACE)
        self.last_scan_lbl.pack(side="right", padx=8)

        # Scan button
        scan_btn = tk.Button(header, text="▶  Scan Now",
                             font=FONT_HEAD, fg="#fff", bg=ACCENT,
                             activebackground="#6355d4", activeforeground="#fff",
                             relief="flat", padx=14, pady=5, cursor="hand2",
                             command=self.run_scan_now)
        scan_btn.pack(side="right", padx=8)

    def _build_tabs(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_MAIN, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_SURFACE,
                        foreground="#a0a0c0", padding=[14, 6],
                        font=FONT_HEAD)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_CARD)],
                  foreground=[("selected", "#fff")])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=0, pady=0)

        # Tab 1: Dashboard
        self.dash_frame = tk.Frame(self.notebook, bg=BG_MAIN)
        self.notebook.add(self.dash_frame, text="  Dashboard  ")
        self._build_dashboard_tab()

        # Tab 2: Logs
        self.log_frame = tk.Frame(self.notebook, bg=BG_MAIN)
        self.notebook.add(self.log_frame, text="  Live Log  ")
        self._build_log_tab()

        # Tab 3: Config
        self.cfg_frame = tk.Frame(self.notebook, bg=BG_MAIN)
        self.notebook.add(self.cfg_frame, text="  Configure  ")
        self._build_config_tab()

        # Tab 4: Add Check
        self.add_frame = tk.Frame(self.notebook, bg=BG_MAIN)
        self.notebook.add(self.add_frame, text="  + Add Check  ")
        self._build_add_check_tab()

    def _build_dashboard_tab(self):
        # Scrollable canvas for check cards
        canvas = tk.Canvas(self.dash_frame, bg=BG_MAIN, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.dash_frame, orient="vertical", command=canvas.yview)
        self.cards_frame = tk.Frame(canvas, bg=BG_MAIN)

        self.cards_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind mousewheel
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        self.check_cards = {}  # check_id -> dict of card widgets

    def _build_log_tab(self):
        controls = tk.Frame(self.log_frame, bg=BG_MAIN, pady=6)
        controls.pack(fill="x", padx=12)

        tk.Label(controls, text="Live Log", font=FONT_TITLE,
                 fg="#fff", bg=BG_MAIN).pack(side="left")

        tk.Button(controls, text="Clear", font=FONT_LABEL,
                  fg="#a0a0c0", bg=BG_SURFACE, relief="flat",
                  command=self._clear_log, cursor="hand2").pack(side="right", padx=4)

        tk.Button(controls, text="Open Log File", font=FONT_LABEL,
                  fg="#a0a0c0", bg=BG_SURFACE, relief="flat",
                  command=self._open_log_file, cursor="hand2").pack(side="right", padx=4)

        self.log_box = scrolledtext.ScrolledText(
            self.log_frame, bg="#0a0a10", fg="#c0c0d0",
            font=FONT_MONO, relief="flat", padx=10, pady=8,
            state="disabled", wrap="none"
        )
        self.log_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Color tags
        self.log_box.tag_config("INFO",    foreground="#a0a0c0")
        self.log_box.tag_config("WARNING", foreground="#f59e0b")
        self.log_box.tag_config("ERROR",   foreground="#ef4444")
        self.log_box.tag_config("CRITICAL",foreground="#ff2255")
        self.log_box.tag_config("DEBUG",   foreground="#555580")

        # Hook into logger
        self._setup_log_handler()

    def _build_config_tab(self):
        tk.Label(self.cfg_frame, text="Check Configuration",
                 font=FONT_TITLE, fg="#fff", bg=BG_MAIN).pack(anchor="w", padx=16, pady=(12, 4))

        tk.Label(self.cfg_frame,
                 text="Toggle checks on/off. Changes take effect on next scan.",
                 font=FONT_LABEL, fg="#6b7280", bg=BG_MAIN).pack(anchor="w", padx=16, pady=(0, 8))

        scroll_canvas = tk.Canvas(self.cfg_frame, bg=BG_MAIN, highlightthickness=0)
        vsb = ttk.Scrollbar(self.cfg_frame, orient="vertical", command=scroll_canvas.yview)
        inner = tk.Frame(scroll_canvas, bg=BG_MAIN)
        inner.bind("<Configure>",
                   lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all")))
        scroll_canvas.create_window((0, 0), window=inner, anchor="nw")
        scroll_canvas.configure(yscrollcommand=vsb.set)
        scroll_canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._check_vars = {}
        checks_cfg = self.config.get("checks", {})

        for check_id, cfg in checks_cfg.items():
            row = tk.Frame(inner, bg=BG_CARD, pady=8, padx=12)
            row.pack(fill="x", padx=12, pady=4)

            var = tk.BooleanVar(value=cfg.get("enabled", True))
            self._check_vars[check_id] = var

            sev = cfg.get("severity", "MEDIUM")
            sev_color = {"LOW": "#22c55e", "MEDIUM": "#f59e0b",
                         "HIGH": "#f97316", "CRITICAL": "#ef4444"}.get(sev, "#fff")

            tk.Label(row, text=f"[{sev}]", font=FONT_LABEL,
                     fg=sev_color, bg=BG_CARD, width=9, anchor="w").pack(side="left")

            tk.Label(row, text=check_id, font=FONT_HEAD,
                     fg="#fff", bg=BG_CARD, anchor="w").pack(side="left", padx=(4, 0))

            tk.Label(row, text=cfg.get("description", ""),
                     font=FONT_LABEL, fg="#6b7280", bg=BG_CARD).pack(side="left", padx=12)

            cb = tk.Checkbutton(row, variable=var, bg=BG_CARD,
                                activebackground=BG_CARD, fg="#fff",
                                selectcolor=BG_MAIN, text="Enabled",
                                font=FONT_LABEL, command=self._save_config_changes)
            cb.pack(side="right")

        # Interval setting
        interval_row = tk.Frame(self.cfg_frame, bg=BG_MAIN, pady=8)
        interval_row.pack(fill="x", padx=16)
        tk.Label(interval_row, text="Scan interval (seconds):",
                 font=FONT_BODY, fg="#a0a0c0", bg=BG_MAIN).pack(side="left")
        self._interval_var = tk.IntVar(value=self.config.get("scan_interval_seconds", 60))
        interval_spin = tk.Spinbox(interval_row, from_=15, to=3600,
                                   textvariable=self._interval_var,
                                   width=6, font=FONT_BODY,
                                   bg=BG_SURFACE, fg="#fff",
                                   command=self._save_config_changes)
        interval_spin.pack(side="left", padx=8)

        tk.Button(self.cfg_frame, text="Save & Apply",
                  font=FONT_HEAD, fg="#fff", bg=ACCENT, relief="flat",
                  padx=14, pady=6, cursor="hand2",
                  command=self._save_config_changes).pack(anchor="e", padx=16, pady=8)

    def _build_add_check_tab(self):
        tk.Label(self.add_frame, text="Add a Custom Check",
                 font=FONT_TITLE, fg="#fff", bg=BG_MAIN).pack(anchor="w", padx=16, pady=(12, 2))

        tk.Label(self.add_frame,
                 text="Drop a check_<name>.py file in the checks/ folder, then click Reload.",
                 font=FONT_LABEL, fg="#6b7280", bg=BG_MAIN).pack(anchor="w", padx=16)

        template_lbl = tk.Label(self.add_frame,
                                text="Check Template:", font=FONT_HEAD,
                                fg="#a0a0c0", bg=BG_MAIN)
        template_lbl.pack(anchor="w", padx=16, pady=(16, 4))

        template = '''"""
Check: my_custom_check
Description of what this check does.
"""
from engine import CheckResult

def run(config: dict) -> CheckResult:
    check_id = "my_custom_check"
    severity = config.get("checks", {}).get(check_id, {}).get("severity", "MEDIUM")
    details = []
    issues = []

    # Your check logic here
    # ...

    if issues:
        return CheckResult(
            check_id=check_id, status="FAIL", severity=severity,
            message=f"{len(issues)} issue(s) found",
            details=details + issues,
            remediation="How to fix this..."
        )

    return CheckResult(
        check_id=check_id, status="PASS", severity=severity,
        message="Check passed",
        details=details
    )
'''

        code_box = scrolledtext.ScrolledText(
            self.add_frame, bg="#0a0a10", fg="#c0c0d0",
            font=FONT_MONO, height=20, relief="flat", padx=10, pady=8
        )
        code_box.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        code_box.insert("1.0", template)

        btn_row = tk.Frame(self.add_frame, bg=BG_MAIN)
        btn_row.pack(fill="x", padx=16, pady=8)

        def open_checks_dir():
            os.startfile(str(CHECKS_DIR))

        tk.Button(btn_row, text="Open checks/ Folder",
                  font=FONT_HEAD, fg="#a0a0c0", bg=BG_SURFACE, relief="flat",
                  padx=12, pady=6, cursor="hand2",
                  command=open_checks_dir).pack(side="left")

        tk.Button(btn_row, text="↺  Reload All Checks",
                  font=FONT_HEAD, fg="#fff", bg=ACCENT2, relief="flat",
                  padx=14, pady=6, cursor="hand2",
                  command=self._reload_checks).pack(side="left", padx=12)

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=BG_SURFACE, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.status_bar_lbl = tk.Label(bar,
            text="EverydayAI-Shield v1.0 | McAfee + EverydayAI-Shield | Checks: 0 loaded",
            font=("Segoe UI", 8), fg="#555580", bg=BG_SURFACE)
        self.status_bar_lbl.pack(side="left", padx=10)

        if not TRAY_AVAILABLE:
            tk.Label(bar, text="⚠ pystray/Pillow not installed — tray icon disabled",
                     font=("Segoe UI", 8), fg="#f59e0b", bg=BG_SURFACE).pack(side="right", padx=10)

    # ─── Log Handler ──────────────────────────────────────────────────────────

    def _setup_log_handler(self):
        import logging

        class GuiLogHandler(logging.Handler):
            def __init__(self_, widget):
                super().__init__()
                self_.widget = widget

            def emit(self_, record):
                msg = self_.format(record)
                level = record.levelname

                def _append():
                    self_.widget.configure(state="normal")
                    self_.widget.insert("end", msg + "\n", level)
                    self_.widget.see("end")
                    self_.widget.configure(state="disabled")

                try:
                    self.root.after(0, _append)
                except Exception:
                    pass

        handler = GuiLogHandler(self.log_box)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%H:%M:%S"
        ))
        logging.getLogger("EverydayAI-Shield").addHandler(handler)

    # ─── Card Rendering ───────────────────────────────────────────────────────

    def _render_cards(self, results: list):
        # Clear existing
        for widget in self.cards_frame.winfo_children():
            widget.destroy()
        self.check_cards.clear()

        # Group by status
        for r in sorted(results, key=lambda x: (
            {"FAIL": 0, "ERROR": 1, "WARN": 2, "PASS": 3, "SKIP": 4}.get(x.status, 5)
        )):
            self._render_card(r)

        self.status_bar_lbl.configure(
            text=f"EverydayAI-Shield v1.0 | McAfee + EverydayAI-Shield | {len(results)} checks | "
                 f"Last: {self.engine.last_scan_time or '—'}"
        )

    def _render_card(self, result: CheckResult):
        color = STATUS_COLORS.get(result.status, "#6b7280")

        card = tk.Frame(self.cards_frame, bg=BG_CARD, pady=0)
        card.pack(fill="x", padx=12, pady=4)

        # Top accent bar
        accent_bar = tk.Frame(card, bg=color, height=3)
        accent_bar.pack(fill="x")

        body = tk.Frame(card, bg=BG_CARD, padx=12, pady=8)
        body.pack(fill="x")

        # Header row
        hdr = tk.Frame(body, bg=BG_CARD)
        hdr.pack(fill="x")

        # Status badge
        tk.Label(hdr, text=f" {result.status} ", font=("Segoe UI Semibold", 9),
                 fg="#000" if result.status not in ("SKIP", "UNKNOWN") else "#fff",
                 bg=color, padx=4).pack(side="left")

        # Check ID
        tk.Label(hdr, text=result.check_id.replace("_", " ").title(),
                 font=FONT_HEAD, fg="#fff", bg=BG_CARD).pack(side="left", padx=(8, 0))

        # Severity
        sev = result.severity
        sev_color = {"LOW": "#22c55e", "MEDIUM": "#f59e0b",
                     "HIGH": "#f97316", "CRITICAL": "#ef4444"}.get(sev, "#6b7280")
        tk.Label(hdr, text=f"[{sev}]", font=FONT_LABEL,
                 fg=sev_color, bg=BG_CARD).pack(side="right")

        # Message
        tk.Label(body, text=result.message, font=FONT_BODY,
                 fg="#c0c0d0", bg=BG_CARD, anchor="w", wraplength=850,
                 justify="left").pack(fill="x", pady=(4, 0))

        # Expandable details
        if result.details or result.remediation:
            toggle_var = tk.BooleanVar(value=False)
            detail_frame = tk.Frame(body, bg=BG_MAIN)

            def toggle(df=detail_frame, tv=toggle_var, btn_ref=[None]):
                tv.set(not tv.get())
                if tv.get():
                    df.pack(fill="x", pady=(4, 0))
                    if btn_ref[0]:
                        btn_ref[0].configure(text="▲ Hide details")
                else:
                    df.pack_forget()
                    if btn_ref[0]:
                        btn_ref[0].configure(text="▼ Show details")

            btn = tk.Button(body, text="▼ Show details",
                            font=FONT_LABEL, fg=ACCENT, bg=BG_CARD,
                            relief="flat", cursor="hand2", command=toggle)
            btn.pack(anchor="w", pady=(4, 0))
            toggle_var_ref = [btn]

            # Details list
            if result.details:
                for d in result.details[:15]:
                    tk.Label(detail_frame, text=f"  {d}", font=FONT_MONO,
                             fg="#a0a0c0", bg=BG_MAIN, anchor="w",
                             justify="left", wraplength=820).pack(fill="x")

            # Remediation
            if result.remediation:
                tk.Label(detail_frame, text="Remediation:",
                         font=FONT_HEAD, fg=ACCENT2, bg=BG_MAIN).pack(anchor="w", pady=(6, 0))
                tk.Label(detail_frame, text=result.remediation,
                         font=FONT_LABEL, fg="#a0ffe0", bg=BG_MAIN,
                         anchor="w", justify="left", wraplength=820).pack(fill="x")

        self.check_cards[result.check_id] = card

    # ─── Callbacks ────────────────────────────────────────────────────────────

    def _on_scan_complete(self, results: list):
        status = self.engine.overall_status
        color = STATUS_COLORS.get(status, "#6b7280")

        def _update():
            self._render_cards(results)
            self.status_badge.configure(
                text=f"  {status}  ",
                bg=color,
                fg="#000" if status not in ("SKIP", "UNKNOWN") else "#fff"
            )
            self.last_scan_lbl.configure(
                text=f"Last scan: {self.engine.last_scan_time}"
            )
            self.tray.update(status)

        self.root.after(0, _update)

    def _save_config_changes(self):
        for check_id, var in self._check_vars.items():
            if check_id in self.config["checks"]:
                self.config["checks"][check_id]["enabled"] = var.get()
        self.config["scan_interval_seconds"] = self._interval_var.get()
        self.engine.interval = self._interval_var.get()
        save_config(self.config, CONFIG_PATH)
        self.logger.info("Config saved")

    def _reload_checks(self):
        self.registry.reload()
        self.logger.info(f"Checks reloaded: {len(self.registry.check_ids)} loaded")
        messagebox.showinfo("Reloaded",
                            f"Checks reloaded.\n{len(self.registry.check_ids)} checks active.")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _open_log_file(self):
        log_file = LOG_DIR / "everydayai-shield.log"
        if log_file.exists():
            os.startfile(str(log_file))
        else:
            messagebox.showinfo("Log File", "No log file found yet.")

    def run_scan_now(self):
        self.engine.run_now()

    def show_window(self):
        self.root.after(0, lambda: (self.root.deiconify(), self.root.lift()))

    def _hide_window(self):
        if TRAY_AVAILABLE:
            self.root.withdraw()
        else:
            self.quit_app()

    def quit_app(self):
        self.engine.stop()
        if TRAY_AVAILABLE and self.tray.icon:
            self.tray.icon.stop()
        self.root.quit()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = EverydayAIShieldApp()
    app.run()