"""Security Audit Suite — native Oberflaeche (Navy Split-Workspace).

Setzt den Design-Handoff in Tkinter um: Konfiguration links, Live-Monitor mit
Fortschrittsring, Ergebniskacheln und Tab-Bereich rechts. Verhalten und
Engine-Callbacks entsprechen dem Original; Farbwelt ist das Navy-Designsystem.
"""
import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.engine import AuditEngine
from core.reporter import Reporter
from core.updater import AppUpdater

INTENSITIES = ["Fast (Baseline)", "Medium (Spider + Fuzzing)", "Deep (Insane - Time-Based)"]
INTENSITY_HINTS = {
    "Fast (Baseline)": "Fast: nur Baseline-Header- und Konfigurations-Checks, kein Crawling.",
    "Medium (Spider + Fuzzing)": "Medium: inkl. Spider-Crawling und Fuzzing der gefundenen URLs.",
    "Deep (Insane - Time-Based)": "Deep: zeitbasierte Tiefenanalyse — deutlich laengere Laufzeit.",
}


class Theme:
    BG_PAGE = "#dfe4ec"
    BG_WINDOW = "#eef1f5"
    SURFACE = "#ffffff"
    NAVY = "#1b3a5c"
    NAVY_HOVER = "#142a44"
    TEXT = "#1a1a2e"
    TEXT_SEC = "#55607a"
    TEXT_MUTED = "#9aa2b1"
    BORDER_INPUT = "#d7dce5"
    BORDER_CARD = "#e1e6ee"
    BADGE = "#e7e9ee"
    SUCCESS = "#1f8a5f"; SUCCESS_BG = "#e6f4ee"
    WARNING = "#b7791f"; WARNING_BG = "#fbf1e0"
    DANGER = "#b3261e"; DANGER_BG = "#fbe9e8"
    OTHER_FG = "#55607a"; OTHER_BG = "#eef1f5"
    CONSOLE_BG = "#111726"
    CONSOLE_FG = "#cdd6e6"
    CONSOLE_MUTED = "#5b6b86"
    RING_TRACK = "#e7e9ee"
    # Log-Tag-Farben
    TAG = {"PASS": "#4ade80", "FAIL": "#f87171", "WARN": "#fbbf24", "INFO": "#7dd3fc",
           "BLOCKED": "#c4b5fd", "NOT_APPLICABLE": "#c4b5fd", "TOOL_ERROR": "#c4b5fd",
           "SKIPPED": "#c4b5fd", "ERROR": "#f87171"}


class ProgressRing(tk.Canvas):
    """Fortschrittsring auf Canvas: Track + Fortschrittsbogen + Prozenttext."""

    def __init__(self, master, size=84, width=9, **kw):
        super().__init__(master, width=size, height=size, highlightthickness=0,
                         bg=Theme.SURFACE, **kw)
        self._size = size
        self._width = width
        self._pct = 0
        self._color = Theme.NAVY
        self._draw()

    def set(self, pct, color):
        self._pct = max(0, min(100, pct))
        self._color = color
        self._draw()

    def _draw(self):
        self.delete("all")
        pad = self._width // 2 + 2
        box = (pad, pad, self._size - pad, self._size - pad)
        self.create_oval(*box, outline=Theme.RING_TRACK, width=self._width)
        if self._pct > 0:
            extent = -359.999 * (self._pct / 100) if self._pct >= 100 else -360 * (self._pct / 100)
            self.create_arc(*box, start=90, extent=extent, style=tk.ARC,
                            outline=self._color, width=self._width)
        self.create_text(self._size / 2, self._size / 2, text=f"{int(self._pct)}%",
                         fill=self._color, font=("Segoe UI", 15, "bold"))


class SecurityAuditGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Audit Suite")
        self.root.geometry("1000x860")
        self.root.minsize(960, 820)
        self.root.configure(bg=Theme.BG_WINDOW)
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.updater = AppUpdater(self.base_dir)
        self.engine = None
        self.start_time = None
        self.phase = "ready"           # ready | running | done | stopped
        self.results = []
        self._counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "OTHER": 0}
        self._detecting = False
        self._updating = False
        self._build_styles()
        self._build_ui()
        self._set_version()

    # ------------------------------------------------------------------ Styles
    def _build_styles(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TFrame", background=Theme.BG_WINDOW)
        s.configure("Card.TFrame", background=Theme.SURFACE)
        s.configure("Nav.TLabel", background=Theme.BG_WINDOW, foreground=Theme.NAVY)
        s.configure("TCombobox", fieldbackground=Theme.SURFACE, background=Theme.SURFACE,
                    foreground=Theme.TEXT, arrowcolor=Theme.TEXT_MUTED, borderwidth=1, padding=6)
        s.map("TCombobox", fieldbackground=[("readonly", Theme.SURFACE)])
        s.configure("Nav.Horizontal.TProgressbar", background=Theme.NAVY,
                    troughcolor=Theme.BADGE, borderwidth=0, thickness=7)

    # ------------------------------------------------------------------ Buttons
    def _button(self, master, text, command, kind="secondary", **grid):
        colors = {
            "primary": (Theme.NAVY, "#ffffff", Theme.NAVY_HOVER),
            "secondary": (Theme.SURFACE, Theme.NAVY, "#f0f4ff"),
            "danger": (Theme.DANGER, "#ffffff", "#8f1e17"),
        }[kind]
        bg, fg, hover = colors
        btn = tk.Button(master, text=text, command=command, relief="flat", bd=0,
                        bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
                        font=("Segoe UI", 10, "bold"), cursor="hand2",
                        highlightbackground=Theme.BORDER_INPUT, highlightthickness=1,
                        padx=14, pady=9, disabledforeground=Theme.TEXT_MUTED)
        btn._kind = kind; btn._bg = bg; btn._hover = hover
        btn.bind("<Enter>", lambda e: e.widget.config(bg=e.widget._hover) if str(e.widget["state"]) != "disabled" else None)
        btn.bind("<Leave>", lambda e: e.widget.config(bg=e.widget._bg))
        return btn

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        root = tk.Frame(self.root, bg=Theme.BG_WINDOW)
        root.pack(fill=tk.BOTH, expand=True, padx=20, pady=18)
        body = tk.Frame(root, bg=Theme.BG_WINDOW)
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(0, minsize=300, weight=0)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_config(body)
        self._build_monitor(body)

    # ---- Linke Spalte -------------------------------------------------
    def _build_config(self, parent):
        col = tk.Frame(parent, bg=Theme.BG_WINDOW, width=300)
        col.grid(row=0, column=0, sticky="nsw", padx=(0, 18))
        col.grid_propagate(False)

        header = tk.Frame(col, bg=Theme.BG_WINDOW)
        header.pack(fill=tk.X, pady=(0, 16))
        tk.Label(header, text="\U0001F6E1", bg=Theme.BG_WINDOW, fg=Theme.NAVY,
                 font=("Segoe UI", 16)).pack(side=tk.LEFT)
        tk.Label(header, text="Security Audit Suite", bg=Theme.BG_WINDOW, fg=Theme.TEXT,
                 font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT, padx=(6, 0))
        self.version_label = tk.Label(header, text="v8.3", bg=Theme.BG_WINDOW,
                                      fg=Theme.TEXT_MUTED, font=("Segoe UI", 9))
        self.version_label.pack(side=tk.LEFT, padx=(6, 0), anchor="s", pady=(0, 3))
        self.update_btn = self._button(header, "Updates", self.check_updates, "secondary")
        self.update_btn.pack(side=tk.RIGHT)

        tk.Label(col, text="ZIEL-KONFIGURATION", bg=Theme.BG_WINDOW, fg=Theme.NAVY,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 10))

        tk.Label(col, text="Ziel-URL", bg=Theme.BG_WINDOW, fg=Theme.TEXT,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.url_var = tk.StringVar(value="")
        self._entry(col, self.url_var).pack(fill=tk.X, pady=(4, 8))
        self.detect_btn = self._button(col, "Analysieren", self.auto_detect, "secondary")
        self.detect_btn.pack(fill=tk.X, pady=(0, 14))

        tk.Label(col, text="Scan-Intensitaet", bg=Theme.BG_WINDOW, fg=Theme.TEXT,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.intensity_var = tk.StringVar(value=INTENSITIES[0])
        cb = ttk.Combobox(col, textvariable=self.intensity_var, values=INTENSITIES,
                          state="readonly", font=("Segoe UI", 10))
        cb.pack(fill=tk.X, pady=(4, 14))
        cb.bind("<<ComboboxSelected>>", lambda e: self._update_hint())

        tk.Label(col, text="Session (Optional)", bg=Theme.BG_WINDOW, fg=Theme.TEXT,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        srow = tk.Frame(col, bg=Theme.BG_WINDOW)
        srow.pack(fill=tk.X, pady=(4, 14))
        self.session_var = tk.StringVar()
        self._entry(srow, self.session_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._button(srow, "Browse", self.browse_session, "secondary").pack(side=tk.LEFT, padx=(8, 0))

        self.consent_var = tk.IntVar(value=0)
        consent = tk.Checkbutton(
            col, variable=self.consent_var, bg=Theme.BG_WINDOW, activebackground=Theme.BG_WINDOW,
            fg=Theme.TEXT, selectcolor=Theme.SURFACE, font=("Segoe UI", 9),
            text="Ich bestaetige die Berechtigung zum Testen (Permission to Test)",
            wraplength=270, justify="left", anchor="w")
        consent.pack(fill=tk.X, pady=(0, 14))

        actions = tk.Frame(col, bg=Theme.BG_WINDOW)
        actions.pack(fill=tk.X)
        self.start_btn = self._button(actions, "Audit starten", self.start, "primary")
        self.start_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.stop_btn = self._button(actions, "Stop", self.stop, "danger")
        self.stop_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
        self._set_state(self.stop_btn, False)
        self.save_btn = self._button(col, "Report speichern", self.save, "secondary")
        self.save_btn.pack(fill=tk.X, pady=(10, 0))
        self._set_state(self.save_btn, False)

        self.hint_label = tk.Label(col, text=INTENSITY_HINTS[INTENSITIES[0]], bg=Theme.BG_WINDOW,
                                   fg=Theme.TEXT_MUTED, font=("Segoe UI", 8), wraplength=280,
                                   justify="left", anchor="w")
        self.hint_label.pack(side=tk.BOTTOM, anchor="w", pady=(16, 0))

    def _entry(self, master, var):
        return tk.Entry(master, textvariable=var, font=("Segoe UI", 10), relief="flat",
                        bg=Theme.SURFACE, fg=Theme.TEXT, insertbackground=Theme.TEXT,
                        highlightbackground=Theme.BORDER_INPUT, highlightcolor=Theme.NAVY,
                        highlightthickness=1)

    # ---- Rechte Spalte ------------------------------------------------
    def _build_monitor(self, parent):
        col = tk.Frame(parent, bg=Theme.BG_WINDOW)
        col.grid(row=0, column=1, sticky="nsew")
        col.rowconfigure(3, weight=1)
        col.columnconfigure(0, weight=1)

        # Monitor-Card
        card = tk.Frame(col, bg=Theme.SURFACE, highlightbackground=Theme.BORDER_CARD,
                        highlightthickness=1)
        card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        inner = tk.Frame(card, bg=Theme.SURFACE)
        inner.pack(fill=tk.X, padx=16, pady=14)
        self.ring = ProgressRing(inner)
        self.ring.pack(side=tk.LEFT)
        main = tk.Frame(inner, bg=Theme.SURFACE)
        main.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(16, 0))

        head = tk.Frame(main, bg=Theme.SURFACE)
        head.pack(fill=tk.X)
        self.dot = tk.Canvas(head, width=10, height=10, highlightthickness=0, bg=Theme.SURFACE)
        self._dot_id = self.dot.create_oval(1, 1, 9, 9, fill=Theme.TEXT_MUTED, outline="")
        self.dot.pack(side=tk.LEFT, pady=(0, 4))
        self.phase_label = tk.Label(head, text="Bereit", bg=Theme.SURFACE, fg=Theme.TEXT,
                                    font=("Segoe UI", 13, "bold"))
        self.phase_label.pack(side=tk.LEFT, padx=(8, 0))
        self.timer_label = tk.Label(head, text="00:00", bg=Theme.SURFACE, fg=Theme.TEXT_SEC,
                                    font=("Consolas", 11))
        self.timer_label.pack(side=tk.RIGHT)

        self.current_label = tk.Label(main, text="Warte auf Konfiguration", bg=Theme.SURFACE,
                                      fg=Theme.TEXT_SEC, font=("Segoe UI", 10), anchor="w")
        self.current_label.pack(fill=tk.X, pady=(2, 8))

        barrow = tk.Frame(main, bg=Theme.SURFACE)
        barrow.pack(fill=tk.X)
        self.progress = ttk.Progressbar(barrow, style="Nav.Horizontal.TProgressbar",
                                        mode="determinate", maximum=100)
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.counter_label = tk.Label(barrow, text="0 / 0", bg=Theme.SURFACE, fg=Theme.TEXT_SEC,
                                      font=("Consolas", 9))
        self.counter_label.pack(side=tk.LEFT, padx=(10, 0))

        # Kacheln
        tiles = tk.Frame(col, bg=Theme.BG_WINDOW)
        tiles.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for i in range(4):
            tiles.columnconfigure(i, weight=1, uniform="tiles")
        self.tile_vals = {}
        specs = [("PASS", Theme.SUCCESS, Theme.SUCCESS_BG), ("FAIL", Theme.DANGER, Theme.DANGER_BG),
                 ("WARN", Theme.WARNING, Theme.WARNING_BG), ("OTHER", Theme.OTHER_FG, Theme.OTHER_BG)]
        for i, (name, fg, bg) in enumerate(specs):
            t = tk.Frame(tiles, bg=bg)
            t.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 5, 0))
            val = tk.Label(t, text="0", bg=bg, fg=fg, font=("Segoe UI", 18, "bold"))
            val.pack(anchor="w", padx=13, pady=(9, 0))
            tk.Label(t, text=name, bg=bg, fg=fg, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=13, pady=(0, 9))
            self.tile_vals[name] = val

        # Tabs
        self.tabs = ttk.Notebook(col)
        self.tabs.grid(row=3, column=0, sticky="nsew")
        log_tab = tk.Frame(self.tabs, bg=Theme.CONSOLE_BG)
        self.tabs.add(log_tab, text="  Live Logs  ")
        self.console = tk.Text(log_tab, bg=Theme.CONSOLE_BG, fg=Theme.CONSOLE_FG, relief="flat",
                               font=("Consolas", 10), wrap="word", padx=14, pady=12,
                               insertbackground=Theme.CONSOLE_FG, state="disabled",
                               highlightthickness=0)
        yscroll = ttk.Scrollbar(log_tab, command=self.console.yview)
        self.console.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.console.pack(fill=tk.BOTH, expand=True)
        for status, color in Theme.TAG.items():
            self.console.tag_configure(status, foreground=color)
        self.console.tag_configure("muted", foreground=Theme.CONSOLE_MUTED)
        self.console.tag_configure("arrow", foreground=Theme.CONSOLE_MUTED)

        adv_tab = tk.Frame(self.tabs, bg=Theme.SURFACE)
        self.tabs.add(adv_tab, text="  Erweiterte Einstellungen  ")
        tk.Label(adv_tab, bg=Theme.SURFACE, fg=Theme.TEXT_SEC, justify="left", anchor="w",
                 wraplength=520, font=("Segoe UI", 9),
                 text=("Diese Felder werden vom 'Analysieren'-Button automatisch ausgefuellt.\n"
                       "Nur manuell aendern, wenn die Auto-Erkennung scheitert.")
                 ).pack(anchor="w", padx=20, pady=(18, 14))
        self.adv_vars = {
            "login": tk.StringVar(value="/login"),
            "dash": tk.StringVar(value="/dashboard"),
            "email": tk.StringVar(value="input[type='email']"),
            "pass": tk.StringVar(value="input[type='password']"),
            "submit": tk.StringVar(value="button[type='submit']"),
        }
        labels = [("Login Pfad", "login"), ("Dashboard Pfad", "dash"), ("E-Mail Selektor", "email"),
                  ("Passwort Selektor", "pass"), ("Submit Selektor", "submit")]
        grid = tk.Frame(adv_tab, bg=Theme.SURFACE)
        grid.pack(anchor="w", padx=20)
        for i, (label, key) in enumerate(labels):
            tk.Label(grid, text=label, bg=Theme.SURFACE, fg=Theme.TEXT, font=("Segoe UI", 10, "bold"),
                     width=16, anchor="w").grid(row=i, column=0, sticky="w", pady=6)
            e = tk.Entry(grid, textvariable=self.adv_vars[key], font=("Consolas", 10), width=44,
                         relief="flat", bg=Theme.SURFACE, fg=Theme.TEXT,
                         highlightbackground=Theme.BORDER_INPUT, highlightcolor=Theme.NAVY,
                         highlightthickness=1)
            e.grid(row=i, column=1, sticky="w", pady=6, padx=(14, 0))

    # ------------------------------------------------------------------ Version
    def _set_version(self):
        try:
            v = self.updater.get_current_version()
            self.version_label.config(text=f"v{v}")
        except Exception:
            pass

    # ------------------------------------------------------------------ Helpers
    def _set_state(self, btn, enabled):
        btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        if not enabled:
            btn.config(bg=Theme.BADGE)
        else:
            btn.config(bg=btn._bg)

    def _update_hint(self):
        self.hint_label.config(text=INTENSITY_HINTS.get(self.intensity_var.get(), ""))

    def _log(self, msg):
        self.root.after(0, lambda: self._append_log(msg))

    def _append_log(self, msg):
        self.console.config(state="normal")
        if "-> [" in msg:
            prefix, rest = msg.split("-> [", 1)
            status, _, tail = rest.partition("]")
            self.console.insert(tk.END, prefix)
            self.console.insert(tk.END, "-> ", "arrow")
            self.console.insert(tk.END, "[")
            self.console.insert(tk.END, status, status if status in Theme.TAG else "muted")
            self.console.insert(tk.END, "]" + tail + "\n")
        elif msg[:1] == "[" and "]" in msg and msg[1:msg.find("]")] in Theme.TAG:
            i = msg.find("]")
            self.console.insert(tk.END, "[")
            self.console.insert(tk.END, msg[1:i], msg[1:i])
            self.console.insert(tk.END, msg[i:] + "\n")
        elif msg.lstrip().startswith("\u00b7 "):
            self.console.insert(tk.END, msg + "\n", "muted")
        else:
            self.console.insert(tk.END, msg + "\n")
        self.console.see(tk.END)
        self.console.config(state="disabled")

    def _clear_log(self):
        self.console.config(state="normal")
        self.console.delete("1.0", tk.END)
        self.console.config(state="disabled")

    # ------------------------------------------------------------------ Phase
    def _apply_phase(self):
        colors = {"ready": Theme.NAVY, "running": Theme.NAVY, "done": Theme.SUCCESS, "stopped": Theme.DANGER}
        dots = {"ready": Theme.TEXT_MUTED, "running": Theme.SUCCESS, "done": Theme.SUCCESS, "stopped": Theme.DANGER}
        labels = {"ready": "Bereit", "running": "Scan laeuft", "done": "Abgeschlossen", "stopped": "Abgebrochen"}
        self.phase_label.config(text=labels[self.phase])
        self.dot.itemconfig(self._dot_id, fill=dots[self.phase])
        pct = self.progress["value"]
        self.ring.set(pct, colors[self.phase])

    # ------------------------------------------------------------------ Engine-Callbacks
    def update_prog(self, cur, total):
        self.root.after(0, lambda: self._update_prog(cur, total))

    def _update_prog(self, cur, total):
        pct = (cur / total) * 100 if total else 0
        self.progress["value"] = pct
        self.counter_label.config(text=f"{cur} / {total}")
        self.ring.set(pct, {"ready": Theme.NAVY, "running": Theme.NAVY,
                            "done": Theme.SUCCESS, "stopped": Theme.DANGER}[self.phase])

    def update_current_test(self, name):
        self.root.after(0, lambda: self.current_label.config(text=f"Laeuft: {name}"))

    def update_live_result(self, status):
        self.root.after(0, lambda: self._bump_count(status))

    def _bump_count(self, status):
        cat = status if status in ("PASS", "FAIL", "WARN") else "OTHER"
        self._counts[cat] += 1
        self.tile_vals[cat].config(text=str(self._counts[cat]))

    # ------------------------------------------------------------------ Timer
    def _start_timer(self):
        self.start_time = datetime.now()
        self._tick()

    def _tick(self):
        if self.start_time is None or self.phase != "running":
            return
        elapsed = int((datetime.now() - self.start_time).total_seconds())
        self.timer_label.config(text=f"{elapsed // 60:02d}:{elapsed % 60:02d}")
        self.root.after(1000, self._tick)

    # ------------------------------------------------------------------ Aktionen
    def start(self):
        if not self.consent_var.get():
            messagebox.showwarning("Achtung", "Bitte bestaetige die Berechtigung zum Testen.")
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Achtung", "Bitte eine Ziel-URL eingeben.")
            return
        if not url.startswith("http"):
            url = "https://" + url
        config = {
            "url": url, "intensity": self.intensity_var.get(),
            "login_path": self.adv_vars["login"].get() or "/login",
            "dashboard_path": self.adv_vars["dash"].get() or "/dashboard",
            "email_sel": self.adv_vars["email"].get(), "pass_sel": self.adv_vars["pass"].get(),
            "btn_sel": self.adv_vars["submit"].get(), "session_file": self.session_var.get(),
            "headless": False,
        }
        self.phase = "running"
        self.results = []
        self._counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "OTHER": 0}
        for name, lbl in self.tile_vals.items():
            lbl.config(text="0")
        self._clear_log()
        self.progress["value"] = 0
        self.counter_label.config(text="0 / 0")
        self.current_label.config(text="Initialisiere...")
        self._set_state(self.start_btn, False)
        self._set_state(self.stop_btn, True)
        self._set_state(self.save_btn, False)
        self.start_btn.config(text="Laeuft...")
        self.tabs.select(0)
        self._apply_phase()
        self._start_timer()
        self.engine = AuditEngine(config)
        self.engine.log_callback = self._log
        self.engine.progress_callback = self.update_prog
        self.engine.current_test_callback = self.update_current_test
        self.engine.result_callback = self.update_live_result
        threading.Thread(target=self._run_engine, daemon=True).start()

    def _run_engine(self):
        try:
            self.results = self.engine.run()
        finally:
            self.root.after(0, self._finish)

    def _finish(self):
        if self.phase == "stopped":
            return
        self.phase = "done"
        self.start_btn.config(text="Audit starten")
        self._set_state(self.start_btn, True)
        self._set_state(self.stop_btn, False)
        self._set_state(self.save_btn, True)
        elapsed = int((datetime.now() - self.start_time).total_seconds()) if self.start_time else 0
        self.current_label.config(text=f"Abgeschlossen — {len(self.results)} Tests in {elapsed // 60:02d}:{elapsed % 60:02d}")
        counts = {}
        for r in self.results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        other = sum(v for k, v in counts.items() if k not in ("PASS", "FAIL", "WARN"))
        self._log("")
        self._log("=" * 50)
        self._log("ZUSAMMENFASSUNG")
        self._log("=" * 50)
        self._log(f"PASS: {counts.get('PASS', 0)}  |  FAIL: {counts.get('FAIL', 0)}  |  "
                  f"WARN: {counts.get('WARN', 0)}  |  OTHER: {other}")
        self._log("=" * 50)

        from core.remediation import iter_findings
        findings = list(iter_findings(self.results))
        if findings:
            self._log("")
            self._log("=" * 50)
            self._log(f"BEFUNDE & EMPFEHLUNGEN ({len(findings)})")
            self._log("=" * 50)
            for fd in findings:
                self._log("")
                self._log(f"[{fd['status']}] {fd['test_id']}: {fd['title']}")
                self._log(f"   Befund:   {fd['message']}")
                self._log(f"   Ursache:  {fd['explanation']}")
                self._log(f"   Behebung: {fd['remediation']}")
        self._apply_phase()

    def stop(self):
        if self.engine and self.phase == "running":
            self.engine.stop()
        self.phase = "stopped"
        self.start_time = None
        self.start_btn.config(text="Audit starten")
        self._set_state(self.start_btn, True)
        self._set_state(self.stop_btn, False)
        self._log("")
        self._log("  -> [INFO] Audit vom Benutzer abgebrochen.")
        self.current_label.config(text="Abgebrochen")
        self._apply_phase()

    def save(self):
        if self.phase != "done":
            return
        d = filedialog.askdirectory(title="Report speichern in...")
        if not d:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        Reporter.save_txt(self.results, os.path.join(d, f"audit_{ts}.txt"))
        Reporter.save_json(self.results, os.path.join(d, f"audit_{ts}.json"))
        Reporter.save_html(self.results, os.path.join(d, f"audit_{ts}.html"))
        self._log("")
        self._log(f"  -> [INFO] Report gespeichert: audit_{ts}.txt / .json / .html")
        messagebox.showinfo("Erfolg", "Reports gespeichert (TXT, JSON, HTML).")

    def browse_session(self):
        f = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if f:
            self.session_var.set(f)

    def auto_detect(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Achtung", "Bitte eine URL eingeben.")
            return
        if self._detecting:
            return
        self._detecting = True
        self.detect_btn.config(text="Analysiere...")
        self._set_state(self.detect_btn, False)
        self._log("Analysiere Zielseite...")
        threading.Thread(target=self._run_detect, args=(url,), daemon=True).start()

    def _run_detect(self, url):
        from playwright.sync_api import sync_playwright
        found = {}
        error = None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                path = page.url.replace(url, "")
                if "login" in path.lower() or "auth" in path.lower():
                    found["login"] = path.split("?")[0]
                emails = ["input[type='email']", "input[name='email']", "input[name='username']"]
                passes = ["input[type='password']", "input[name='password']"]
                subs = ["button[type='submit']", "input[type='submit']", "button:has-text('Anmelden')"]
                fe = next((s for s in emails if page.locator(s).count() > 0), None)
                fp = next((s for s in passes if page.locator(s).count() > 0), None)
                fs = next((s for s in subs if page.locator(s).count() > 0), None)
                if fe: found["email"] = fe
                if fp: found["pass"] = fp
                if fs: found["submit"] = fs
                browser.close()
        except Exception as e:
            error = str(e)
        self.root.after(0, lambda: self._detect_done(found, error))

    def _detect_done(self, found, error):
        self._detecting = False
        self.detect_btn.config(text="Analysieren")
        self._set_state(self.detect_btn, True)
        for key, val in found.items():
            self.adv_vars[key].set(val)
        if error:
            self._log(f"Analysefehler: {error}")
        else:
            self._log("Analyse abgeschlossen. Felder konfiguriert.")

    def check_updates(self):
        if self._updating:
            return
        self._updating = True
        self.update_btn.config(text="Suche...")
        self._set_state(self.update_btn, False)
        threading.Thread(target=self._run_update_check, daemon=True).start()

    def _run_update_check(self):
        result, error = None, None
        try:
            result = self.updater.check_online()
        except Exception as e:
            error = str(e)
            local = self.updater.check_local_zip()
            if local:
                result = {"local": local}
        self.root.after(0, lambda: self._update_check_done(result, error))

    def _update_check_done(self, result, error):
        self._updating = False
        self.update_btn.config(text="Updates")
        self._set_state(self.update_btn, True)
        if result and result.get("local"):
            if messagebox.askyesno("Update", "Lokales Update gefunden. Jetzt installieren?"):
                res = self.updater.apply_local_zip(result["local"])
                if res is True:
                    messagebox.showinfo("Update", "Update installiert. Bitte neu starten.")
                else:
                    messagebox.showerror("Update", f"Fehler: {res}")
            return
        if result:
            msg = f"Version {result['version']} verfuegbar. Jetzt herunterladen und installieren?"
            if messagebox.askyesno("Update verfuegbar", msg):
                self._log(f"Lade Update {result['version']}...")
                threading.Thread(target=self._download_and_run, args=(result,), daemon=True).start()
            return
        if error:
            messagebox.showinfo("Updates", f"Update-Pruefung nicht moeglich:\n{error}\n\n"
                                "Alternativ ein 'update.zip' im Updates-Ordner ablegen.")
        else:
            messagebox.showinfo("Updates", "Keine Updates gefunden.")

    def _download_and_run(self, result):
        try:
            path = self.updater.download(result["url"], result["name"])
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Update", f"Download fehlgeschlagen: {e}"))
            return
        self.root.after(0, lambda: self._run_installer(path))

    def _run_installer(self, path):
        if messagebox.askyesno("Update", "Download abgeschlossen. Installer starten? Die App wird beendet."):
            try:
                self.updater.run_installer(path)
                self.root.destroy()
                sys.exit(0)
            except Exception as e:
                messagebox.showerror("Update", f"Installer-Start fehlgeschlagen: {e}")


def main():
    root = tk.Tk()
    SecurityAuditGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
