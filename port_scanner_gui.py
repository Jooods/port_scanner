"""
port_scanner_gui.py
Modern Windows Port Scanner Desktop GUI
Built with standard Python Tkinter (Zero external dependencies, User-level execution)
"""

import csv
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scanner_core import (
    COMMON_SERVICES,
    PORT_PRESETS,
    parse_port_input,
    scan_ports_parallel,
)


class PortScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Windows Port Scanner (TCP / UDP)")
        self.root.geometry("860x650")
        self.root.minsize(740, 500)

        # Scanner state
        self.scan_thread = None
        self.is_scanning = False
        self.stop_requested = False
        self.scan_results = []  # list of tuples: (port, proto, status, service, latency)

        # Style configuration
        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        self.style = ttk.Style(self.root)
        # Use 'clam' or native if available
        available_themes = self.style.theme_names()
        if "clam" in available_themes:
            self.style.theme_use("clam")

        # Color palette
        self.bg_dark = "#1e1e24"
        self.card_bg = "#2b2b36"
        self.input_bg = "#181820"
        self.accent_blue = "#3b82f6"
        self.accent_green = "#10b981"
        self.accent_red = "#ef4444"
        self.text_light = "#f3f4f6"
        self.text_dim = "#9ca3af"

        self.root.configure(bg=self.bg_dark)

        # Custom ttk styles
        self.style.configure(".", background=self.bg_dark, foreground=self.text_light, font=("Segoe UI", 9))
        self.style.configure("TFrame", background=self.bg_dark)
        self.style.configure("Card.TFrame", background=self.card_bg, relief="flat")
        self.style.configure("TLabel", background=self.bg_dark, foreground=self.text_light, font=("Segoe UI", 9))
        self.style.configure("Card.TLabel", background=self.card_bg, foreground=self.text_light, font=("Segoe UI", 9))
        self.style.configure("Title.TLabel", background=self.bg_dark, foreground="#ffffff", font=("Segoe UI", 13, "bold"))
        self.style.configure("Subtitle.TLabel", background=self.bg_dark, foreground=self.text_dim, font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", background=self.card_bg, foreground="#ffffff", font=("Segoe UI", 10, "bold"))

        # Input Entry styling (Target Host, Ports to Scan, Timeout, Search / Filter)
        self.style.configure(
            "TEntry",
            fieldbackground=self.input_bg,
            foreground="#ffffff",
            insertcolor="#ffffff",
            bordercolor="#3f3f50",
            lightcolor="#3f3f50",
            darkcolor=self.input_bg,
            padding=5,
            font=("Segoe UI", 9),
        )
        self.style.map(
            "TEntry",
            fieldbackground=[("focus", self.input_bg), ("disabled", "#2b2b36")],
            foreground=[("focus", "#ffffff"), ("disabled", "#6b7280")],
            bordercolor=[("focus", self.accent_blue)],
            lightcolor=[("focus", self.accent_blue)],
            selectbackground=[("focus", self.accent_blue)],
            selectforeground=[("focus", "#ffffff")],
        )

        # Treeview styling
        self.style.configure(
            "Treeview",
            background="#23232c",
            foreground="#e2e8f0",
            fieldbackground="#23232c",
            rowheight=26,
            font=("Segoe UI", 9),
        )
        self.style.configure("Treeview.Heading", background="#18181f", foreground="#94a3b8", font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", "#3b82f6")], foreground=[("selected", "#ffffff")])

        # Progressbar styling
        self.style.configure(
            "Horizontal.TProgressbar",
            background=self.accent_blue,
            troughcolor="#181820",
            bordercolor="#2b2b36",
            lightcolor=self.accent_blue,
            darkcolor=self.accent_blue,
        )

        # Scrollbar styling
        self.style.configure(
            "Vertical.TScrollbar",
            background="#2b2b36",
            troughcolor="#1e1e24",
            bordercolor="#1e1e24",
            arrowcolor="#9ca3af",
        )
        self.style.map("Vertical.TScrollbar", background=[("active", "#3b82f6")])

        # Buttons
        self.style.configure("Action.TButton", font=("Segoe UI", 9, "bold"), padding=6)
        self.style.configure("Preset.TButton", font=("Segoe UI", 8), padding=3)

    def _build_ui(self):
        # 1. Header banner
        header_frame = ttk.Frame(self.root, padding="15 12 15 5")
        header_frame.pack(fill=tk.X)

        title_lbl = ttk.Label(header_frame, text="🔍 Windows Port Scanner", style="Title.TLabel")
        title_lbl.pack(anchor=tk.W)
        subtitle_lbl = ttk.Label(
            header_frame,
            text="User-level TCP & UDP port status scanner • Safe execution without Administrator rights",
            style="Subtitle.TLabel",
        )
        subtitle_lbl.pack(anchor=tk.W)

        # 2. Main Config Card
        config_frame = ttk.Frame(self.root, style="Card.TFrame", padding="14")
        config_frame.pack(fill=tk.X, padx=15, pady=8)

        # Row 1: Target Host and Protocol
        r1_frame = ttk.Frame(config_frame, style="Card.TFrame")
        r1_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(r1_frame, text="Target Host / IP:", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.host_entry = ttk.Entry(r1_frame, textvariable=self.host_var, width=22, font=("Segoe UI", 9))
        self.host_entry.pack(side=tk.LEFT, padx=(0, 20))

        ttk.Label(r1_frame, text="Protocol:", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.proto_var = tk.StringVar(value="TCP")
        for proto in ("TCP", "UDP", "BOTH"):
            rb = tk.Radiobutton(
                r1_frame,
                text=proto,
                variable=self.proto_var,
                value=proto,
                bg=self.card_bg,
                fg=self.text_light,
                selectcolor="#1e1e24",
                activebackground=self.card_bg,
                activeforeground="#ffffff",
                font=("Segoe UI", 9),
            )
            rb.pack(side=tk.LEFT, padx=4)

        # Timeout setting
        ttk.Label(r1_frame, text="Timeout (s):", style="Card.TLabel").pack(side=tk.LEFT, padx=(18, 4))
        self.timeout_var = tk.StringVar(value="1.0")
        self.timeout_entry = ttk.Entry(r1_frame, textvariable=self.timeout_var, width=6, font=("Segoe UI", 9))
        self.timeout_entry.pack(side=tk.LEFT)

        # Row 2: Ports Input and Action Buttons
        r2_frame = ttk.Frame(config_frame, style="Card.TFrame")
        r2_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(r2_frame, text="Ports to Scan:", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 18))
        self.ports_var = tk.StringVar(value="80, 443, 8080, 3000, 3306, 3389, 22, 21")
        self.ports_entry = ttk.Entry(r2_frame, textvariable=self.ports_var, font=("Segoe UI", 9))
        self.ports_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.btn_scan = tk.Button(
            r2_frame,
            text="▶ Start Scan",
            bg=self.accent_blue,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief=tk.FLAT,
            command=self.start_scan,
        )
        self.btn_scan.pack(side=tk.LEFT, padx=3)

        self.btn_stop = tk.Button(
            r2_frame,
            text="⏹ Stop",
            bg=self.accent_red,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            relief=tk.FLAT,
            state=tk.DISABLED,
            command=self.stop_scan,
        )
        self.btn_stop.pack(side=tk.LEFT, padx=3)

        # Row 3: Quick Preset Buttons
        preset_frame = ttk.Frame(config_frame, style="Card.TFrame")
        preset_frame.pack(fill=tk.X)

        ttk.Label(preset_frame, text="Quick Presets:", style="Card.TLabel", font=("Segoe UI", 8, "italic")).pack(side=tk.LEFT, padx=(0, 8))
        for name, preset_val in PORT_PRESETS.items():
            btn = tk.Button(
                preset_frame,
                text=name,
                bg="#373748",
                fg="#e2e8f0",
                activebackground="#4a4a60",
                activeforeground="#ffffff",
                relief=tk.FLAT,
                font=("Segoe UI", 8),
                padx=6,
                pady=2,
                command=lambda val=preset_val: self.apply_preset(val),
            )
            btn.pack(side=tk.LEFT, padx=2)

        # 3. Search & Results Toolbar
        toolbar_frame = ttk.Frame(self.root, padding="15 4 15 4")
        toolbar_frame.pack(fill=tk.X)

        # Search box
        ttk.Label(toolbar_frame, text="🔎 Search / Filter:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_results())
        self.search_entry = ttk.Entry(toolbar_frame, textvariable=self.search_var, width=24, font=("Segoe UI", 9))
        self.search_entry.pack(side=tk.LEFT, padx=(0, 15))

        # Filter: Open Only
        self.open_only_var = tk.BooleanVar(value=False)
        self.open_only_cb = tk.Checkbutton(
            toolbar_frame,
            text="Show OPEN Only",
            variable=self.open_only_var,
            bg=self.bg_dark,
            fg=self.text_light,
            selectcolor="#2b2b36",
            activebackground=self.bg_dark,
            activeforeground="#ffffff",
            command=self.filter_results,
        )
        self.open_only_cb.pack(side=tk.LEFT, padx=(0, 15))

        # Counters display
        self.summary_label = ttk.Label(toolbar_frame, text="Ready to scan", font=("Segoe UI", 9))
        self.summary_label.pack(side=tk.LEFT, padx=10)

        # Export button
        self.btn_export = tk.Button(
            toolbar_frame,
            text="📥 Export CSV",
            bg="#2b2b36",
            fg="#e2e8f0",
            relief=tk.FLAT,
            font=("Segoe UI", 8),
            padx=8,
            pady=2,
            command=self.export_csv,
        )
        self.btn_export.pack(side=tk.RIGHT)

        # 4. Results Table (Treeview)
        table_container = ttk.Frame(self.root, padding="15 0 15 8")
        table_container.pack(fill=tk.BOTH, expand=True)

        columns = ("port", "protocol", "status", "service", "latency")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("port", text="Port #", command=lambda: self.sort_tree("port", False))
        self.tree.heading("protocol", text="Protocol", command=lambda: self.sort_tree("protocol", False))
        self.tree.heading("status", text="Status (Open / Close)", command=lambda: self.sort_tree("status", False))
        self.tree.heading("service", text="Common Service", command=lambda: self.sort_tree("service", False))
        self.tree.heading("latency", text="Latency (ms)", command=lambda: self.sort_tree("latency", False))

        self.tree.column("port", width=80, anchor=tk.CENTER)
        self.tree.column("protocol", width=80, anchor=tk.CENTER)
        self.tree.column("status", width=140, anchor=tk.CENTER)
        self.tree.column("service", width=220, anchor=tk.W)
        self.tree.column("latency", width=100, anchor=tk.CENTER)

        # Tree tags for status coloring
        self.tree.tag_configure("open", foreground="#10b981", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("closed", foreground="#ef4444")
        self.tree.tag_configure("neutral", foreground="#9ca3af")

        scrollbar = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 5. Bottom Progress and Status Bar
        bottom_frame = ttk.Frame(self.root, padding="15 4 15 10")
        bottom_frame.pack(fill=tk.X)

        self.progress_bar = ttk.Progressbar(bottom_frame, orient=tk.HORIZONTAL, mode="determinate")
        self.progress_bar.pack(fill=tk.X, pady=(0, 4))

        self.status_bar_lbl = ttk.Label(bottom_frame, text="Status: Idle", foreground=self.text_dim)
        self.status_bar_lbl.pack(side=tk.LEFT)

    def apply_preset(self, val: str):
        self.ports_var.set(val)

    def start_scan(self):
        if self.is_scanning:
            return

        host = self.host_var.get().strip()
        if not host:
            messagebox.showwarning("Input Missing", "Please enter a target host or IP address.")
            return

        ports_raw = self.ports_var.get().strip()
        ports = parse_port_input(ports_raw)
        if not ports:
            messagebox.showwarning("Invalid Ports", "Please enter valid ports (e.g., '80, 443' or '1-100').")
            return

        try:
            timeout = float(self.timeout_var.get().strip())
        except ValueError:
            timeout = 1.0

        protocol = self.proto_var.get()

        # Reset UI
        self.scan_results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.is_scanning = True
        self.stop_requested = False
        self.btn_scan.config(state=tk.DISABLED, bg="#4b5563")
        self.btn_stop.config(state=tk.NORMAL)
        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = len(ports) * (2 if protocol == "BOTH" else 1)
        self.status_bar_lbl.config(text=f"Scanning {host} ({len(ports)} ports, {protocol})...")
        self.summary_label.config(text="Scanning in progress...")

        # Start background scanning thread
        self.scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(host, ports, protocol, timeout),
            daemon=True,
        )
        self.scan_thread.start()

    def _run_scan_worker(self, host: str, ports: list, protocol: str, timeout: float):
        try:
            def on_progress(completed, total, result):
                if self.stop_requested:
                    return
                self.root.after(0, self._on_single_port_completed, completed, total, result)

            def is_stopped():
                return self.stop_requested

            scan_ports_parallel(
                host=host,
                ports=ports,
                protocol=protocol,
                max_workers=40,
                timeout=timeout,
                progress_callback=on_progress,
                stop_event=is_stopped,
            )

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
        finally:
            self.root.after(0, self._on_scan_finished)

    def _on_single_port_completed(self, completed: int, total: int, result: tuple):
        self.scan_results.append(result)
        self.progress_bar["value"] = completed
        self.status_bar_lbl.config(text=f"Scanning: {completed}/{total} ports checked")
        self._insert_result_in_tree(result)
        self._update_summary_counter()

    def _insert_result_in_tree(self, result: tuple):
        port, proto, status, service, latency = result

        # Check search and filter
        search_term = self.search_var.get().strip().lower()
        if self.open_only_var.get() and status != "OPEN":
            return

        if search_term:
            match = (
                search_term in str(port)
                or search_term in proto.lower()
                or search_term in status.lower()
                or search_term in service.lower()
            )
            if not match:
                return

        # Tag
        if status == "OPEN":
            tag = "open"
            status_text = "🟢 OPEN"
        else:
            tag = "closed"
            status_text = "🔴 CLOSED"

        self.tree.insert(
            "",
            tk.END,
            values=(port, proto, status_text, service, f"{latency:.1f}"),
            tags=(tag,),
        )

    def _update_summary_counter(self):
        total = len(self.scan_results)
        open_count = sum(1 for r in self.scan_results if r[2] == "OPEN")
        closed_count = total - open_count
        self.summary_label.config(
            text=f"Total: {total}  |  🟢 Open: {open_count}  |  🔴 Closed: {closed_count}"
        )

    def _on_scan_finished(self):
        self.is_scanning = False
        self.btn_scan.config(state=tk.NORMAL, bg=self.accent_blue)
        self.btn_stop.config(state=tk.DISABLED)
        total = len(self.scan_results)
        open_count = sum(1 for r in self.scan_results if r[2] == "OPEN")
        status_msg = "Scan stopped by user" if self.stop_requested else "Scan completed"
        self.status_bar_lbl.config(text=f"Status: {status_msg}. Found {open_count} open port(s).")
        self.filter_results()

    def stop_scan(self):
        if self.is_scanning:
            self.stop_requested = True
            self.status_bar_lbl.config(text="Stopping scan...")

    def filter_results(self):
        """Re-populates treeview based on current search term and open_only filter."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        search_term = self.search_var.get().strip().lower()
        open_only = self.open_only_var.get()

        for res in self.scan_results:
            port, proto, status, service, latency = res
            if open_only and status != "OPEN":
                continue

            if search_term:
                match = (
                    search_term in str(port)
                    or search_term in proto.lower()
                    or search_term in status.lower()
                    or search_term in service.lower()
                )
                if not match:
                    continue

            tag = "open" if status == "OPEN" else "closed"
            status_text = "🟢 OPEN" if status == "OPEN" else "🔴 CLOSED"

            self.tree.insert(
                "",
                tk.END,
                values=(port, proto, status_text, service, f"{latency:.1f}"),
                tags=(tag,),
            )
        self._update_summary_counter()

    def sort_tree(self, col: str, reverse: bool):
        """Sorts table by column."""
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0].replace("🟢", "").replace("🔴", "").strip()), reverse=reverse)
        except ValueError:
            items.sort(key=lambda t: t[0].lower(), reverse=reverse)

        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    def export_csv(self):
        if not self.scan_results:
            messagebox.showinfo("Export", "No results to export yet. Please run a scan first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Save Scan Results",
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Protocol", "Status", "Service", "Latency_ms"])
                for r in self.scan_results:
                    writer.writerow(r)
            messagebox.showinfo("Export Success", f"Scan results successfully exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
