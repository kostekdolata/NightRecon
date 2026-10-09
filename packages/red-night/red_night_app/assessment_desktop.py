"""Professional Red Night desktop assessment workspace.

Presentation and planning only: deliberately never launches a scan.
Uses only the Python standard library Tkinter for Windows distribution.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from .assessment_preflight import plan_assessment, ENGINE_NAMES

ENGINES = (
    ("Nmap", "Network discovery and service identification", "Integration testing"),
    ("Nuclei", "Template-driven checks", "Evidence import only"),
    ("OWASP ZAP", "Web application assessment", "Evidence import only"),
    ("TShark", "Packet and protocol analysis", "Evidence import only"),
    ("Metasploit", "Authorised exploit validation", "Catalogue only"),
)
BG = "#0b0e13"
PANEL = "#151a22"
FG = "#e8edf4"
MUTED = "#a6b1bf"
RED = "#e65962"


class ScrollableFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.canvas = tk.Canvas(self, background=BG, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.horizontal = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.content = ttk.Frame(self.canvas)
        self.window = self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set, xscrollcommand=self.horizontal.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.horizontal.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.content.bind("<Configure>", lambda _e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(
            self.window, width=max(760, e.width)))
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _event):
        self.canvas.bind_all("<MouseWheel>", self._wheel)
        self.canvas.bind_all("<Button-4>", self._wheel)
        self.canvas.bind_all("<Button-5>", self._wheel)

    def _unbind_wheel(self, _event):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _wheel(self, event):
        direction = -1 if getattr(event, "num", None) == 4 else (
            1 if getattr(event, "num", None) == 5 else -int(event.delta / 120))
        self.canvas.yview_scroll(direction, "units")


def build_window(root: tk.Tk) -> None:
    root.title("Red Night | Assessment Operations")
    root.geometry("1200x820")
    root.resizable(True, True)
    root.configure(background=BG)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 11))
    style.configure("TCheckbutton", background=BG, foreground=FG, font=("Segoe UI", 11))
    style.configure("TRadiobutton", background=BG, foreground=FG, font=("Segoe UI", 11))
    style.configure("TEntry", fieldbackground=PANEL, foreground=FG)
    style.configure("TLabelframe", background=BG, foreground=FG)
    style.configure("TLabelframe.Label", background=BG, foreground=FG)
    style.configure("TButton", font=("Segoe UI", 10), padding=8)

    frame = ScrollableFrame(root)
    frame.pack(fill="both", expand=True)
    content = frame.content
    content.columnconfigure(0, weight=1)
    header = ttk.Frame(content)
    header.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 18))
    ttk.Label(header, text="RED NIGHT", foreground=RED,
              font=("Segoe UI", 20, "bold")).pack(anchor="w")
    ttk.Label(header, text="ASSESSMENT OPERATIONS  /  OPERATOR WORKSPACE",
              foreground=MUTED).pack(anchor="w", pady=(4, 0))
    ttk.Separator(content).grid(row=1, column=0, sticky="ew", padx=28)
    body = ttk.Frame(content)
    body.grid(row=2, column=0, sticky="nsew", padx=28, pady=20)
    body.columnconfigure(0, weight=1)

    ttk.Label(body, text="New assessment", font=("Segoe UI", 19, "bold")).grid(
        row=0, column=0, sticky="w")
    ttk.Label(body, text="Plan an authorised, evidence-driven engagement. Execution is not yet connected.",
              foreground=MUTED, wraplength=800).grid(row=1, column=0, sticky="w", pady=(6, 18))

    engagement = ttk.LabelFrame(body, text="Engagement & scope", padding=16)
    engagement.grid(row=2, column=0, sticky="ew", pady=(0, 15))
    engagement.columnconfigure(1, weight=1)
    ttk.Label(engagement, text="Engagement ID").grid(row=0, column=0, sticky="w", padx=(0, 15))
    engagement_id = tk.StringVar()
    ttk.Entry(engagement, textvariable=engagement_id).grid(row=0, column=1, sticky="ew")
    ttk.Label(engagement, text="Target allowlist").grid(row=1, column=0, sticky="nw", pady=12)
    targets = tk.Text(engagement, height=4, wrap="word", background=PANEL,
                      foreground=FG, insertbackground=FG, relief="flat")
    targets.grid(row=1, column=1, sticky="ew", pady=12)
    ttk.Label(engagement, text="Targets shown here are planning inputs only. No scope authorisation is inferred.",
              foreground=MUTED, wraplength=800).grid(row=2, column=0, columnspan=2, sticky="w")

    modes = ttk.LabelFrame(body, text="Assessment mode", padding=16)
    modes.grid(row=3, column=0, sticky="ew", pady=(0, 15))
    mode = tk.StringVar(value="all")
    ttk.Radiobutton(modes, text="Run All — eligible, approved engines only",
                    variable=mode, value="all").pack(anchor="w", pady=4)
    ttk.Radiobutton(modes, text="Custom — choose engines and execution sequence",
                    variable=mode, value="custom").pack(anchor="w", pady=4)
    ttk.Label(modes, text="Intrusive tests always require explicit approval. Run All cannot override scope or impact ceilings.",
              foreground=MUTED, wraplength=800).pack(anchor="w", pady=(12, 0))

    engine_box = ttk.LabelFrame(body, text="Engine selection and readiness", padding=16)
    engine_box.grid(row=4, column=0, sticky="ew", pady=(0, 15))
    engine_box.columnconfigure(0, weight=1)
    selected = []
    for index, (name, role, availability) in enumerate(ENGINES):
        line = ttk.Frame(engine_box)
        line.grid(row=index, column=0, sticky="ew", pady=6)
        line.columnconfigure(1, weight=1)
        option = tk.BooleanVar(value=(name == "Nmap"))
        selected.append(option)
        ttk.Checkbutton(line, text=name, variable=option).grid(row=0, column=0, sticky="w", padx=(0, 16))
        ttk.Label(line, text=role, foreground=MUTED).grid(row=0, column=1, sticky="w")
        ttk.Label(line, text=availability, foreground="#f1c483").grid(row=0, column=2, sticky="e", padx=(12, 0))
    ttk.Label(engine_box, text="Readiness labels describe current integration maturity, not detected installation status.",
              foreground=MUTED, wraplength=800).grid(row=len(ENGINES), column=0, sticky="w", pady=(14, 0))

    controls = ttk.LabelFrame(body, text="Execution control", padding=16)
    controls.grid(row=5, column=0, sticky="ew")
    ttk.Label(controls, text="Preflight • authorisation • operation budgets • approvals • audit trail",
              foreground=MUTED, wraplength=800).pack(anchor="w")
    def show_preflight():
        values = tuple(name for (name, _, _), flag in zip(ENGINES, selected)
                       if flag.get())
        preview = plan_assessment(
            engagement_id=engagement_id.get(),
            targets_text=targets.get("1.0", "end-1c"),
            mode=mode.get(), selected_engines=values)
        panel = tk.Toplevel(root)
        panel.title("Red Night | Assessment Preflight")
        panel.geometry("850x600")
        panel.resizable(True, True)
        panel.configure(background=BG)
        holder = ttk.Frame(panel)
        holder.pack(fill="both", expand=True, padx=12, pady=12)
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        details = tk.Text(holder, wrap="none", background=PANEL, foreground=FG,
                          insertbackground=FG, relief="flat")
        vertical = ttk.Scrollbar(holder, orient="vertical", command=details.yview)
        horizontal = ttk.Scrollbar(holder, orient="horizontal", command=details.xview)
        details.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        details.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        details.insert("1.0", preview.as_text())
        details.configure(state="disabled")
        ttk.Button(holder, text="Close", command=panel.destroy).grid(
            row=2, column=0, sticky="e", pady=8)

    ttk.Button(controls, text="Review assessment preflight",
               command=show_preflight).pack(anchor="w", pady=(12, 0))
    ttk.Button(controls, text="Start assessment (not connected)", state="disabled").pack(
        anchor="w", pady=(12, 0))
    ttk.Label(controls, text="No engine will run from this preview. Backend wiring and operator approvals must be verified first.",
              foreground="#f1c483", wraplength=800).pack(anchor="w", pady=(10, 0))

    root.bind("<Escape>", lambda _e: root.focus_set())


def main() -> None:
    root = tk.Tk()
    build_window(root)
    root.mainloop()


if __name__ == "__main__":
    main()
