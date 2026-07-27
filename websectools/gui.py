"""Tkinter GUI for Web-Security-Tools.

Worker threads never touch Tk directly — they push callables onto a queue the
main thread drains via ``after`` (the safe Tk + threads pattern).
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk

from . import clickjack, csp, disclosure, headers

BG, FG, ACC, ACC2 = "#0a0f0c", "#e6f5ee", "#00ff6a", "#26e0ff"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Web-Security-Tools")
        self.configure(bg=BG)
        self.geometry("780x560")
        self.ui_queue: queue.Queue = queue.Queue()
        self._build()
        self.after(80, self._drain)

    def _build(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=14, pady=(14, 6))
        tk.Label(top, text="⟩ web-security-tools", bg=BG, fg=ACC,
                 font=("Consolas", 18, "bold")).pack(side="left")

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=14, pady=4)
        tk.Label(row, text="target", bg=BG, fg=FG,
                 font=("Consolas", 11)).pack(side="left")
        self.target = tk.StringVar(value="example.com")
        tk.Entry(row, textvariable=self.target, width=46, bg="#0f1a14", fg=FG,
                 insertbackground=ACC, relief="flat").pack(side="left", padx=8)

        btns = tk.Frame(self, bg=BG)
        btns.pack(fill="x", padx=14, pady=6)
        for text, fn in [("Headers", self._headers), ("CSP", self._csp),
                         ("Clickjack", self._clickjack),
                         ("Disclosure", self._disclosure),
                         ("Full audit", self._audit)]:
            tk.Button(btns, text=text, command=fn, bg="#10231a", fg=ACC,
                      activebackground=ACC, activeforeground=BG, relief="flat",
                      font=("Consolas", 10, "bold"), padx=12, pady=6).pack(
                          side="left", padx=4)

        self.out = tk.Text(self, bg="#060d09", fg=FG, insertbackground=ACC,
                           relief="flat", font=("Consolas", 10), wrap="word")
        self.out.pack(fill="both", expand=True, padx=14, pady=(4, 14))
        self._log("Enter a target and pick a check. Authorized targets only.")

    # threading plumbing
    def _drain(self):
        try:
            while True:
                self.ui_queue.get_nowait()()
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _log(self, msg):
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def _post(self, msg):
        self.ui_queue.put(lambda: self._log(msg))

    def _bg(self, label, work):
        self._log(f"\n>>> {label} …")

        def run():
            try:
                for line in work():
                    self._post(line)
            except Exception as e:
                self._post(f"error: {e}")
            self._post("— done —")
        threading.Thread(target=run, daemon=True).start()

    # actions -> yield printable lines
    def _headers(self):
        t = self.target.get().strip()
        def w():
            r = headers.scan_url(t)
            if not r.get("reachable"):
                return [f"unreachable: {r.get('error')}"]
            return [f"grade {r['grade']} ({r['score']}/100)",
                    "present: " + (", ".join(r["present"]) or "none"),
                    "missing: " + (", ".join(r["missing"]) or "none")]
        self._bg("headers", w)

    def _csp(self):
        t = self.target.get().strip()
        def w():
            r = csp.scan_url(t)
            if not r.get("reachable"):
                return [f"unreachable: {r.get('error')}"]
            return [f"policy: {r['csp'] or '(none)'}"] + \
                   [f"[{s.upper()}] {m}" for s, m in r["findings"]]
        self._bg("csp", w)

    def _clickjack(self):
        t = self.target.get().strip()
        def w():
            r = clickjack.scan_url(t)
            if not r.get("reachable"):
                return [f"unreachable: {r.get('error')}"]
            m = r["methods"]
            return [f"X-Frame-Options: {r['x_frame_options'] or 'MISSING'}",
                    f"CSP frame-ancestors: {'yes' if r['csp_frame_ancestors'] else 'no'}",
                    "clickjacking: " + ("protected" if r["clickjacking_protected"] else "VULNERABLE"),
                    "methods: " + (", ".join(m["allow"]) or "unknown"),
                    ("risky: " + ", ".join(m["risky"])) if m["risky"] else "risky: none"]
        self._bg("clickjack", w)

    def _disclosure(self):
        t = self.target.get().strip()
        def w():
            r = disclosure.scan_url(t)
            return [("FOUND  " if x["found"] else "absent ") + x["path"]
                    for x in r["results"]]
        self._bg("disclosure", w)

    def _audit(self):
        self._headers()
        self._csp()
        self._clickjack()
        self._disclosure()


if __name__ == "__main__":
    App().mainloop()
