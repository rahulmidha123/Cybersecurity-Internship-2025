import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import threading
import time
import psutil
from utils.process_scan import list_processes, find_suspicious_processes
from utils.keylogger_detect import start_keystroke_monitor
from utils.logger import log_suspicious
from PIL import Image, ImageTk

APP_ROOT = Path(__file__).resolve().parent

class AKDApp:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Keylogger Detector")
        root.geometry("900x600")
        root.resizable(False, False)

        # Top banner with generated image
        banner_path = APP_ROOT / 'assets' / 'bg_banner.png'
        img = Image.open(banner_path).resize((900,140))
        self.banner_img = ImageTk.PhotoImage(img)
        banner = ttk.Label(root, image=self.banner_img)
        banner.place(x=0, y=0)

        # Main frame
        main = ttk.Frame(root, padding=12)
        main.place(x=10, y=150, width=880, height=430)

        # Left: Processes list
        left = ttk.Frame(main)
        left.place(x=0, y=0, width=540, height=420)
        ttk.Label(left, text="Running Processes", font=(None, 12, 'bold')).pack(anchor='w')
        cols = ('pid','name','cpu','user')
        self.tree = ttk.Treeview(left, columns=cols, show='headings', height=18)
        for c in cols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=120)
        self.tree.pack(fill='both', expand=True, pady=(6,0))

        # Right: Controls & Suspects
        right = ttk.Frame(main)
        right.place(x=560, y=0, width=320, height=420)
        ttk.Label(right, text="Controls", font=(None, 12, 'bold')).pack(anchor='w')
        ttk.Button(right, text="Refresh Processes", command=self.refresh_processes).pack(fill='x', pady=6)
        ttk.Button(right, text="Run Quick Scan", command=self.run_quick_scan).pack(fill='x', pady=6)
        ttk.Button(right, text="Start Demo Keystroke Monitor", command=self.start_demo_keystroke).pack(fill='x', pady=6)
        ttk.Button(right, text="Open Logs", command=self.open_logs).pack(fill='x', pady=6)

        ttk.Label(right, text="Suspicious Processes", font=(None, 12, 'bold')).pack(anchor='w', pady=(12,0))
        self.suspect_box = tk.Listbox(right, height=10)
        self.suspect_box.pack(fill='both', expand=True, pady=(6,0))
        ttk.Button(right, text="Terminate Selected", command=self.terminate_selected).pack(fill='x', pady=6)

        # Status bar
        self.status_var = tk.StringVar(value='Ready')
        status = ttk.Label(root, textvariable=self.status_var, relief='sunken', anchor='w')
        status.place(x=0, y=580, width=900)

        # populate once
        self.refresh_processes()

    def refresh_processes(self):
        self.status_var.set('Refreshing process list...')
        for i in self.tree.get_children():
            self.tree.delete(i)
        try:
            procs = list_processes()
            for p in procs:
                self.tree.insert('', 'end', values=(p.get('pid'), p.get('name'), p.get('cpu_percent'), p.get('username')))
            self.status_var.set(f'Loaded {len(procs)} processes.')
        except Exception as e:
            self.status_var.set('Error refreshing processes.')
            messagebox.showerror('Error', str(e))

    def run_quick_scan(self):
        self.status_var.set('Running quick heuristic scan...')
        self.suspect_box.delete(0, 'end')
        def _scan():
            suspects = find_suspicious_processes()
            if not suspects:
                messagebox.showinfo('Scan Result', 'No suspicious processes found by heuristics.')
            else:
                for s in suspects:
                    display = f"PID:{s.get('pid')} | {s.get('name')} | score={s.get('score')}"
                    self.suspect_box.insert('end', display)
                    log_suspicious(f"Suspect found: {display}")
            self.status_var.set('Scan complete.')
        t = threading.Thread(target=_scan, daemon=True)
        t.start()

    def start_demo_keystroke(self):
        self.status_var.set('Starting demo keystroke monitor for 10 seconds...')
        start_keystroke_monitor(duration=10)
        messagebox.showinfo('Demo', 'Keystroke demo monitor started for 10 seconds. (Type to generate activity)')
        self.status_var.set('Demo monitor running...')

    def open_logs(self):
        logs = APP_ROOT / 'logs' / 'suspicious.log'
        if logs.exists():
            try:
                if os.name == 'nt':
                    os.startfile(str(logs))
                else:
                    import subprocess
                    subprocess.run(['xdg-open', str(logs)])
            except Exception as e:
                messagebox.showinfo('Logs path', str(logs))
        else:
            messagebox.showinfo('Logs', 'No logs yet.')

    def terminate_selected(self):
        sel = self.suspect_box.curselection()
        if not sel:
            messagebox.showwarning('Select', 'Please select a suspicious entry to terminate.')
            return
        entry = self.suspect_box.get(sel[0])
        try:
            pid = int(entry.split('|')[0].split(':')[1].strip())
        except:
            messagebox.showerror('Parse', 'Could not parse PID from entry.')
            return
        try:
            p = psutil.Process(pid)
            p.terminate()
            messagebox.showinfo('Terminated', f'Process {pid} terminated (requested).')
            log_suspicious(f'User requested termination of PID {pid}')
            self.run_quick_scan()
        except Exception as e:
            messagebox.showerror('Error', str(e))

if __name__ == '__main__':
    root = tk.Tk()
    style = ttk.Style(root)
    # Try to use a modern theme if available
    try:
        style.theme_use('clam')
    except:
        pass
    app = AKDApp(root)
    root.mainloop()
