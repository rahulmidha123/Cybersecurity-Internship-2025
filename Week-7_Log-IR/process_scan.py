import psutil
import time

SUSPICIOUS_KEYWORDS = ['key', 'logger', 'log', 'clip', 'spy', 'monitor', 'capture', 'hook']

def list_processes():
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'username']):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs

def heuristic_flag_process(proc_info):
    name = (proc_info.get('name') or '').lower()
    exe = (proc_info.get('exe') or '') .lower()
    cpu = proc_info.get('cpu_percent') or 0

    score = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in name or kw in exe:
            score += 2
    # unusually high CPU for small processes can be suspicious
    if cpu and cpu > 30:
        score += 1
    return score

def find_suspicious_processes(threshold=2):
    suspects = []
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'username']):
        try:
            info = p.info
            score = heuristic_flag_process(info)
            if score >= threshold:
                info['score'] = score
                suspects.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspects
