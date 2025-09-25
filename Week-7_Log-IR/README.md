# Advanced Keylogger Detector (AKD)

**Description**
Advanced Keylogger Detector is a Python-based desktop utility that monitors running processes,
checks for suspicious behavior commonly associated with keyloggers (heuristic checks),
monitors clipboard access, and provides a friendly GUI to alert users and optionally terminate
suspicious processes.

**What's included**
- `main.py` - Launches the attractive Tkinter GUI and ties everything together.
- `utils/process_scan.py` - Scans running processes using psutil and flags suspicious ones.
- `utils/keylogger_detect.py` - Heuristic checks to detect likely keylogger behavior.
- `utils/logger.py` - Handles logging suspicious events to `logs/suspicious.log`.
- `assets/` - Contains a generated background image used by the GUI.
- `requirements.txt` - Python dependencies.
- `README.md` - This file.

**How to run**
1. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate   # on Windows use: venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Run the app:
   ```bash
   python main.py
   ```

**Notes & Safety**
- This project uses heuristic detection — it *simulates* keystroke-hook detection for educational/demonstration use.
- Do NOT use this tool for malicious purposes.
- Tested on Windows and Linux (requires `psutil` and `pynput` for full functionality).

