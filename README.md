# BinLens

BinLens is a PySide6 desktop app for **configuring, running, and monitoring** binary analyses—built entirely in code (no Qt Designer). It gives you a smooth workflow from selecting entrypoints and library paths to watching live logs and vulnerability categories as the analysis progresses.

---

## Highlights

- **Modern, no-Designer UI** (PySide6)
- **Pre-run configuration**  
  Set ISA/timeout, add shared/static library search paths, pick entrypoints, and define advanced CLI arg patterns
- **Live analysis view**  
  Status pill (Running/Paused/Complete), busy bar that hides on completion, Logs/Config/CLI tabs, and vulnerability categories updating in real time
- **Separation of concerns**  
  Widgets emit signals; orchestration lives in a small host window—easy to integrate with your analysis engine

---

## Project Structure

.
├─ main.py                     # launcher for ConfigureAnalysisWindow
├─ BinLens_Dashboard.py        # dashboard + main window host
├─ configure_analysis.py       # multi-tab settings window
├─ live_view/
│  ├─ analysis_live_view.py    # AnalysisLiveWidget (live run view)
│  └─ __init__.py              # (optional) makes this a package
├─ docs/
│  └─ screenshots/
│     ├─ dashboard.png
│     ├─ configure.png
│     └─ live_view.png
├─ README.md                   # landing page (this file)
├─ LICENSE                     # MIT (or your chosen license)
├─ requirements.txt            # PySide6 etc.
├─ pyproject.toml              # tooling config (ruff, metadata) — optional but recommended
└─ .gitignore                  # ignore venv, build artifacts, __pycache__, etc.
