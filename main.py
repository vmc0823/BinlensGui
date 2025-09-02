"""Entry point for launching the Configure Analysis window.

This boots Qt application, creates a :class:`ConfigureAnalysisWindow`,
and wires the window's **Start** button to print the collected configuration.
Intended for local testing or as a thin launcher that hands config to your
analysis engine.

Usage:
    python main.py --target path/to/binary_or_project

Notes:
    - The ConfigureAnalysisWindow class is defined in `configure_analysis.py`.
"""

import sys
from PySide6.QtWidgets import QApplication
from configure_analysis import ConfigureAnalysisWindow

def main(target_name="cwe_nightmare_x86") -> None:
    """Launch a ConfigureAnalysisWindow for the given target.

    Args:
        target_name: Display name of the binary/project shown in the header.

    Side Effects:
        - Starts the Qt event loop (blocking).
        - Prints the configuration dictionary when **Start** is clicked.
    """
    app = QApplication(sys.argv)
    win = ConfigureAnalysisWindow(target_name)

    #handle start outside the window (optional)
    def on_start_clicked():
        cfg = win.get_config()
        print("Starting analysis with:", cfg)
        # TODO: call your analysis engine here

    win.start_btn.clicked.connect(on_start_clicked)

    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BinLens Configure Analysis launcher.")
    parser.add_argument("--target", default="cwe_nightmare_x86", help="Binary/project name to show in the header")
    args = parser.parse_args()
    main(args.target)