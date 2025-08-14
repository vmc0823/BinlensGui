import sys
from PySide6.QtWidgets import QApplication
from configure_analysis import ConfigureAnalysisWindow

def main(target_name="cwe_nightmare_x86"):
    app = QApplication(sys.argv)
    win = ConfigureAnalysisWindow(target_name)

    # Optional: handle Start outside the window
    def on_start_clicked():
        cfg = win.get_config()
        print("Starting analysis with:", cfg)
        # TODO: call your analysis engine here

    win.start_btn.clicked.connect(on_start_clicked)

    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="cwe_nightmare_x86",
                        help="Binary/project name to show in the header")
    args = parser.parse_args()
    main(args.target)