from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QMainWindow, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget,
    QPushButton, QLabel, QGroupBox, QTabWidget, QTextEdit, QFileDialog,
    QApplication, QSizePolicy, QFrame
)

from configure_analysis import ConfigureAnalysisWindow

class BinLensDashboard(QWidget):
    openFileRequested = Signal()
    analyzeRequested  = Signal()
    settingsRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._apply_styles()

    #helpers (public)
    def set_functions(self, names: list[str]):
        self.functions.clear()
        if not names:
            self.functions.addItem("No functions to display.")
            self.functions.setEnabled(False)
        else:
            self.functions.setEnabled(True)
            self.functions.addItems(names)

    def append_log(self, line: str):
        self.log_text.append(line)

    def set_status(self, text: str):
        self.status_text.setText(text)

    def set_results_widget(self, widget: QWidget):
        # Swap results view
        for i in reversed(range(self.results_box_layout.count())):
            old = self.results_box_layout.itemAt(i).widget()
            if old:
                old.setParent(None)
        self.results_box_layout.addWidget(widget)

    #ui
    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)

        splitter = QSplitter(Qt.Horizontal)
        root.addWidget(splitter)

        sidebar = QWidget()
        sbl = QVBoxLayout(sidebar)
        sbl.setContentsMargins(25, 25, 25, 25)
        self.btn_open = QPushButton("Open File")
        self.btn_analyze = QPushButton("Analyze")
        self.btn_settings = QPushButton("Settings")

        for b in (self.btn_open, self.btn_analyze, self.btn_settings):
            b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            sbl.addWidget(b)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        sbl.addWidget(line)

        fn_title = QLabel("FUNCTIONS")
        fn_title.setAlignment(Qt.AlignCenter)
        sbl.addWidget(fn_title)

        self.functions = QListWidget()
        self.functions.setToolTip("Open a file to explore its functions.")
        self.set_functions([])  
        sbl.addWidget(self.functions, 1)

        splitter.addWidget(sidebar)

        #center status/logs
        center = QWidget()
        cl = QVBoxLayout(center)
        cl.setContentsMargins(25, 25, 25, 25)
        self.welcome_box = QGroupBox()
        self.welcome_box.setTitle("")  # clean look like your mock
        wb = QVBoxLayout(self.welcome_box)
        title = QLabel("WELCOME TO BINLENS")
        tf = QFont()
        tf.setPointSize(14)
        tf.setBold(True)
        title.setFont(tf)
        subtitle = QLabel("Load a binary to get started.")
        subtitle.setAlignment(Qt.AlignCenter)
        title.setAlignment(Qt.AlignCenter)
        wb.addWidget(title)
        wb.addWidget(self._hline())
        wb.addWidget(subtitle, 1)
        cl.addWidget(self.welcome_box)

        self.bottom_tabs = QTabWidget()
        #status tab
        status_page = QWidget()
        sp = QVBoxLayout(status_page)
        self.status_text = QLabel("[INFO] Waiting…")
        self.status_text.setWordWrap(True)
        sp.addWidget(self.status_text, 1)
        self.bottom_tabs.addTab(status_page, "Status")
        #logs tab
        logs_page = QWidget()
        lp = QVBoxLayout(logs_page)
        self.log_text = QTextEdit(readOnly=True)
        self.log_text.setPlaceholderText("[INFO] Analysis Started")
        lp.addWidget(self.log_text)
        self.bottom_tabs.addTab(logs_page, "Logs")
        # Placeholder third tab
        self.bottom_tabs.addTab(QWidget(), "…")

        cl.addWidget(self.bottom_tabs, 1)
        splitter.addWidget(center)

        #analysis results
        results = QGroupBox("Analysis Results")
        self.results_box_layout = QVBoxLayout(results)
        self.results_box_layout.addWidget(QLabel("No results yet."))
        splitter.addWidget(results)

        splitter.setSizes([220, 520, 380])  

        #signals out
        self.btn_open.clicked.connect(self.openFileRequested.emit)
        self.btn_analyze.clicked.connect(self.analyzeRequested.emit)
        self.btn_settings.clicked.connect(self.settingsRequested.emit)

    def _hline(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Plain)
        return line

    def _apply_styles(self):
        self.setStyleSheet("""
            QListWidget { border: 1px solid #C9C9C9; border-radius: 6px; }
            QGroupBox { border: 1px solid #BDBDBD; border-radius: 10px; padding: 8px 8px 12px 8px; }
            QPushButton {
                padding: 8px 12px; border-radius: 8px; border: 1px solid #2C2C2C;
                background: #FFFFFF;
            }
            QPushButton:hover { background: #F5F7FF; }
            QTabWidget::pane { border: 1px solid #BDBDBD; border-radius: 8px; }
            QTabBar::tab { padding: 8px 16px; border: 1px solid #BDBDBD; border-bottom: none;
                           background: #F4F6F8; margin-right: 6px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
            QTabBar::tab:selected { background: #1976D2; color: white; }
        """)

class BinLensMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BinLens")
        self.resize(1150, 720)
        self.dashboard = BinLensDashboard()
        self.setCentralWidget(self.dashboard)

        #state
        self._current_file: str | None = None
        self._settings_dlg: ConfigureAnalysisWindow | None = None

        #actions (wired)
        self.dashboard.openFileRequested.connect(self._on_open_file)
        self.dashboard.analyzeRequested.connect(self._on_analyze)
        self.dashboard.settingsRequested.connect(self._on_open_settings)

        #ui (initial)
        self.dashboard.set_status("[INFO] Ready. Open a file to begin.")
        self.dashboard.append_log("[INFO] Analysis UI initialized.")

    #handlers
    def _on_open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open binary", "", "All files (*)")
        if not path:
            return
        self._current_file = path
        self.setWindowTitle(f"BinLens — {path}")
        self.dashboard.append_log(f"[INFO] Opened file: {path}")

        # TODO: populate with real discovery
        demo_functions = ["_start", "main", "helper", "validate", "encrypt_block"]
        self.dashboard.set_functions(demo_functions)

    def _on_analyze(self):
        self.dashboard.bottom_tabs.setCurrentIndex(1)  # show Logs
        self.dashboard.append_log("[INFO] Analysis started…")
        self.dashboard.set_status("Running symbolic explorer…")
        # TODO: start analysis thread/pipeline and stream logs back

    def _on_open_settings(self):
        #reuse an existing modeless dialog or create a new one
        if self._settings_dlg and not self._settings_dlg.isHidden():
            self._settings_dlg.raise_()
            self._settings_dlg.activateWindow()
            return

        target_name = self._current_file if self._current_file else "selected_binary"
        dlg = ConfigureAnalysisWindow(target_name=target_name)
        dlg.setParent(self, Qt.Window)                 
        dlg.setAttribute(Qt.WA_DeleteOnClose, True)     
        dlg.start_btn.clicked.connect(
            lambda: self.dashboard.append_log(f"[INFO] Settings: {dlg.get_config()}")
        )
        dlg.show()
        self._settings_dlg = dlg

#quick run
if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    w = BinLensMainWindow()
    w.show()
    sys.exit(app.exec())
