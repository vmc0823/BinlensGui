from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTabWidget, QFormLayout, QComboBox, QSpinBox,
    QPushButton, QFrame, QSizePolicy, QSpacerItem, QTableView
)
from PySide6.QtGui import QStandardItemModel, QStandardItem
from PySide6.QtWidgets import QHeaderView

class ConfigureAnalysisWindow(QMainWindow):
    def __init__(self, target_name="cwe_nightmare_x86", entrypoints=None):
        super().__init__()
        self.setWindowTitle("Configure Analysis")
        self.setMinimumSize(840, 560)
        self._build_ui(target_name)
        self._apply_styles()
        if entrypoints:
            self.set_entrypoints(entrypoints)
        else:
            # rows you can remove
            self.set_entrypoints([
                {"address": "0x401000", "function": "_start", "file": target_name, "selected": True},
                {"address": "0x401140", "function": "main",   "file": target_name, "selected": True},
                {"address": "0x402000", "function": "helper", "file": target_name, "selected": False},
            ])

    #ui
    def _build_ui(self, target_name: str):
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(18)

        # Header (rounded box with the title)
        header_frame = QFrame()
        header_frame.setObjectName("headerFrame")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(16, 12, 16, 12)
        header = QLabel(f"Configure Analysis on <{target_name}>")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setWeight(QFont.DemiBold)
        header.setFont(header_font)
        header_layout.addWidget(header)
        root.addWidget(header_frame)

        # Tabs
        self.tabs = QTabWidget(documentMode=True)
        root.addWidget(self.tabs, 1)

        # General tab
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
        general_layout.setContentsMargins(24, 20, 24, 20)
        form = QFormLayout()
        form.setHorizontalSpacing(24); form.setVerticalSpacing(24)

        self.arch_combo = QComboBox()
        self.arch_combo.addItems([
            "x86", "x86_64", "ARM", "AArch64", "MIPS", "RISC-V"
        ])
        self.arch_combo.setCurrentText("ARM")

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 240)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setAlignment(Qt.AlignCenter)

        form.addRow(QLabel("Instruction Set Architecture:"), self.arch_combo)
        form.addRow(QLabel("Analysis Timeout (Minutes):"), self.timeout_spin)

        general_layout.addLayout(form)
        general_layout.addStretch(1)
        self.tabs.addTab(general_tab, "General")

        # Shared Objects tab (placeholder content)
        so_tab = QWidget()
        so_layout = QVBoxLayout(so_tab)
        so_layout.setContentsMargins(24, 20, 24, 20)
        so_layout.addWidget(QLabel("Add your shared object configuration here."))
        so_layout.addStretch(1)
        self.tabs.addTab(so_tab, "Shared Objects")

        # Wiring up entrypoints tab
        entry_tab = QWidget()
        entry_layout = QVBoxLayout(entry_tab)
        entry_layout.setContentsMargins(24, 20, 24, 20)
        entry_layout.setSpacing(14)

        # buttons row
        btn_row = QHBoxLayout()
        btn_row.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))
        self.btn_select_all = QPushButton("Select All")
        self.btn_select_default = QPushButton("Select Default")
        self.btn_select_all.setObjectName("pillButton")
        self.btn_select_default.setObjectName("pillButton")
        btn_row.addWidget(self.btn_select_all)
        btn_row.addWidget(self.btn_select_default)
        entry_layout.addLayout(btn_row)

        # table
        self.entry_table = QTableView()
        self.entry_table.setAlternatingRowColors(True)
        self.entry_table.setSelectionBehavior(QTableView.SelectRows)
        self.entry_table.setEditTriggers(QTableView.NoEditTriggers)

        self.entry_model = QStandardItemModel(0, 4, self)
        self.entry_model.setHorizontalHeaderLabels(["", "Address", "Function", "File"])
        self.entry_table.setModel(self.entry_model)

        header = self.entry_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.sectionClicked.connect(self._on_header_clicked)

        entry_layout.addWidget(self.entry_table, 1)
        self.tabs.addTab(entry_tab, "Entrypoints")

        # wire buttons
        self.btn_select_all.clicked.connect(lambda: self.select_all_entrypoints(True))
        self.btn_select_default.clicked.connect(self.select_default_entrypoints)

        # Footer buttons
        footer = QHBoxLayout()
        footer.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.back_btn = QPushButton("Back")
        self.back_btn.setObjectName("secondaryButton")
        self.back_btn.clicked.connect(self.on_back)

        self.start_btn = QPushButton("Start")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setDefault(True)
        self.start_btn.clicked.connect(self.on_start)

        footer.addWidget(self.back_btn)
        footer.addWidget(self.start_btn)
        root.addLayout(footer)

    # Styles
    def _apply_styles(self):
        self.setStyleSheet("""
            #headerFrame {
                background: white;
                border: 2px solid #BDBDBD;
                border-radius: 12px;
            }

            QTabWidget::pane {
                border: 1px solid #D0D0D0;
                border-top: none;
                border-radius: 8px;
                background: white;
            }
            QTabBar::tab {
                background: #F4F6F8;
                border: 1px solid #D0D0D0;
                border-bottom: none;
                padding: 10px 18px;
                margin-right: 6px;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: white;
            }

            QLabel {
                font-size: 14px;
            }

            QComboBox, QSpinBox {
                min-height: 36px;
                padding: 4px 8px;
                border: 1px solid #C7CAD1;
                border-radius: 8px;
                background: #FFFFFF;
            }

            QPushButton#primaryButton { 
                min-width: 120px; 
                min-height: 44px; 
                padding: 8px 18px; 
                border-radius: 22px;
                background: #0A84FF; 
                color: white; 
                font-weight: 700; 
                border: none; }
            QPushButton#secondaryButton { 
                min-width: 120px; 
                min-height: 44px; 
                padding: 8px 18px; 
                border-radius: 22px;
                background: white; 
                color: #0A84FF; 
                font-weight: 700; 
                border: 2px solid #0A84FF; 
                margin-right: 8px; }
            QPushButton#pillButton { 
                min-width: 140px; 
                min-height: 38px; 
                padding: 6px 16px; 
                border-radius: 19px;
                background: white; 
                border: 2px solid #BDBDBD; 
                font-weight: 600; }
            QTableView { border: 2px solid #2C2C2C; 
                border-radius: 6px; 
                gridline-color: #2C2C2C; }
        """)

    def set_entrypoints(self, rows):
        """
        rows: list of dicts with keys: address(str), function(str), file(str), selected(bool)
        """
        self.entry_model.removeRows(0, self.entry_model.rowCount())
        for r in rows:
            chk = QStandardItem()
            chk.setCheckable(True)
            chk.setEditable(False)
            chk.setCheckState(Qt.Checked if r.get("selected") else Qt.Unchecked)

            addr = QStandardItem(r.get("address", ""))
            func = QStandardItem(r.get("function", ""))
            src  = QStandardItem(r.get("file", ""))

            # Make data non-editable but selectable
            for it in (addr, func, src):
                it.setEditable(False)

            self.entry_model.appendRow([chk, addr, func, src])

    def _on_header_clicked(self, section):
        if section != 0:
            return
        # Toggle all checkboxes when first header clicked
        any_unchecked = any(
            self.entry_model.item(row, 0).checkState() != Qt.Checked
            for row in range(self.entry_model.rowCount())
        )
        self.select_all_entrypoints(any_unchecked)

    def select_all_entrypoints(self, checked: bool):
        state = Qt.Checked if checked else Qt.Unchecked
        for row in range(self.entry_model.rowCount()):
            self.entry_model.item(row, 0).setCheckState(state)

    def select_default_entrypoints(self):
        defaults = {"_start", "main", "WinMain", "wWinMain", "DllMain"}
        any_hit = False
        for row in range(self.entry_model.rowCount()):
            func = self.entry_model.item(row, 2).text()
            if func in defaults:
                self.entry_model.item(row, 0).setCheckState(Qt.Checked)
                any_hit = True
            else:
                self.entry_model.item(row, 0).setCheckState(Qt.Unchecked)
        # If none matched, select first row as a sane fallback
        if not any_hit and self.entry_model.rowCount() > 0:
            self.entry_model.item(0, 0).setCheckState(Qt.Checked)

    def get_selected_entrypoints(self):
        out = []
        for row in range(self.entry_model.rowCount()):
            if self.entry_model.item(row, 0).checkState() == Qt.Checked:
                out.append({
                    "address":  self.entry_model.item(row, 1).text(),
                    "function": self.entry_model.item(row, 2).text(),
                    "file":     self.entry_model.item(row, 3).text(),
                })
        return out

    # Behavior
    def on_back(self):
        print("[Back] returning to previous screen…")
        self.close()

    def on_start(self):
        config = self.get_config()
        print("[Start] configuration:", config)

    def get_config(self) -> dict:
        return {
            "architecture": self.arch_combo.currentText(),
            "timeout_minutes": self.timeout_spin.value(),
            "active_tab": self.tabs.tabText(self.tabs.currentIndex()),
            "entrypoints": self.get_selected_entrypoints()
        }

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    w = ConfigureAnalysisWindow("cwe_nightmare_x86")
    w.show()
    sys.exit(app.exec())