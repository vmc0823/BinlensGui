"""
It defines :class:`ConfigureAnalysisWindow`, a multi-tab window that lets
users configure analysis parameters before running the engine.
Tabs:
    - **General**: ISA/Architecture, analysis timeout (minutes).
    - **Shared Objects**: Library search paths for dynamic/static libs (.so/.dylib/.dll/.a/.lib).
    - **Entrypoints**: Candidate entry functions with checkboxes; includes 'Select All'
      and 'Select Default' helpers (e.g., `_start`, `main`, `DllMain`, ...).
    - **Advanced**: Max number of CLI arguments and user-defined argument patterns.

Public API:
    - :meth:`get_config` → dict with all settings.
    - :meth:`set_entrypoints`, :meth:`get_selected_entrypoints`
    - :meth:`set_shared_search_paths`, :meth:`get_shared_search_paths`

Notes:
    - This class is a QMainWindow to keep a consistent top-level frame

"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTabWidget, QFormLayout, QComboBox, QSpinBox,
    QPushButton, QFrame, QSizePolicy, QSpacerItem, QTableView, 
    QFileDialog, QListWidget, QListWidgetItem, QMessageBox, QHeaderView,
    QInputDialog, QAbstractItemView
)
from PySide6.QtGui import QStandardItemModel, QStandardItem

import os
import sys
from pathlib import Path
from typing import Iterable, List, Dict, Any

LIB_EXTS = {".so", ".dylib", ".dll", ".a", ".lib"} #dynamic + static libraries

class ConfigureAnalysisWindow(QMainWindow):
    """
    Args:
        target_name: Display name for the binary/project (shown in the header).
        entrypoints: Optional initial table rows:
            Each row is a dict with keys:
                - "address": str (e.g., "0x401000")
                - "function": str (e.g., "main")
                - "file": str (source module/binary)
                - "selected": bool (checkbox state)

    Attributes:
        tabs: The main QTabWidget.
        start_btn: The **Start** QPushButton; connect this in your controller.
        back_btn: The **Back** QPushButton; closes the window by default.
    """
    def __init__(self, target_name="cwe_nightmare_x86", entrypoints=None):
        super().__init__()
        self.setWindowTitle("Configure Analysis")
        self.setMinimumSize(840, 560)
        self._build_ui(target_name)
        self._apply_styles()

        self.set_entrypoints(entrypoints or [
            {"address": "0x401000", "function": "_start", "file": target_name, "selected": True},
            {"address": "0x401140", "function": "main",   "file": target_name, "selected": True},
            {"address": "0x402000", "function": "helper", "file": target_name, "selected": False},
        ])
        self.set_shared_search_paths(self._default_search_paths())
        self.max_args_spin.setValue(5)

    #ui
    """Builds all widgets and layouts"""
    def _build_ui(self, target_name: str) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(18)

        # Header 
        header_frame = QFrame(objectName="headerFrame")
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
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
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

        # Shared Objects tab
        so_tab = QWidget()
        so_layout = QVBoxLayout(so_tab)
        so_layout.setContentsMargins(24, 20, 24, 20)
        so_layout.setSpacing(10)
        desc = QLabel("Add one or more directories containing shared or static libraries required for accurate dynamic analysis.")
        desc.setWordWrap(True)
        so_layout.addWidget(desc)
        label_paths = QLabel("<b>Current Search Paths:</b>")
        so_layout.addWidget(label_paths)
        self.paths_list = QListWidget()
        self.paths_list.setSelectionMode(QListWidget.ExtendedSelection)
        self.paths_list.setMinimumHeight(200)
        so_layout.addWidget(self.paths_list, 1)
        
        # buttons row
        row = QHBoxLayout()
        add_btn = QPushButton("+ Add directory", objectName="pillButton")
        rem_btn = QPushButton("- Remove selected", objectName="pillButton")
        reset_btn = QPushButton("Reset to System Default", objectName="pillButton")
        add_btn.clicked.connect(self._on_add_directory)
        rem_btn.clicked.connect(self._on_remove_selected_paths)
        reset_btn.clicked.connect(lambda: self.set_shared_search_paths(self._default_search_paths()))
        row.addWidget(add_btn)
        row.addWidget(rem_btn)
        row.addWidget(reset_btn)
        row.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))
        so_layout.addLayout(row)
        self.tabs.addTab(so_tab, "Shared Objects")

        # entrypoints tab
        entry_tab = QWidget()
        entry_layout = QVBoxLayout(entry_tab); entry_layout.setContentsMargins(24, 20, 24, 20); entry_layout.setSpacing(14)
        btn_row = QHBoxLayout()
        btn_row.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))
        self.btn_select_all = QPushButton("Select All", objectName="pillButton")
        self.btn_select_default = QPushButton("Select Default", objectName="pillButton")
        self.btn_select_all.clicked.connect(lambda: self.select_all_entrypoints(True))
        self.btn_select_default.clicked.connect(self.select_default_entrypoints)
        btn_row.addWidget(self.btn_select_all); btn_row.addWidget(self.btn_select_default)
        entry_layout.addLayout(btn_row)
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

        #advanced tab
        adv_tab = QWidget()
        av = QVBoxLayout(adv_tab); av.setContentsMargins(24, 20, 24, 20); av.setSpacing(12)
        header = QLabel("<b>Command-Line Arguments</b>")
        av.addWidget(header)
        info = QLabel("ℹ️  Set the maximum number of arguments the program can accept.")
        info.setWordWrap(True)
        av.addWidget(info)
        row = QHBoxLayout()
        row.addWidget(QLabel("Max Number of Arguments:"))
        self.max_args_spin = QSpinBox()
        self.max_args_spin.setRange(0, 64)  # tweak as needed
        self.max_args_spin.setAlignment(Qt.AlignCenter)
        row.addWidget(self.max_args_spin, 0, Qt.AlignLeft)
        row.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))
        av.addLayout(row)
        av.addWidget(QLabel("Argument Patterns:"))
        self.arg_list = QListWidget()
        self.arg_list.setMinimumHeight(150)
        self.arg_list.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.SelectedClicked)  # allow inline edit
        av.addWidget(self.arg_list)
        add_arg_btn = QPushButton("+ Add Arg Pattern")
        add_arg_btn.clicked.connect(self._on_add_arg_pattern)
        av.addWidget(add_arg_btn, 0, Qt.AlignLeft)
        self.tabs.addTab(adv_tab, "Advanced")

        # Footer
        footer = QHBoxLayout()
        footer.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))
        self.back_btn = QPushButton("Back", objectName="secondaryButton"); self.back_btn.clicked.connect(self.on_back)
        self.start_btn = QPushButton("Start", objectName="primaryButton"); self.start_btn.setDefault(True); self.start_btn.clicked.connect(self.on_start)
        footer.addWidget(self.back_btn); footer.addWidget(self.start_btn)
        root.addLayout(footer)


    # Styles
    def _apply_styles(self) -> None:
        """Applies a light stylesheet to keep the window consistent with your mockups."""
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

    #shared objects logic
    def _on_add_directory(self) -> None:
        """Open a directory chooser and append valid library paths to the list.

        Behavior:
            - Allows selecting multiple directories (non-native dialog).
            - Warns if a directory appears to contain no typical library files,
              but still allows adding by user choice.
              """
        dlg = QFileDialog(self, "Add library directory")
        dlg.setFileMode(QFileDialog.Directory)
        dlg.setOption(QFileDialog.ShowDirsOnly, True)
        dlg.setOption(QFileDialog.DontUseNativeDialog, True)  # allows multi-select
        if dlg.exec():
            dirs = [Path(p) for p in dlg.selectedFiles()]
            to_add = []
            for d in dirs:
                if not d.exists():
                    continue
                if not self._dir_contains_libs(d):
                    # Warn but still allow adding (some users keep symlinked trees)
                    ans = QMessageBox.question(
                        self, "No libraries detected",
                        f"'{d}' does not appear to contain typical library files ({', '.join(sorted(LIB_EXTS))}).\nAdd anyway?",
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                    )
                    if ans != QMessageBox.Yes:
                        continue
                to_add.append(str(d))
            self._append_unique_paths(to_add)


    def _dir_contains_libs(self, directory: Path) -> bool:
        """Heuristic: return True if any child file has an extension in LIB_EXTS."""
        try:
            for child in directory.iterdir():
                if child.is_file() and child.suffix.lower() in LIB_EXTS:
                    return True
        except Exception:
            pass
        return False
    
    def _append_unique_paths(self, paths: Iterable[str]) -> None:
        """Append normalized paths to the list widget, skipping duplicates."""
        current = set(self.get_shared_search_paths())
        for p in paths:
            norm = os.path.normpath(p)
            if norm in current:
                continue
            item = QListWidgetItem(norm)
            self.paths_list.addItem(item)
            current.add(norm) 

    def _on_remove_selected_paths(self) -> None:
        """Remove all currently selected items from the search path list."""
        for item in self.paths_list.selectedItems():
            row = self.paths_list.row(item)
            self.paths_list.takeItem(row)

    def _default_search_paths(self) -> List[str]:
        """Return a cleaned, de-duplicated list of common system library paths.

        Notes:
            - Uses platform-specific environment variables (`LD_LIBRARY_PATH`,
              `DYLD_LIBRARY_PATH`, `PATH`) when available.
            - Filters out non-existing directories.
        """
        paths: List[str] = []
        if sys.platform.startswith("linux"):
            paths += ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64"]
            paths += os.environ.get("LD_LIBRARY_PATH", "").split(":")
        elif sys.platform == "darwin":
            paths += ["/usr/lib", "/usr/local/lib", "/opt/homebrew/lib", "/opt/local/lib"]
            paths += os.environ.get("DYLD_LIBRARY_PATH", "").split(":")
        elif sys.platform.startswith("win"):
            sysroot = os.environ.get("SystemRoot", r"C:\Windows")
            paths += [os.path.join(sysroot, "System32"), os.path.join(sysroot, "SysWOW64")]
            paths += os.environ.get("PATH", "").split(";")
        # dedupe & existing only
        cleaned = []
        seen = set()
        for p in paths:
            if not p:
                continue
            n = os.path.normpath(p)
            if n in seen or not os.path.exists(n):
                continue
            seen.add(n); cleaned.append(n)
        return cleaned

    def set_shared_search_paths(self, paths: Iterable[str]) -> None:
        """Replace the current library search path list with `paths`."""
        self.paths_list.clear()
        self._append_unique_paths(paths)

    def get_shared_search_paths(self) -> List[str]:
        """Return the list of library search paths currently configured."""
        return [self.paths_list.item(i).text() for i in range(self.paths_list.count())]


    def set_entrypoints(self, rows: Iterable[Dict[str, Any]]) -> None:
        """Populate the entrypoint table.

        Args:
            rows: Iterable of dicts with keys (address, function, file, selected).

        Behavior:
            - Creates a checkable first column for selection.
            - Makes data cells non-editable to avoid accidental edits.
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
            for it in (addr, func, src): it.setEditable(False)
            self.entry_model.appendRow([chk, addr, func, src])

    def _on_header_clicked(self, section: int) -> None:
        """Header click handler to toggle all checkboxes when first column is clicked."""
        if section != 0:
            return
        any_unchecked = any(
            self.entry_model.item(row, 0).checkState() != Qt.Checked
            for row in range(self.entry_model.rowCount())
        )
        self.select_all_entrypoints(any_unchecked)

    def select_all_entrypoints(self, checked: bool) -> None:
        """Set all entrypoint checkboxes to the given state."""
        state = Qt.Checked if checked else Qt.Unchecked
        for row in range(self.entry_model.rowCount()):
            self.entry_model.item(row, 0).setCheckState(state)

    def select_default_entrypoints(self) -> None:
        """Select common entrypoints (e.g., `_start`, `main`, `DllMain`)."""
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

    def get_selected_entrypoints(self) -> List[Dict[str, str]]:
        """Return a list of selected entrypoints as dicts.

        Returns:
            List of dicts with keys: address, function, file.
        """
        out: List[Dict[str, str]] = []
        for row in range(self.entry_model.rowCount()):
            if self.entry_model.item(row, 0).checkState() == Qt.Checked:
                out.append({
                    "address":  self.entry_model.item(row, 1).text(),
                    "function": self.entry_model.item(row, 2).text(),
                    "file":     self.entry_model.item(row, 3).text(),
                })
        return out
    
    def _on_add_arg_pattern(self) -> None:
        """Prompt for a new argument pattern and append it to the list."""
        text, ok = QInputDialog.getText(
            self, "Add Argument Pattern",
            "Pattern (e.g. -i {file} --count {int}):"
        )
        if ok and text.strip():
            self.arg_list.addItem(text.strip())

    def get_arg_patterns(self) -> List[str]:
        """Return all user-specified CLI argument patterns."""
        return [self.arg_list.item(i).text() for i in range(self.arg_list.count())]

    # Behavior
    def on_back(self) -> None:
        """Default handler for the **Back** button (closes the window)."""
        print("[Back] returning to previous screen…")
        self.close()

    def on_start(self) -> None:
        """Default handler for the **Start** button (prints config to stdout).

        Notes:
            - In production, connect `start_btn.clicked` to a controller slot that
              reads `get_config()` and kicks off the analysis engine.
        """
        config = self.get_config()
        print("[Start] configuration:", config)

    def get_config(self) -> Dict[str, Any]:
        """Collect all currently configured options across tabs.

        Returns:
            Dict with keys:
                - "architecture": str
                - "timeout_minutes": int
                - "active_tab": str
                - "entrypoints": list[dict]
                - "lib_search_paths": list[str]
                - "max_cli_args": int
                - "arg_patterns": list[str]
        """
        return {
            "architecture": self.arch_combo.currentText(),
            "timeout_minutes": self.timeout_spin.value(),
            "active_tab": self.tabs.tabText(self.tabs.currentIndex()),
            "entrypoints": self.get_selected_entrypoints(),
            "lib_search_paths": self.get_shared_search_paths(),
            "max_cli_args": self.max_args_spin.value(),   
            "arg_patterns": self.get_arg_patterns(),
        }