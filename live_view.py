from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel,
    QCheckBox, QTabWidget, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QGroupBox, QGridLayout, QFrame, QProgressBar
)
import json
import sys
from datetime import datetime

class CategoryCard(QFrame):
    """Small rounded card showing a vulnerability category and its count.

    Emits:
        clicked(str): The category name when the card is clicked.
    """
    clicked = Signal(str)

    def __init__(self, name: str, count: int = 0, parent=None):
        """Create a card with the given name and starting count."""
        super().__init__(parent)
        self._name = name
        self._count = count
        self.setObjectName("CategoryCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 12)
        lay.setSpacing(4)
        self.title = QLabel()
        self.title.setAlignment(Qt.AlignCenter)
        self._refresh()
        lay.addWidget(self.title)
        self.setCursor(Qt.PointingHandCursor)

    def mouseReleaseEvent(self, e):
        """Forward clicks as a signal with the category name."""
        self.clicked.emit(self._name)
        return super().mouseReleaseEvent(e)

    def set_count(self, n: int):
        """Update the displayed count."""
        self._count = n
        self._refresh()

    def _refresh(self):
        """Refresh the text shown on the card."""
        self.title.setText(f"<b>{self._name}</b> ({self._count})")


class AnalysisLiveWidget(QWidget):
    """Live analysis view (status, logs, config/CLI, and vulnerability buckets).

    Left panel:
        - Status line, read-only status pill (Running/Paused/Complete), and a busy bar
          (indeterminate progress; hidden when analysis completes).
        - Tabs: **Logs** (table), **Config** (JSON pretty-print), **CLI** (plain text).
    Right panel:
        - Two grids of :class:`CategoryCard`: **Detected** and **Not Detected**.

    Signals:
        categoryClicked(str): Emitted when a category card is clicked.
    """
    _TITLE_PT = 12
    _GRID_COLS = 2
    _BUSY_HEIGHT = 6

    categoryClicked = Signal(str)

    def __init__(self, filename: str = "filename", parent=None):
        """Initialize the view for a given filename (display only)."""
        super().__init__(parent)
        self.filename = filename
        self._categories_detected = {}      
        self._categories_not_detected = {} 
        self._cards_det = {}
        self._cards_not = {}
        self._build_ui()
        self._apply_styles()

    #public API
    def set_running(self, running: bool):
        """Show the running/paused state (title, pill color/text, busy bar)."""
        self._set_state(
            title="Analyzing" if running else "Paused",
            pill_text="Running" if running else "Paused",
            pill_color="#2ecc71" if running else "#f39c12",
            busy=running,
        )

    def mark_complete(self, message: str = "Analysis complete."):
        """Mark the view as complete, hide the busy bar, and set a final message."""
        self.set_status_line(message)
        self._set_state(
            title="Complete",
            pill_text="Complete",
            pill_color="#95a5a6",
            busy=False,
        )

    def set_status_line(self, text: str):
        """Update the single-line status label at the top-left box."""
        self.status_line.setText(text)

    def set_config_preview(self, cfg: dict):
        """Pretty-print the configuration used for this run in the Config tab."""
        self.cfg_edit.setPlainText(json.dumps(cfg, indent=2))

    def append_cli_output(self, text: str):
        """Append one line of text to the CLI tab."""
        self.cli_edit.appendPlainText(text)

    def append_log(self, severity: str, message: str, ts: datetime | None = None, *, max_rows: int | None = 2000):
        """Append a row to the logs table, trimming oldest rows if `max_rows` is reached."""
        ts = ts or datetime.now()
        row = self.log_table.rowCount()
        if max_rows is not None and row >= max_rows:
            self.log_table.removeRow(0)
            row -= 1
        self.log_table.insertRow(row)
        self.log_table.setItem(row, 0, QTableWidgetItem(ts.strftime(self._time_fmt())))
        self.log_table.setItem(row, 1, QTableWidgetItem(f"[{severity.upper()}]"))
        self.log_table.setItem(row, 2, QTableWidgetItem(message))
        self.log_table.scrollToBottom()

    def bump_category(self, name: str, detected: bool = True, by: int = 1):
        """Increment a category counter and update/create its card incrementally."""
        store = self._categories_detected if detected else self._categories_not_detected
        cards = self._cards_det if detected else self._cards_not
        grid = self.detected_grid if detected else self.notdet_grid

        store[name] = store.get(name, 0) + by

        if name in cards:
            cards[name].set_count(store[name])
        else:
            # add a new card at next row/col
            r, c = divmod(len(cards), self._GRID_COLS)
            card = CategoryCard(name, store[name])
            card.clicked.connect(self.categoryClicked)
            grid.addWidget(card, r, c)
            cards[name] = card

        self.detected_box.setTitle(f"Vulnerabilities Detected ({sum(self._categories_detected.values())})")
        self.notdet_box.setTitle(f"Vulnerabilities Not Detected ({sum(self._categories_not_detected.values())})")

    def clear_categories(self):
        """Clear all category data and rebuild the grids (removes all cards)."""
        self._categories_detected.clear()
        self._categories_not_detected.clear()
        self._cards_det.clear()
        self._cards_not.clear()
        self._rebuild_category_grid()

    def set_categories(self, detected: dict | None = None, not_detected: dict | None = None):
        """Bulk-set category data and rebuild the grids (useful for initial load)."""
        if detected is not None:
            self._categories_detected = dict(detected)
        if not_detected is not None:
            self._categories_not_detected = dict(not_detected)
        self._rebuild_category_grid()

    #ui
    def _build_ui(self):
        """Create widgets and layout for both panels (left/right)."""
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 8, 10, 10)
        root.setSpacing(8)

        #top title
        self.status_header = QLabel()
        self.status_header.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(self._TITLE_PT)
        self.status_header.setFont(title_font)
        self._set_title("Analyzing")
        root.addWidget(self.status_header)

        #split left (status/logs) | right (vulns)
        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        #left side
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(8, 8, 8, 8)
        lv.setSpacing(10)

        #analysis Status box
        status_box = QGroupBox()
        sb = QVBoxLayout(status_box)
        sb.setContentsMargins(12, 12, 12, 12)

        #status text line
        self.status_line = QLabel("Analysis Status (runtime, states explored…)")
        self.status_line.setAlignment(Qt.AlignCenter)

        #centered status pill row
        pill_row = QHBoxLayout()
        pill_row.addStretch(1)
        self.status_pill = QLabel()
        self.status_pill.setObjectName("StatusPill")
        self._set_pill("Running", "#2ecc71")  # initial
        pill_row.addWidget(self.status_pill)
        pill_row.addStretch(1)

        #indeterminate busy bar
        self.busy = QProgressBar()
        self.busy.setRange(0, 0)   # indeterminate
        self.busy.setFixedHeight(self._BUSY_HEIGHT)

        sb.addWidget(self.status_line)
        sb.addLayout(pill_row)
        sb.addWidget(self.busy)
        lv.addWidget(status_box)

        #tabs (Logs / Config / CLI)
        self.tabs = QTabWidget()
        #logs tab
        logs = QWidget()
        ll = QVBoxLayout(logs)
        self.log_table = QTableWidget(0, 3)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Message"])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.setSelectionMode(QTableWidget.NoSelection)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ll.addWidget(self.log_table)
        self.tabs.addTab(logs, "Logs")

        #config tab
        cfg = QWidget()
        cl = QVBoxLayout(cfg)
        self.cfg_edit = QPlainTextEdit(readOnly=True)
        self.cfg_edit.setPlaceholderText("Configuration used for this run will appear here…")
        cl.addWidget(self.cfg_edit)
        self.tabs.addTab(cfg, "Config")

        # CLI tab
        cli = QWidget()
        cil = QVBoxLayout(cli)
        self.cli_edit = QPlainTextEdit(readOnly=True)
        self.cli_edit.setPlaceholderText("$ analysis-engine --args ...\n(streamed output)")
        cil.addWidget(self.cli_edit)
        self.tabs.addTab(cli, "CLI")

        lv.addWidget(self.tabs, 1)
        split.addWidget(left)

        #right side (vulnerabilities)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 8, 8, 8)
        rv.setSpacing(8)

        #detected section
        self.detected_box = QGroupBox("Vulnerabilities Detected (0)")
        db = QVBoxLayout(self.detected_box)
        self.detected_grid = QGridLayout()
        self.detected_grid.setHorizontalSpacing(10)
        self.detected_grid.setVerticalSpacing(10)
        db.addLayout(self.detected_grid)
        rv.addWidget(self.detected_box, 1)

        #not detected section
        self.notdet_box = QGroupBox("Vulnerabilities Not Detected (0)")
        nb = QVBoxLayout(self.notdet_box)
        self.notdet_grid = QGridLayout()
        self.notdet_grid.setHorizontalSpacing(10)
        self.notdet_grid.setVerticalSpacing(10)
        nb.addLayout(self.notdet_grid)
        rv.addWidget(self.notdet_box, 1)

        split.addWidget(right)
        split.setSizes([650, 500])

    def _apply_styles(self):
        self.setStyleSheet("""
            QGroupBox { border: 1px solid #BDBDBD; border-radius: 10px; padding: 10px; }
            #CategoryCard { border: 1px solid #9AA0A6; border-radius: 12px; background: #FFFFFF; }
            #CategoryCard:hover { background: #F5F7FF; }
            #StatusPill { border-radius: 12px; padding: 4px 14px; color: white; font-weight: 600; }
        """)

    #helpers
    def _set_pill(self, text: str, color: str):
        """Update the read-only status pill text and background color."""
        self.status_pill.setText(text)
        self.status_pill.setAlignment(Qt.AlignCenter)
        self.status_pill.setStyleSheet(
            f"#StatusPill {{ padding: 4px 14px; border-radius: 12px; "
            f"color: white; background: {color}; font-weight: 600; }}"
        )

    def _set_title(self, prefix: str):
        """Set the title above the split view (includes sanitized filename)."""
        self.status_header.setText(f"<b>{prefix} &lt;{self.filename}&gt;</b>")

    def _time_fmt(self) -> str:
        """Return a platform-appropriate timestamp format for the logs table."""
        return "%-I:%M:%S %p" if sys.platform != "win32" else "%I:%M:%S %p"

    def _clear_layout(self, layout):
        """Remove all widgets from a layout (preserving the layout instance)."""
        for i in reversed(range(layout.count())):
            w = layout.itemAt(i).widget()
            if w:
                w.setParent(None)

    def _set_state(self, *, title: str, pill_text: str, pill_color: str, busy: bool):
        """Atomically update title, pill, and busy bar visibility."""
        self._set_title(title)
        self._set_pill(pill_text, pill_color)
        self.busy.setVisible(busy)

    def _rebuild_category_grid(self):
        """Recreate both category grids from current data (bulk refresh)."""
        self._clear_layout(self.detected_grid)
        self._clear_layout(self.notdet_grid)
        self._cards_det.clear()
        self._cards_not.clear()

        #build cards
        def populate(grid, store, card_map):
            r = c = 0
            for name, cnt in sorted(store.items()):
                card = CategoryCard(name, cnt)
                card.clicked.connect(self.categoryClicked)
                grid.addWidget(card, r, c)
                c += 1
                if c == self._GRID_COLS: 
                    c = 0
                    r += 1

        populate(self.detected_grid, self._categories_detected, self._cards_det)
        populate(self.notdet_grid, self._categories_not_detected, self._cards_not)

        self.detected_box.setTitle(f"Vulnerabilities Detected ({sum(self._categories_detected.values())})")
        self.notdet_box.setTitle(f"Vulnerabilities Not Detected ({sum(self._categories_not_detected.values())})")

#quick run
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = AnalysisLiveWidget("sample.bin")
    w.set_running(True)
    w.set_config_preview({"arch": "ARM", "timeout_min": 30, "entrypoints": ["_start", "main"]})
    w.bump_category("Category 1", detected=True)
    w.bump_category("Category 2", detected=True, by=2)
    w.bump_category("Category X", detected=False)
    w.show()
    sys.exit(app.exec())  