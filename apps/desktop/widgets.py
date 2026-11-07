"""Controles compartidos de la mesa de Vigía."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPlainTextEdit, QPushButton


STYLE = """
QMainWindow, QDialog, QWidget { background: #101723; color: #e6edf7; font-size: 13px; }
QToolTip { background: #243348; color: #eef4fc; border: 1px solid #41536b; }
#title { font-size: 29px; font-weight: 700; }
#sectionTitle { font-size: 19px; font-weight: 650; }
#muted { color: #a7b8ce; }
#notice { color: #ffcb98; }
#accentText { color: #a9df7a; font-weight: 700; }
#rail { background: #121d2a; border-right: 1px solid #29374c; }
#surface, #chatPanel { background: #151f2e; border: 1px solid #2b394e; border-radius: 9px; }
#loginSide { background: #0d1714; }
#authSurface { background: #121e1b; border: 1px solid #2f4c3e; border-radius: 15px; }
#authSurface QLabel, #chatPanel QLabel { background: transparent; }
#matrixTitle { background: transparent; color: #f0faed; font-size: 46px; font-weight: 700; }
#matrixCopy { background: transparent; color: #c6ddce; font-size: 15px; }
QLineEdit, QPlainTextEdit, QComboBox, QDateEdit {
    background: #101a29; border: 1px solid #34465e; border-radius: 5px;
    padding: 7px; selection-background-color: #355876;
}
#authSurface QLineEdit { background: #0c1613; border-color: #3a5949; min-height: 27px; }
QTableWidget { background: #152031; alternate-background-color: #192538;
    border: 1px solid #2b394e; border-radius: 7px; gridline-color: #243349;
    selection-background-color: #2e445b; }
QTableWidget::item { padding: 3px 6px; }
QLineEdit:focus, QPlainTextEdit:focus, QTableWidget:focus, QPushButton:focus,
QComboBox:focus, QDateEdit:focus { border: 1px solid #a2dc72; }
QPushButton { background: #202d40; padding: 7px 10px; border: 1px solid #354760; border-radius: 5px; }
QPushButton:hover { background: #293b51; }
QPushButton:checked { background: #274536; color: #c1eea3; border-color: #4a7053; }
QPushButton:disabled { color: #8392a5; background: #1a2534; }
QPushButton#primary { background: #a1d66c; color: #142319; border-color: #b6e189; font-weight: 700; }
QPushButton#primary:hover { background: #b4e584; }
QPushButton#primary:disabled { background: #2e4335; color: #a5b6a8; border-color: #395141; }
#rowAction { padding: 4px 5px; }
QHeaderView::section { background: #1c2a3d; color: #afc3dc; padding: 8px 6px; border: 0; }
QSplitter::handle { background: #26354a; }
QMenu { background: #1b293c; border: 1px solid #3b4e67; padding: 4px; }
QMenu::item { padding: 7px 14px; }
QMenu::item:selected { background: #344d68; }
"""


def label(text: str, role: str = "") -> QLabel:
    widget = QLabel()
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setText(text)
    widget.setWordWrap(True)
    if role:
        widget.setObjectName(role)
    return widget


def button(text, callback=None, *, primary=False, tip=""):
    widget = QPushButton(text)
    if callback:
        widget.clicked.connect(callback)
    if primary:
        widget.setObjectName("primary")
    if tip:
        widget.setToolTip(tip)
        widget.setAccessibleName(tip)
    return widget


def text_area(name: str) -> QPlainTextEdit:
    widget = QPlainTextEdit()
    widget.setAccessibleName(name)
    widget.setReadOnly(True)
    return widget
