"""Controles compartidos de la mesa de Vigía."""
from html import escape
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPlainTextEdit, QPushButton, QTextBrowser


# Mesa de trabajo de Vigía. El azul del logotipo marca las acciones principales.
INK = "#202b36"
MUTED = "#536272"
PAPER = "#f7f8fa"
RAIL = "#f0f2f5"
PANEL = "#ffffff"
HOVER = "#eef2f6"
RULE = "#d8dfe6"
SELECTION = "#e1ebf4"
ACCENT = "#173e5c"
ACCENT_HOVER = "#245475"
FOCUS = "#326b9a"
WARNING = "#79521c"
POSITIVE = "#2d644b"
CHEVRON = (Path(__file__).with_name("brand") / "chevron-down.svg").as_posix()

STYLE = f"""
QMainWindow, QDialog, QWidget {{ background: {PAPER}; color: {INK}; font-size: 13px; }}
QLabel {{ background: transparent; }}
QToolTip {{ background: {HOVER}; color: {INK}; border: 1px solid {RULE}; }}
#title {{ font-size: 26px; font-weight: 700; }}
#sectionTitle {{ font-size: 17px; font-weight: 700; }}
#muted {{ color: {MUTED}; }}
#notice {{ color: {WARNING}; }}
#accentText {{ color: {ACCENT}; font-weight: 700; }}
#rail {{ background: {RAIL}; border-right: 1px solid {RULE}; }}
#navItem {{ background: {RAIL}; border-color: transparent; text-align: left; min-height: 22px; }}
#navItem:hover {{ background: {HOVER}; }}
#navItem:checked {{ background: {SELECTION}; color: {ACCENT}; font-weight: 700; }}
#navItem[compact="true"] {{ padding: 7px; text-align: center; }}
#navItem:focus, #menuToggle:focus {{ border-color: {FOCUS}; }}
#menuToggle {{ background: transparent; border-color: transparent; padding: 4px; }}
#menuToggle:hover {{ background: {HOVER}; }}
#workspaceHeader {{ background: {PANEL}; }}
#mainCanvas {{ background: {PAPER}; }}
#workspaceHeader, #queueFooter {{ border-bottom: 1px solid {RULE}; }}
#queueFooter {{ border-top: 1px solid {RULE}; border-bottom: 0; }}
#chatPanel {{ background: {PANEL}; }}
#chatPanel QPlainTextEdit {{ background: {PANEL}; }}
#authSurface {{ background: {PANEL}; border: 1px solid {RULE}; border-radius: 8px; }}
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QDateEdit {{
    background: {PANEL}; border: 1px solid {RULE}; border-radius: 4px;
    padding: 7px; selection-background-color: {SELECTION}; selection-color: {INK};
}}
#authSurface QLineEdit {{ min-height: 27px; }}
QComboBox, QDateEdit {{ padding-right: 21px; }}
QComboBox::drop-down, QDateEdit::drop-down {{
    subcontrol-origin: padding; subcontrol-position: top right; width: 19px; border: 0;
}}
QComboBox::down-arrow, QDateEdit::down-arrow {{ image: url("{CHEVRON}"); width: 12px; height: 12px; }}
QComboBox QAbstractItemView {{ background: {PANEL}; selection-background-color: {SELECTION}; selection-color: {INK}; }}
QTableWidget {{ background: {PANEL};
    border: 1px solid {RULE}; gridline-color: {RULE}; selection-background-color: {SELECTION};
    selection-color: {INK}; }}
QTableWidget::item {{ padding: 4px 8px; border-bottom: 1px solid {RULE}; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus, QTableWidget:focus,
QPushButton:focus, QComboBox:focus, QDateEdit:focus {{ border: 1px solid {FOCUS}; }}
QPushButton {{ background: {PANEL}; padding: 7px 10px; border: 1px solid {RULE}; border-radius: 4px; }}
QPushButton:hover {{ background: {HOVER}; }}
QPushButton:pressed, QPushButton:checked {{ background: {SELECTION}; color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; background: {PAPER}; }}
QPushButton#primary {{ background: {ACCENT}; color: {PANEL}; border-color: {ACCENT}; font-weight: 700; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {INK}; }}
QPushButton#primary:focus {{ border-color: {FOCUS}; }}
QPushButton#primary:disabled {{ background: {PANEL}; color: {MUTED}; border-color: {RULE}; }}
#rowAction {{ padding: 4px 9px; color: {ACCENT}; background: {PANEL}; }}
#rowAction:hover {{ background: {HOVER}; color: {ACCENT}; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 9px 8px;
    border: 0; border-bottom: 1px solid {RULE}; font-weight: 600; }}
QSplitter::handle {{ background: {RULE}; width: 4px; }}
QSplitter::handle:hover {{ background: {FOCUS}; }}
QMenu {{ background: {PANEL}; border: 1px solid {RULE}; padding: 4px; }}
QMenu::item {{ padding: 7px 14px; }}
QMenu::item:selected {{ background: {SELECTION}; }}
QTabWidget::pane {{ border: 0; border-top: 1px solid {RULE}; }}
QTabBar::tab {{ color: {MUTED}; padding: 9px 12px; border: 1px solid transparent; border-bottom-width: 2px; }}
QTabBar::tab:hover {{ background: {HOVER}; color: {INK}; }}
QTabBar::tab:selected {{ color: {INK}; border-bottom-color: {ACCENT}; font-weight: 700; }}
QTabBar::tab:focus {{ border-top-color: {ACCENT}; }}
QScrollBar:vertical {{ background: {PAPER}; width: 10px; margin: 0; }}
QScrollBar:horizontal {{ background: {PAPER}; height: 10px; margin: 0; }}
QScrollBar::handle {{ background: {RULE}; border-radius: 4px; min-height: 26px; min-width: 26px; }}
QScrollBar::handle:hover {{ background: {MUTED}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QProgressBar {{ background: {PANEL}; border: 1px solid {RULE}; border-radius: 3px; }}
QProgressBar::chunk {{ background: {ACCENT}; }}
QSlider::groove:horizontal {{ height: 4px; background: {RULE}; }}
QSlider::handle:horizontal {{ background: {ACCENT}; width: 14px; margin: -5px 0; border-radius: 7px; }}
#caseFacts {{ background: {PANEL}; border-top: 1px solid {RULE}; border-bottom: 1px solid {RULE}; }}
#factLabel {{ color: {MUTED}; font-size: 12px; }}
#factValue {{ font-size: 17px; font-weight: 700; }}
#caseReading, #reviewProcess {{ background: {PAPER}; border: 1px solid transparent; padding: 0; }}
#caseReading:focus, #reviewProcess:focus {{ border-color: {ACCENT}; }}
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
        widget.setAccessibleDescription(tip)
    return widget


def set_primary(widget: QPushButton, primary: bool):
    name = "primary" if primary else ""
    if widget.objectName() != name:
        widget.setObjectName(name)
        widget.style().unpolish(widget)
        widget.style().polish(widget)


def text_area(name: str) -> QPlainTextEdit:
    widget = QPlainTextEdit()
    widget.setAccessibleName(name)
    widget.setReadOnly(True)
    return widget


class Article(QTextBrowser):
    """Lectura con secciones y texto seleccionable, incluidas salidas no confiables."""

    def __init__(self, name: str):
        super().__init__()
        self.setObjectName("caseReading")
        self.setAccessibleName(name)
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.document().setDocumentMargin(14)

    def show_sections(self, sections):
        blocks = []
        for heading, copy in sections:
            if not copy:
                continue
            paragraphs = escape(copy).split("\n\n")
            body = "".join("<p>" + paragraph.replace("\n", "<br>") + "</p>" for paragraph in paragraphs)
            blocks.append(f"<h2>{escape(heading)}</h2>{body}")
        self.setHtml(f"""
            <style>
              body {{ color: {INK}; font-size: 14px; }}
              h2 {{ color: {INK}; font-size: 16px; margin-top: 18px; margin-bottom: 5px; }}
              p {{ margin-top: 0; margin-bottom: 9px; line-height: 145%; }}
            </style>
            {"".join(blocks)}
        """)
