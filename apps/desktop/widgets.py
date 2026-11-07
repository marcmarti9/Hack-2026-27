"""Controles compartidos de la mesa de Vigía."""
from html import escape
from pathlib import Path

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QVariantAnimation
from PySide6.QtGui import QPainter, QPalette
from PySide6.QtWidgets import QGraphicsOpacityEffect, QLabel, QPlainTextEdit, QPushButton, QTextBrowser


# Paletas del escritorio. El color de los estados de triaje se aplica en la mesa.
LIGHT = {
    "INK": "#202b36", "MUTED": "#536272", "PAPER": "#f7f8fa", "RAIL": "#edf0f4",
    "PANEL": "#ffffff", "HOVER": "#eef2f6", "RULE": "#d8dfe6", "SELECTION": "#e1ebf4",
    "ACCENT": "#173e5c", "ACCENT_HOVER": "#245475", "FOCUS": "#326b9a",
    "WARNING": "#79521c", "POSITIVE": "#2d644b", "ON_ACCENT": "#ffffff",
}
DARK = {
    "INK": "#e8edf2", "MUTED": "#a7b4c0", "PAPER": "#151c24", "RAIL": "#10171f",
    "PANEL": "#1d2732", "HOVER": "#283645", "RULE": "#344455", "SELECTION": "#2d4256",
    "ACCENT": "#a9c3d9", "ACCENT_HOVER": "#c1d4e4", "FOCUS": "#88afd0",
    "WARNING": "#e3bd83", "POSITIVE": "#9dc9b4", "ON_ACCENT": "#172331",
}
BRAND_DIR = Path(__file__).with_name("brand")


def palette_for(dark):
    return DARK if dark else LIGHT


def stylesheet(dark):
    chevron = "chevron-down-dark.svg" if dark else "chevron-down.svg"
    return STYLE.format(**palette_for(dark), CHEVRON=(BRAND_DIR / chevron).as_posix())


STYLE = """
QMainWindow, QDialog, QWidget {{ background: {PAPER}; color: {INK}; font-size: 14px; }}
QLabel {{ background: transparent; }}
QToolTip {{ background: {HOVER}; color: {INK}; border: 1px solid {RULE}; }}
#title {{ font-size: 30px; font-weight: 700; }}
#sectionTitle {{ font-size: 18px; font-weight: 700; }}
#muted {{ color: {MUTED}; }}
#notice {{ color: {WARNING}; }}
#accentText {{ color: {ACCENT}; font-weight: 700; }}
#rail {{ background: {RAIL}; border-right: 1px solid {RULE}; }}
#navItem {{ background: {RAIL}; border-color: transparent; text-align: left; min-height: 25px; }}
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
#backupDivider {{ border-top: 1px solid {RULE}; }}
#queueRowActions {{ background: transparent; }}
#chatPanel {{ background: {PANEL}; }}
#chatPanel QPlainTextEdit {{ background: {PANEL}; }}
#chatTool {{ padding: 9px 7px; }}
#authSurface {{ background: {PANEL}; border: 1px solid {RULE}; border-radius: 12px; }}
#backupPanel, #statsPanel, #reportPanel {{ background: {PANEL}; border: 1px solid {RULE}; border-radius: 8px; }}
#backupPanel QLabel, #statsPanel QLabel, #reportPanel QLabel {{ background: transparent; }}
#metricValue {{ font-size: 26px; font-weight: 700; }}
QScrollArea {{ border: 0; }}
QListWidget {{ background: {PANEL}; border: 1px solid {RULE}; border-radius: 6px; }}
QListWidget::item {{ min-height: 29px; padding: 2px 8px; }}
QListWidget::item:selected {{ background: {SELECTION}; color: {INK}; }}
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QDateEdit, QSpinBox {{
    background: {PANEL}; border: 1px solid {RULE}; border-radius: 4px;
    padding: 9px; selection-background-color: {SELECTION}; selection-color: {INK};
}}
QLineEdit, QPlainTextEdit {{ placeholder-text-color: {MUTED}; }}
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
QTableWidget::item {{ padding: 6px 12px; border-bottom: 1px solid {RULE}; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus, QTableWidget:focus,
QPushButton:focus, QComboBox:focus, QDateEdit:focus, QSpinBox:focus,
QListWidget:focus {{ border: 1px solid {FOCUS}; }}
QPushButton {{ background: {PANEL}; padding: 9px 13px; border: 1px solid {RULE}; border-radius: 6px; }}
QPushButton:hover {{ background: {HOVER}; }}
QPushButton:pressed, QPushButton:checked {{ background: {SELECTION}; color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; background: {PAPER}; }}
QPushButton#primary {{ background: {ACCENT}; color: {ON_ACCENT}; border-color: {ACCENT}; font-weight: 700; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:focus {{ border-color: {FOCUS}; }}
QPushButton#primary:disabled {{ background: {PANEL}; color: {MUTED}; border-color: {RULE}; }}
#rowAction {{ padding: 6px 7px; color: {ACCENT}; background: transparent; border-color: transparent; }}
#rowAction:hover {{ background: {HOVER}; color: {ACCENT}; }}
#rowAction:focus {{ border-color: {FOCUS}; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 13px; height: 13px; background: {PANEL}; border: 1px solid {MUTED}; border-radius: 3px; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border: 2px solid {PANEL}; }}
QCheckBox::indicator:hover, QCheckBox::indicator:focus {{ border-color: {FOCUS}; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 10px 12px;
    border: 0; border-bottom: 1px solid {RULE}; font-weight: 600; }}
QSplitter::handle {{ background: {RULE}; width: 4px; }}
QSplitter::handle:hover {{ background: {FOCUS}; }}
QMenu {{ background: {PANEL}; border: 1px solid {RULE}; padding: 4px; }}
QMenu::item {{ padding: 7px 14px; }}
QMenu::item:selected {{ background: {SELECTION}; }}
QTabWidget::pane {{ border: 0; border-top: 1px solid {RULE}; }}
QTabBar::tab {{ color: {MUTED}; padding: 11px 14px; border: 1px solid transparent; border-bottom-width: 2px; }}
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


def motion_enabled(widget):
    while widget is not None:
        preference = getattr(widget, "reduced_motion", None)
        if preference is not None:
            return not (preference() if callable(preference) else preference)
        widget = widget.parentWidget()
    return True


def fade_in(widget):
    if widget is None or not widget.isVisible() or not motion_enabled(widget):
        return
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.72)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", effect)
    animation.setDuration(155)
    animation.setStartValue(0.72)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.finished.connect(lambda: widget.setGraphicsEffect(None))
    animation.start()


class MotionButton(QPushButton):
    def __init__(self, text):
        super().__init__(text)
        self._overlay = 0.0
        self._transition = None
        self.pressed.connect(lambda: self._tint(0.11))
        self.released.connect(lambda: self._tint(0.05 if self.underMouse() else 0.0))

    def _tint(self, target):
        if not motion_enabled(self) or not self.isEnabled():
            if self._transition:
                self._transition.stop()
            self._set_overlay(0.0)
            return
        if self._transition is None:
            self._transition = QVariantAnimation(self)
            self._transition.setDuration(135)
            self._transition.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._transition.valueChanged.connect(self._set_overlay)
        self._transition.stop()
        self._transition.setStartValue(self._overlay)
        self._transition.setEndValue(target)
        self._transition.start()

    def _set_overlay(self, value):
        self._overlay = value
        self.update()

    def enterEvent(self, event):
        super().enterEvent(event)
        self._tint(0.05)

    def leaveEvent(self, event):
        super().leaveEvent(event)
        self._tint(0.0)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._overlay and self.isEnabled() and motion_enabled(self):
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            color = self.palette().color(QPalette.ColorRole.ButtonText)
            color.setAlphaF(self._overlay)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 5, 5)



def label(text: str, role: str = "") -> QLabel:
    widget = QLabel()
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setText(text)
    widget.setWordWrap(True)
    if role:
        widget.setObjectName(role)
    return widget


def button(text, callback=None, *, primary=False, tip=""):
    widget = MotionButton(text)
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
        self.document().setDocumentMargin(18)

    def show_sections(self, sections):
        blocks = []
        for heading, copy in sections:
            if not copy:
                continue
            paragraphs = escape(copy).split("\n\n")
            body = "".join("<p>" + paragraph.replace("\n", "<br>") + "</p>" for paragraph in paragraphs)
            blocks.append(f"<h2>{escape(heading)}</h2>{body}")
        ink = self.palette().color(QPalette.ColorRole.Text).name()
        self.setHtml(f"""
            <style>
              body {{ color: {ink}; font-size: 14px; }}
              h2 {{ color: {ink}; font-size: 17px; margin-top: 23px; margin-bottom: 8px; }}
              p {{ margin-top: 0; margin-bottom: 12px; line-height: 145%; }}
            </style>
            {"".join(blocks)}
        """)
