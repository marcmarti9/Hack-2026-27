"""Logotipo de Vigía e iconos de navegación del escritorio."""
from pathlib import Path

from PySide6.QtCore import QElapsedTimer, QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QWidget

BRAND = Path(__file__).with_name("brand")


class Mark(QWidget):
    def __init__(self, width: int, icon: bool = False, *, dark: bool = False):
        super().__init__()
        self.renderer = QSvgRenderer(self)
        self.icon = icon
        self.set_theme(dark)
        self.setFixedSize(width, width if icon else round(width * 207 / 768))
        self.setAccessibleName("Vigía")
        self.opening = 1.0

    def set_theme(self, dark):
        kind = "icon" if self.icon else "logo"
        variant = "dark" if dark else "light"
        self.renderer.load(str(BRAND / f"vigia_{kind}_{variant}.svg"))
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bounds = QRectF(self.rect())
        if self.opening >= 1:
            self.renderer.render(painter, bounds)
            return
        split = bounds.width() * 0.736
        painter.save()
        painter.setClipRect(QRectF(0, 0, split, bounds.height()))
        self.renderer.render(painter, bounds)
        painter.restore()
        painter.setClipRect(QRectF(split, 0, bounds.width() - split, bounds.height()))
        center = bounds.height() * .56
        painter.translate(0, center)
        painter.scale(1, self.opening)
        painter.translate(0, -center)
        self.renderer.render(painter, bounds)


class OpeningMark(Mark):
    def __init__(self, reduced_motion: bool, *, dark: bool = False):
        super().__init__(340, dark=dark)
        self.reduced_motion = reduced_motion
        self.clock = QElapsedTimer()
        self.timer = QTimer(self, interval=32)
        self.timer.timeout.connect(self._advance)
        self.complete = False

    def begin(self):
        self.complete = False
        self.opening = 1 if self.reduced_motion else 0.045
        self.clock.start()
        if not self.reduced_motion:
            self.timer.start()
        self.update()

    def finish(self):
        self.complete = True
        self.timer.stop()
        self.opening = 1
        self.update()

    def _advance(self):
        self.opening = min(.94, .045 + .89 * (1 - 2 ** (-self.clock.elapsed() / 480)))
        self.update()

    def hideEvent(self, event):
        self.timer.stop()
        super().hideEvent(event)


_NAV_PATHS = {
    "menu": "M3 4h14v12H3z M8 4v12",
    "alerts": "M3 9l7-6 7 6v8H5V9 M8 17v-5h4v5",
    "statistics": "M3 17h14 M6 14v-4 M10 14V5 M14 14V8",
    "report": "M5 3h7l3 3v11H5z M12 3v4h3 M8 10h4 M8 13h4",
    "tickets": "M3 5h14v3a2 2 0 0 0 0 4v3H3v-3a2 2 0 0 0 0-4z M10 8v4",
    "history": "M5 5a7 7 0 1 1-2 6 M3 3v4h4 M10 6v5l3 2",
    "guides": "M10 6c-2-2-4-2-7-2v11c3 0 5 0 7 2 2-2 4-2 7-2V4c-3 0-5 0-7 2z M10 6v11",
    "notices": "M5 14h10l-1-2V8a4 4 0 0 0-8 0v4z M8 17h4",
    "backup": "M3 7h14v10H3z M3 7l3-4h8l3 4 M7 12h6",
    "profile": "M10 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M4 17v-1c0-2 2-4 6-4s6 2 6 4v1",
}


def navigation_icon(name: str, dark: bool = False) -> QIcon:
    stroke = "#b0c1d0" if dark else "#405467"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
        <path d="{_NAV_PATHS[name]}" fill="none" stroke="{stroke}" stroke-width="1.45"
        stroke-linecap="round" stroke-linejoin="round"/>
    </svg>"""
    pixmap = QPixmap(40, 40)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer = QSvgRenderer(svg.encode())
    renderer.render(painter, QRectF(0, 0, 20, 20))
    painter.end()
    return QIcon(pixmap)
