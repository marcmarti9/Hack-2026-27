"""Identidad de Vigía y animaciones decorativas del escritorio."""
from pathlib import Path
from random import Random

from PySide6.QtCore import QElapsedTimer, QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QWidget

BRAND = Path(__file__).with_name("brand")


class Mark(QWidget):
    def __init__(self, width: int, icon: bool = False):
        super().__init__()
        self.renderer = QSvgRenderer(str(BRAND / ("vigia_icon_dark.svg" if icon else "vigia_logo_dark.svg")))
        self.setFixedSize(width, width if icon else round(width * 207 / 768))
        self.setAccessibleName("Vigía")
        self.opening = 1.0

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
    def __init__(self, reduced_motion: bool):
        super().__init__(340)
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


class MatrixPanel(QWidget):
    def __init__(self, reduced_motion: bool):
        super().__init__()
        self.setMinimumWidth(270)
        rng = Random(41)
        self.columns = [(rng.randrange(95), rng.uniform(.19, .54), rng.randrange(100)) for _ in range(56)]
        self.frame = 0
        self.timer = QTimer(self, interval=90)
        self.timer.timeout.connect(self._advance)
        if not reduced_motion:
            self.timer.start()

    def _advance(self):
        self.frame = (self.frame + 1) % 10000
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor("#081812"))
        font = QFont("monospace", 11)
        font.setStyleHint(QFont.StyleHint.Monospace)
        p.setFont(font)
        chars = "01△∷⟐A9E"
        rows = self.height() // 21 + 12
        for col, (offset, speed, seed) in enumerate(self.columns):
            x = 9 + col * 22
            if x > self.width():
                break
            head = int(offset + self.frame * speed) % rows
            for tail in range(11):
                y = ((head - tail) % rows) * 21 - 120
                if 0 < y <= self.height():
                    p.setPen(QColor(101, 192, 125, max(8, 86 - tail * 7)))
                    p.drawText(x, y, chars[(seed + head + tail * 11) % len(chars)])
        shade = QLinearGradient(0, 0, 0, self.height())
        shade.setColorAt(0, QColor(5, 17, 12, 40))
        shade.setColorAt(.49, QColor(5, 17, 12, 218))
        shade.setColorAt(1, QColor(5, 17, 12, 90))
        p.fillRect(self.rect(), shade)
