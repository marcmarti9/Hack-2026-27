"""Sesión y carga del índice de Vigía."""
from pathlib import Path

from PySide6.QtCore import QElapsedTimer, QObject, QRunnable, QSettings, QThreadPool, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QFontDatabase, QIcon, QPainter
from PySide6.QtWidgets import (
    QFileDialog, QFormLayout, QFrame, QLineEdit, QMainWindow, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from apps.backend.config import DATA, DB
from apps.backend.ingest import ingest
from apps.backend.tools import db
from apps.desktop.brand_widgets import BRAND, Mark, OpeningMark
from apps.desktop.demo import DEMO_ALERT, DEMO_PASSWORD, DEMO_USER
from apps.desktop.review import Reviews
from apps.desktop.session import Account
from apps.desktop.widgets import button, label, palette_for, stylesheet
from apps.desktop.workbench import PAGE_SIZE, Workbench


class JobSignals(QObject):
    done = Signal(object, object)


class Job(QRunnable):
    def __init__(self, operation):
        super().__init__()
        self.operation = operation
        self.signals = JobSignals()

    def run(self):
        try:
            result = self.operation()
        except Exception as error:
            self.signals.done.emit(None, error)
        else:
            self.signals.done.emit(result, None)


class LoginCanvas(QWidget):
    """Trama de caracteres tenue; el formulario queda en primer plano."""

    def __init__(self, window):
        super().__init__()
        self.window = window
        self.clock = QElapsedTimer()
        self.timer = QTimer(self, interval=90)
        self.timer.timeout.connect(self.update)
        self.glyph_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.glyph_font.setPixelSize(13)

    def showEvent(self, event):
        super().showEvent(event)
        if not self.window.reduced_motion():
            self.clock.start()
            self.timer.start()

    def hideEvent(self, event):
        self.timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setFont(self.glyph_font)
        color = QColor(palette_for(self.window.dark)["ACCENT"])
        alphabet = "0123456789ABCDEF:·"
        elapsed = self.clock.elapsed() if self.timer.isActive() else 0
        for column, x in enumerate(range(26, self.width() - 20, 38)):
            if abs(x - self.width() / 2) < 232 or column % 7 == 2:
                continue
            stride = 16
            length = 4 + column * 7 % 8
            span = self.height() + length * stride
            head = (column * 119 + elapsed * (6 + column % 5) // 1000) % span
            for i in range(length):
                y = head - i * stride
                if 0 < y < self.height():
                    color.setAlphaF(0.045 + 0.105 * (1 - i / length))
                    painter.setPen(color)
                    painter.drawText(x, y, alphabet[(column * 13 + (head // stride - i) * 7) % len(alphabet)])


class Window(QMainWindow):
    def __init__(self, home: Path, *, demo: bool = False, present: bool = False):
        super().__init__()
        self.demo = demo
        self.present = demo and present
        self.account = Account(home)
        if demo and not self.account.name():
            self.account.create(DEMO_USER, DEMO_PASSWORD)
        self.reviews = Reviews(home)
        self.settings = QSettings(str(home / "settings.ini"), QSettings.Format.IniFormat)
        self.dark = self.settings.value("theme", "dark", type=str) != "light"
        self.setWindowTitle("Vigía | SOC de Tarvia")
        self.setWindowIcon(QIcon(str(BRAND / "vigia_icon_light.svg")))
        self.resize(1440, 850)
        self.setMinimumSize(990, 600)
        self.job = None
        self.transitioning = False
        self.setStyleSheet(stylesheet(self.dark))
        self.show_login()

    def theme_button(self):
        control = button(self._theme_action(), self._toggle_theme)
        control.setObjectName("themeToggle")
        return control

    def _theme_action(self):
        return "Tema claro" if self.dark else "Tema oscuro"

    def _toggle_theme(self):
        self.dark = not self.dark
        self.settings.setValue("theme", "dark" if self.dark else "light")
        self.setStyleSheet(stylesheet(self.dark))
        for mark in self.findChildren(Mark):
            mark.set_theme(self.dark)
        for control in self.findChildren(QPushButton, "themeToggle"):
            control.setText(self._theme_action())
        if isinstance(self.centralWidget(), Workbench):
            self.centralWidget().refresh_theme()

    def reduced_motion(self) -> bool:
        return self.settings.value("reduced_motion", False, type=bool)

    def _background(self, operation, callback):
        if self.job is not None:
            return
        job = Job(operation)
        self.job = job

        def finished(result, error):
            self.job = None
            callback(result, error)

        job.signals.done.connect(finished, Qt.ConnectionType.QueuedConnection)
        QThreadPool.globalInstance().start(job)

    def show_login(self):
        existing = self.account.name()
        page = QWidget()
        self.setCentralWidget(page)
        pane = QVBoxLayout(page)
        pane.setContentsMargins(32, 24, 32, 20)
        pane.setSpacing(16)
        pane.addWidget(self.theme_button(), alignment=Qt.AlignmentFlag.AlignRight)

        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        pane.addWidget(scroll, 1)
        body = LoginCanvas(self)
        scroll.setWidget(body)
        center = QVBoxLayout(body)
        center.setContentsMargins(12, 12, 12, 16)
        center.addStretch()
        card = QWidget()
        card.setObjectName("authSurface")
        card.setFixedWidth(472)
        center.addWidget(card, alignment=Qt.AlignmentFlag.AlignHCenter)
        center.addStretch()

        form = QVBoxLayout(card)
        form.setContentsMargins(40, 34, 40, 38)
        form.setSpacing(16)
        form.addWidget(Mark(184, dark=self.dark), alignment=Qt.AlignmentFlag.AlignLeft)
        form.addSpacing(6)
        heading = QVBoxLayout()
        heading.setSpacing(6)
        heading.addWidget(label("Iniciar sesión" if existing else "Configurar acceso", "title"))
        if self.demo:
            heading.addWidget(label("Entorno de práctica · SOC de Tarvia", "muted"))
        else:
            heading.addWidget(label("SOC de Tarvia" if existing else "Crea tu acceso local al SOC de Tarvia.", "muted"))
        form.addLayout(heading)
        form.addSpacing(5)

        fields = QFormLayout()
        fields.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        fields.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        fields.setVerticalSpacing(9)
        form.addLayout(fields)
        self.username = QLineEdit(existing or "")
        self.username.setMaxLength(80)
        self.username.setReadOnly(bool(existing))
        self.username.setAccessibleName("Usuario")
        fields.addRow("Usuario", self.username)
        self.password = QLineEdit()
        self.password.setMaxLength(128)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setAccessibleName("Contraseña")
        fields.addRow("Contraseña", self.password)
        self.confirm = QLineEdit(parent=card)
        self.confirm.setMaxLength(128)
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm.setAccessibleName("Repetir contraseña")
        if not existing:
            fields.addRow("Repetir contraseña", self.confirm)
        else:
            self.confirm.hide()
        self.login_notice = label("", "notice")
        self.login_notice.setVisible(False)
        form.addWidget(self.login_notice)
        self.login_button = button("Iniciar sesión", lambda: self._login(bool(existing)), primary=True)
        self.login_button.setMinimumHeight(42)
        form.addWidget(self.login_button)
        if self.demo:
            practice = button("Entrar en modo de práctica", self.enter_demo)
            practice.setMinimumHeight(40)
            form.addWidget(practice)
        self.password.returnPressed.connect(self.login_button.click if existing else self.confirm.setFocus)
        self.confirm.returnPressed.connect(self.login_button.click)
        (self.password if existing else self.username).setFocus()

    def enter_demo(self):
        if self.demo and self.login_button.isEnabled():
            self.password.setText(DEMO_PASSWORD)
            self.login_button.click()

    def _login(self, existing: bool):
        password = self.password.text()
        try:
            if existing:
                if not self.account.verify(password):
                    self.login_notice.setText("Contraseña incorrecta.")
                    self.login_notice.show()
                    self.password.clear()
                    self.login_button.setEnabled(False)
                    QTimer.singleShot(1800, lambda: self.login_button.setEnabled(True))
                    return
            else:
                if password != self.confirm.text():
                    raise ValueError("Las contraseñas no coinciden.")
                self.account.create(self.username.text(), password)
        except ValueError as error:
            self.login_notice.setText(str(error))
            self.login_notice.show()
            return
        self.password.clear()
        self.confirm.clear()
        self.show_loading()
        if DB.is_file():
            self._load(None)
        elif (DATA / "03_alertas" / "alertas.jsonl").is_file():
            self._load(DATA)

    def show_loading(self):
        page = QWidget()
        self.setCentralWidget(page)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 24, 32, 20)
        layout.addWidget(self.theme_button(), alignment=Qt.AlignmentFlag.AlignRight)
        layout.addStretch()

        content = QWidget()
        content.setMaximumWidth(520)
        stack = QVBoxLayout(content)
        stack.setContentsMargins(0, 0, 0, 0)
        stack.setSpacing(15)
        self.loading_mark = OpeningMark(self.reduced_motion(), dark=self.dark)
        stack.addWidget(self.loading_mark, alignment=Qt.AlignmentFlag.AlignHCenter)
        stack.addSpacing(10)
        self.load_notice = label("Selecciona la carpeta raíz del dataset de Tarvia.", "muted")
        self.load_notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stack.addWidget(self.load_notice)
        self.choose = button("Seleccionar carpeta…", self._choose_dataset, primary=True)
        self.back = button("Cerrar sesión", self.show_login)
        for control in (self.choose, self.back):
            control.setMinimumHeight(40)
            stack.addWidget(control, alignment=Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(content, alignment=Qt.AlignmentFlag.AlignHCenter)
        layout.addStretch()

    def _choose_dataset(self):
        selection = QFileDialog.getExistingDirectory(self, "Dataset oficial de Tarvia", str(Path.home()))
        if selection:
            self._load(Path(selection))

    def _load(self, source: Path | None):
        self.choose.hide()
        self.back.hide()
        self.loading_mark.begin()
        self.load_notice.setText("Indexando el dataset de Tarvia…" if source else "Abriendo la mesa de trabajo…")

        def operation():
            if source is not None:
                if not (source / "03_alertas" / "alertas.jsonl").is_file():
                    raise ValueError("Selecciona la carpeta raíz del dataset de Tarvia.")
                ingest(source, DB)
            with db.read_session():
                return (*db.alert_page("", 0, PAGE_SIZE), db.latest_alert_day(), db.alert_schedule())

        def finished(result, error):
            if error:
                self.loading_mark.finish()
                self.load_notice.setText(f"No se pudo cargar el dataset. {error}")
                self.choose.show()
                self.back.show()
                return
            self.loading_mark.finish()
            self.load_notice.setText("Mesa de trabajo lista")
            self.transitioning = True

            def show():
                self.transitioning = False
                self.workbench = Workbench(self, *result)
                self.setCentralWidget(self.workbench)
                if self.present:
                    self.present = False
                    self.workbench._open_by_id(DEMO_ALERT)

            QTimer.singleShot(0 if self.reduced_motion() else 230, show)

        self._background(operation, finished)

    def closeEvent(self, event):
        if self.job or self.transitioning:
            event.ignore()
            return
        super().closeEvent(event)
