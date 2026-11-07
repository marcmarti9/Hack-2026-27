"""Flujo de escritorio: sesión local, carga del índice y mesa de alertas."""
import json
import os
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton,
    QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from apps.backend.config import DATA, DB
from apps.backend.ingest import ingest
from apps.backend.tools import db
from apps.desktop.assistant import claude_answer, context_for, local_answer
from apps.desktop.session import Account

PAGE_SIZE = 100


def label(text: str, role: str = "") -> QLabel:
    widget = QLabel()
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setText(text)
    widget.setWordWrap(True)
    if role:
        widget.setObjectName(role)
    return widget


def text_area(name: str) -> QPlainTextEdit:
    widget = QPlainTextEdit()
    widget.setAccessibleName(name)
    widget.setReadOnly(True)
    return widget


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


class Window(QMainWindow):
    def __init__(self, home: Path):
        super().__init__()
        self.account = Account(home)
        self.setWindowTitle("Vigía | Mesa SOC")
        self.resize(1280, 820)
        self.setMinimumSize(760, 560)
        self.job = None
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #151b24; color: #e8edf4; font-size: 14px; }
            #title { font-size: 29px; font-weight: 700; }
            #muted { color: #aab8c8; }
            #notice { color: #ffd194; }
            QLineEdit, QPlainTextEdit, QTableWidget {
                background: #10151d; border: 1px solid #394759; border-radius: 5px;
                padding: 7px; selection-background-color: #315773;
            }
            QLineEdit:focus, QPlainTextEdit:focus, QTableWidget:focus, QPushButton:focus {
                border: 1px solid #83c8e5;
            }
            QPushButton { background: #273749; padding: 7px 12px; border: 1px solid #42566d;
                          border-radius: 5px; }
            QPushButton:hover { background: #35516a; }
            QPushButton:disabled { color: #8997a8; }
            QHeaderView::section { background: #202c3b; padding: 7px; border: 0; }
        """)
        self.show_login()

    def _page(self) -> QVBoxLayout:
        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)
        return layout

    def _centered(self, title: str, explanation: str) -> QVBoxLayout:
        page = self._page()
        page.addStretch()
        panel = QWidget()
        panel.setMaximumWidth(470)
        page.addWidget(panel, alignment=Qt.AlignmentFlag.AlignHCenter)
        page.addStretch()
        layout = QVBoxLayout(panel)
        layout.addWidget(label("VIGÍA / SOC DE TARVIA", "muted"))
        layout.addWidget(label(title, "title"))
        layout.addWidget(label(explanation, "muted"))
        return layout

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
        form = self._centered("Inicia sesión" if existing else "Crea tu cuenta local",
                              "La cuenta se guarda en este perfil del sistema operativo.")
        fields = QFormLayout()
        form.addLayout(fields)
        self.username = QLineEdit(existing or "")
        self.username.setMaxLength(80)
        self.username.setReadOnly(bool(existing))
        fields.addRow("Analista", self.username)
        self.password = QLineEdit()
        self.password.setMaxLength(128)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        fields.addRow("Contraseña", self.password)
        self.confirm = QLineEdit()
        self.confirm.setMaxLength(128)
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        if not existing:
            fields.addRow("Repetir contraseña", self.confirm)
        else:
            self.confirm.hide()
        self.login_notice = label("", "notice")
        form.addWidget(self.login_notice)
        self.login_button = QPushButton("Entrar" if existing else "Crear cuenta y entrar")
        form.addWidget(self.login_button)
        self.login_button.clicked.connect(lambda: self._login(bool(existing)))
        self.password.returnPressed.connect(self.login_button.click if existing else self.confirm.setFocus)
        self.confirm.returnPressed.connect(self.login_button.click)
        (self.password if existing else self.username).setFocus()

    def _login(self, existing: bool):
        password = self.password.text()
        try:
            if existing:
                if not self.account.verify(password):
                    self.login_notice.setText("Contraseña incorrecta.")
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
            return
        self.password.clear()
        self.confirm.clear()
        self.show_loading()
        if DB.is_file():
            self._load(None)
        elif (DATA / "03_alertas" / "alertas.jsonl").is_file():
            self._load(DATA)

    def show_loading(self):
        layout = self._centered("Preparar mesa de trabajo", "Vigía consulta un índice local del dataset de Tarvia.")
        self.load_notice = label("Selecciona la carpeta que contiene 01_contexto a 06_herramientas.", "notice")
        layout.addWidget(self.load_notice)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.choose = QPushButton("Seleccionar carpeta del dataset…")
        self.choose.clicked.connect(self._choose_dataset)
        layout.addWidget(self.choose)
        self.back = QPushButton("Cerrar sesión")
        self.back.clicked.connect(self.show_login)
        layout.addWidget(self.back)

    def _choose_dataset(self):
        selection = QFileDialog.getExistingDirectory(self, "Dataset oficial de Tarvia", str(Path.home()))
        if selection:
            self._load(Path(selection))

    def _load(self, source: Path | None):
        self.choose.setEnabled(False)
        self.back.setEnabled(False)
        self.progress.show()
        self.load_notice.setText("Importando el dataset…" if source else "Abriendo el índice…")

        def operation():
            if source is not None:
                if not (source / "03_alertas" / "alertas.jsonl").is_file():
                    raise ValueError("Selecciona la carpeta raíz del dataset de Tarvia.")
                ingest(source, DB)
            return db.alert_page("", 0, PAGE_SIZE)

        def finished(result, error):
            if error:
                self.progress.hide()
                self.load_notice.setText(f"No se pudo cargar el dataset. {error}")
                self.choose.setEnabled(True)
                self.back.setEnabled(True)
            else:
                self.show_work(*result)

        self._background(operation, finished)

    def show_work(self, rows: list[dict], total: int):
        self.rows, self.total, self.offset, self.filter = rows, total, 0, ""
        self.selected = None
        layout = self._page()
        header = QHBoxLayout()
        header.addWidget(label("Mesa de trabajo", "title"), 1)
        header.addWidget(label(self.account.name() or "", "muted"))
        self.logout = QPushButton("Cerrar sesión")
        self.logout.clicked.connect(self.show_login)
        header.addWidget(self.logout)
        layout.addLayout(header)

        split = QSplitter()
        layout.addWidget(split, 1)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(label("Alertas del SIEM"))
        search = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("Buscar por ID, regla, usuario o equipo")
        self.query.setMaxLength(150)
        self.query.setAccessibleName("Buscar alertas")
        self.search = QPushButton("Buscar")
        self.search.clicked.connect(lambda: self._page_alerts(0, self.query.text()))
        self.query.returnPressed.connect(self.search.click)
        search.addWidget(self.query, 1)
        search.addWidget(self.search)
        left_layout.addLayout(search)
        self.table = QTableWidget(0, 4)
        self.table.setAccessibleName("Cola de alertas")
        self.table.setHorizontalHeaderLabels(["Alerta", "Regla", "SIEM", "Fecha UTC"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.currentCellChanged.connect(self._select)
        left_layout.addWidget(self.table, 1)
        pagination = QHBoxLayout()
        self.count = label("", "muted")
        self.previous = QPushButton("Anterior")
        self.next = QPushButton("Siguiente")
        self.previous.clicked.connect(lambda: self._page_alerts(self.offset - PAGE_SIZE, self.filter))
        self.next.clicked.connect(lambda: self._page_alerts(self.offset + PAGE_SIZE, self.filter))
        pagination.addWidget(self.count, 1)
        pagination.addWidget(self.previous)
        pagination.addWidget(self.next)
        left_layout.addLayout(pagination)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(label("Expediente de alerta"))
        self.detail = text_area("Expediente de alerta")
        right_layout.addWidget(self.detail, 2)
        right_layout.addWidget(label("Chat de investigación"))
        self.chat = text_area("Historial del chat")
        self.chat.setPlainText("Consulta la alerta seleccionada o indica un ID de evento.")
        right_layout.addWidget(self.chat, 3)
        self.remote = QCheckBox("Usar Claude · enviar el contexto seleccionado")
        self.remote.setVisible(bool(os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL")))
        right_layout.addWidget(self.remote)
        chat_row = QHBoxLayout()
        self.question = QLineEdit()
        self.question.setAccessibleName("Pregunta al asistente")
        self.question.setPlaceholderText("¿Qué evidencias tenemos para esta alerta?")
        self.question.setMaxLength(1000)
        self.send = QPushButton("Enviar")
        self.send.clicked.connect(self._ask)
        self.question.returnPressed.connect(self.send.click)
        chat_row.addWidget(self.question, 1)
        chat_row.addWidget(self.send)
        right_layout.addLayout(chat_row)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([720, 520])
        self._render_rows()

    def _render_rows(self):
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.rows))
        for row, item in enumerate(self.rows):
            values = (item["alert_id"], item["rule_name"], item["severity"], item["created_at"][:16])
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.table.blockSignals(False)
        self.count.setText(f"{self.offset + 1}–{self.offset + len(self.rows)} de {self.total}"
                           if self.rows else "Sin coincidencias")
        self.previous.setEnabled(self.offset > 0)
        self.next.setEnabled(self.offset + len(self.rows) < self.total)
        if self.rows:
            self.table.selectRow(0)
        self._select(0 if self.rows else -1)

    def _select(self, row, *_):
        self.selected = self.rows[row] if 0 <= row < len(self.rows) else None
        if not self.selected:
            self.detail.setPlainText("Selecciona una alerta.")
            return
        item = self.selected
        self.detail.setPlainText(
            f"{item['alert_id']}\n{item['rule_name']} · {item['runbook']}\n\n"
            f"{item['description']}\n\nSeveridad SIEM: {item['severity']}\n"
            f"Eventos enlazados: {', '.join(item['related_events']) or 'Ninguno'}\n\n"
            f"{json.dumps(item.get('evidence', {}), ensure_ascii=False, indent=2)}"
        )

    def _busy(self, busy: bool):
        self.logout.setEnabled(not busy)
        self.search.setEnabled(not busy)
        self.send.setEnabled(not busy)
        self.previous.setEnabled(not busy and self.offset > 0)
        self.next.setEnabled(not busy and self.offset + len(self.rows) < self.total)

    def _page_alerts(self, offset: int, query: str):
        if self.job:
            return
        self._busy(True)

        def finished(result, error):
            if error:
                self.count.setText("No se pudieron recuperar las alertas.")
            else:
                self.rows, self.total = result
                self.offset, self.filter = offset, query
                self._render_rows()
            self._busy(False)

        self._background(lambda: db.alert_page(query, offset, PAGE_SIZE), finished)

    def _ask(self):
        question = self.question.text().strip()
        if not question or self.job:
            return
        selected, remote = self.selected, self.remote.isChecked()
        self.question.clear()
        self.chat.appendPlainText(f"Analista · {question}")
        self._busy(True)

        def answer():
            alert, events = context_for(question, selected)
            return claude_answer(question, alert, events) if remote else local_answer(alert, events)

        def finished(result, error):
            source = "Claude" if remote else "Consulta local"
            self.chat.appendPlainText(f"\n{source}\n{result if error is None else str(error)}\n")
            self._busy(False)
            self.question.setFocus()

        self._background(answer, finished)

    def closeEvent(self, event):
        if self.job:
            event.ignore()
            return
        super().closeEvent(event)
