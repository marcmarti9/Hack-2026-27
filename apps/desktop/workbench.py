"""Cola SIEM, decisiones, estadísticas e informe de Vigía."""
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QDate, QSignalBlocker, QSize, Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFontDatabase
from PySide6.QtWidgets import (
    QBoxLayout, QButtonGroup, QCheckBox, QComboBox, QDateEdit, QDialog, QFileDialog, QGridLayout,
    QHBoxLayout, QHeaderView, QLineEdit, QMenu, QMessageBox, QProgressBar, QSlider,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from apps.backend.rules.engine import LEVELS, fuera_de_horario, madrid
from apps.backend.tools import db
from apps.desktop.assistant import available_model, context_for, local_answer, openai_answer
from apps.desktop.brand_widgets import Mark, navigation_icon
from apps.desktop.case_data import SECTION_NAMES, case_sections, demo_process, fraction, pretty, soc_status
from apps.desktop.demo import DEMO_ALERT, archive, for_alert
from apps.desktop.operations import Operations
from apps.desktop.reports import imported_summary, read_report
from apps.desktop.review import CLASSIFICATIONS, PLAYBOOKS, VERDICTS, investigate, replay_demo
from apps.desktop.widgets import POSITIVE, WARNING, Article, button, label, set_primary, text_area

PAGE_SIZE = 50
SEVERITY = {
    "critical": ("Crítica", "#9d302d"), "high": ("Alta", "#92412a"),
    "medium": ("Media", "#78551f"), "low": ("Baja", "#35614d"),
    "informational": ("Info", "#536272"),
}


def number(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def table(headers: list[str]) -> QTableWidget:
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.verticalHeader().hide()
    widget.verticalHeader().setDefaultSectionSize(41)
    widget.setShowGrid(False)
    widget.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    widget.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    return widget


def calendar(day: str) -> QDateEdit:
    widget = QDateEdit(QDate.fromString(day, Qt.DateFormat.ISODate) if day else QDate.currentDate())
    widget.setDisplayFormat("dd/MM/yyyy")
    widget.setCalendarPopup(True)
    widget.setAccessibleName("Fecha UTC")
    return widget


class Workbench(QWidget):
    def __init__(self, window, rows: list[dict], total: int, latest_day: str, schedule: tuple[int, int]):
        super().__init__()
        self.window = window
        self.demo = window.demo
        self.store = window.reviews
        self.reviews = self.store.all()
        self.rows, self.total, self.offset = rows, total, 0
        self.dataset_total = total
        self.latest_day = latest_day
        self.schedule = schedule
        self.selected = None
        self.filters = ("", "", "", "latest", "all")
        self.report_rows = None
        self.attachment = ("", "")
        self.chat_expanded = False
        self.chat_choice = None
        self.stats_loaded = False
        self.report_loaded = False
        self.operations = []
        self.sections = Operations(self)
        self.root = QHBoxLayout(self)
        self.root.setContentsMargins(0, 0, 0, 0)
        self.root.setSpacing(0)
        self._rail()

        body = QWidget()
        body.setObjectName("mainCanvas")
        layout = QVBoxLayout(body)
        layout.setContentsMargins(20, 14, 18, 16)
        self.root.addWidget(body, 1)
        masthead = QWidget()
        masthead.setObjectName("workspaceHeader")
        top = QHBoxLayout(masthead)
        top.setContentsMargins(12, 5, 7, 5)
        brand = label("Entorno de práctica" if self.demo else "SOC de Tarvia", "muted")
        brand.setWordWrap(False)
        top.addWidget(brand)
        top.addStretch()
        self.soc = label("", "accentText")
        self.soc.setToolTip("Horario de Madrid · lunes a viernes de 08:00 a 20:00")
        self.soc.setWordWrap(False)
        self.soc_timer = QTimer(self, interval=30_000)
        self.soc_timer.timeout.connect(self._update_soc)
        self.soc_timer.start()
        self._update_soc()
        top.addWidget(self.soc)
        self.status = label("Índice local listo", "muted")
        self.chat_toggle = button("Chat", self._choose_chat, tip="Mostrar u ocultar el chat")
        self.chat_toggle.setCheckable(True)
        self.chat_toggle.setChecked(True)
        top.addWidget(self.chat_toggle)
        layout.addWidget(masthead)
        self.split = QSplitter()
        self.split.setChildrenCollapsible(False)
        layout.addWidget(self.split, 1)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._alerts())
        self.pages.addWidget(self._statistics())
        self.pages.addWidget(self._reports())
        self.pages.addWidget(self.sections.tickets(table))
        self.pages.addWidget(self.sections.history(table))
        self.pages.addWidget(self.sections.playbooks())
        self.split.addWidget(self.pages)
        self.split.addWidget(self._chat())
        self.split.setStretchFactor(0, 3)
        self.split.setStretchFactor(1, 1)
        self.split.setSizes([980, 310])
        layout.addWidget(self.status)
        self._render_rows()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "chat_panel") and self.chat_choice is None and not self.window.isFullScreen():
            self._apply_chat_width()

    def _apply_chat_width(self):
        visible = self.width() >= 1180 if self.chat_choice is None else self.chat_choice
        self.chat_toggle.setChecked(visible)
        self._toggle_chat(visible)

    def _choose_chat(self, visible):
        self.chat_choice = visible
        self._toggle_chat(visible)

    def _update_soc(self):
        state = soc_status()
        self.soc.setText(state)
        self.soc.setStyleSheet("color: " + (WARNING if state == "SOC cerrado" else POSITIVE))

    def _remote_model(self):
        return "" if self.demo else available_model()

    def _rail(self):
        self.rail = QWidget()
        self.rail.setObjectName("rail")
        layout = QVBoxLayout(self.rail)
        layout.setContentsMargins(8, 14, 8, 12)
        layout.setSpacing(5)
        self.rail_identity = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.rail_identity.setSpacing(5)
        self.rail_logo = Mark(116)
        self.rail_eye = Mark(24, icon=True)
        for mark in (self.rail_logo, self.rail_eye):
            self.rail_identity.addWidget(mark, alignment=Qt.AlignmentFlag.AlignHCenter)
        self.menu_toggle = button("", self._toggle_menu)
        self.menu_toggle.setObjectName("menuToggle")
        self.menu_toggle.setFixedSize(34, 34)
        self.menu_toggle.setIcon(navigation_icon("menu"))
        self.menu_toggle.setIconSize(QSize(18, 18))
        self.rail_identity.addWidget(self.menu_toggle, alignment=Qt.AlignmentFlag.AlignHCenter)
        layout.addLayout(self.rail_identity)
        layout.addSpacing(16)
        self.nav = QButtonGroup(self)
        self.rail_controls = {}
        destinations = (
            ("Inicio", "alerts"), ("Estadísticas", "statistics"), ("Informe diario", "report"),
            ("Tickets", "tickets"), ("Historial", "history"), ("Playbooks", "guides"),
        )
        for index, (title, icon) in enumerate(destinations):
            control = self._rail_button(title, icon, lambda _checked=False, idx=index: self._navigate(idx))
            control.setCheckable(True)
            control.setChecked(index == 0)
            self.nav.addButton(control, index)
            self.operations.append(control)
            layout.addWidget(control)
        layout.addStretch()
        layout.addWidget(self._rail_button("Avisos", "notices", self._notifications))
        self.profile = self._rail_button("Perfil", "profile", self._profile)
        layout.addWidget(self.profile)
        self.root.addWidget(self.rail)
        self._set_menu_expanded(self.window.settings.value("menu_expanded", True, type=bool))

    def _rail_button(self, title, icon, callback):
        control = button(title, callback, tip=title)
        control.setObjectName("navItem")
        control.setAccessibleName(title)
        control.setIcon(navigation_icon(icon))
        control.setIconSize(QSize(18, 18))
        self.rail_controls[control] = title
        return control

    def _toggle_menu(self):
        self._set_menu_expanded(not self.menu_expanded)
        self.window.settings.setValue("menu_expanded", self.menu_expanded)

    def _set_menu_expanded(self, expanded):
        self.menu_expanded = expanded
        self.rail.setFixedWidth(178 if expanded else 57)
        self.rail_logo.setVisible(expanded)
        self.rail_eye.setVisible(not expanded)
        self.rail_identity.setDirection(QBoxLayout.Direction.LeftToRight if expanded else QBoxLayout.Direction.TopToBottom)
        action = "Plegar menú" if expanded else "Desplegar menú"
        self.menu_toggle.setAccessibleName(action)
        self.menu_toggle.setToolTip(action)
        for control, title in self.rail_controls.items():
            control.setText(title if expanded else "")
            control.setProperty("compact", not expanded)
            control.style().unpolish(control)
            control.style().polish(control)

    def _navigate(self, index: int):
        self.nav.button(index).setChecked(True)
        if index != 2 and self.window.isFullScreen():
            self._present()
        if index != 2 and self.replay.isActive():
            self.replay.stop()
            self.play.setText("Reproducir")
        self.pages.setCurrentIndex(index)
        if index == 1 and not self.stats_loaded:
            self._refresh_stats()
        elif index == 2 and not self.report_loaded:
            self._refresh_report()
        elif index == 3:
            self.sections.refresh_tickets()
        elif index == 4:
            self.sections.refresh_history()

    def _profile(self):
        menu = QMenu(self)
        identity = menu.addAction(self.window.account.name() or "Analista")
        identity.setEnabled(False)
        menu.addSeparator()
        menu.addAction("Ajustes", self._settings)
        menu.addAction("Manual de uso", self._manual)
        leave = menu.addAction("Cerrar sesión", self._logout)
        leave.setEnabled(self.window.job is None)
        menu.exec(self.profile.mapToGlobal(self.profile.rect().topRight()))

    def _settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Ajustes de Vigía")
        layout = QVBoxLayout(dialog)
        motion = QCheckBox("Reducir las animaciones")
        motion.setChecked(self.window.reduced_motion())
        motion.toggled.connect(lambda value: self.window.settings.setValue("reduced_motion", value))
        layout.addWidget(motion)
        layout.addWidget(label("Entorno de práctica · expedientes archivados" if self.demo else
                               f"Modelo de OpenAI: {self._remote_model() or 'sin configurar'}", "muted"))
        layout.addWidget(button("Cerrar", dialog.accept))
        dialog.exec()

    def _manual(self):
        QMessageBox.information(self, "Manual de Vigía",
            "Inicio: busca o filtra alertas y abre su detalle. Una propuesta que supera la segunda "
            "pasada puede aceptarse. Si la corriges, elige el veredicto y Vigía registra tu decisión.\n\n"
            "Estadísticas: consulta severidades, fuentes y decisiones locales.\n\n"
            "Informe diario: elige una fecha, importa un archivo JSON o JSONL de alertas y reproduce "
            "la jornada por horas UTC.\n\n"
            "Chat: selecciona una alerta o indica un ID de evento. OpenAI se habilita si hay un modelo "
            "y una clave configurados. Al elegirlo se envía el contexto mostrado.")

    def _logout(self):
        if not self.window.job:
            self.window.show_login()

    def _notifications(self):
        done = sum(bool(item["decision"]) for item in self.reviews.values())
        proposed = sum(self._can_accept(item) for item in self.reviews.values())
        QMessageBox.information(self, "Notificaciones de la cola",
            f"{proposed:,} propuestas listas para revisar.\n"
            f"{max(0, self.dataset_total - done):,} alertas sin decisión registrada.")

    def _panel(self, title: str, description: str) -> tuple[QWidget, QVBoxLayout]:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 13, 0)
        layout.setSpacing(10)
        layout.addWidget(label(title, "title"))
        layout.addWidget(label(description, "muted"))
        return widget, layout

    def _alerts(self):
        widget, layout = self._panel(
            "Alertas", f"{number(self.dataset_total)} en el índice   ·   Fuera de horario {fraction(*self.schedule)}"
        )
        filters = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setMaxLength(150)
        self.query.setPlaceholderText("Buscar por ID, regla, usuario o equipo")
        self.query.setAccessibleName("Buscar alertas")
        self.search = button("Buscar", self._search)
        self.prepare = button("Preparar 5", self._prepare_queue, primary=True,
                              tip="Envía a OpenAI hasta cinco alertas visibles para análisis y contraste")
        self.prepare.setVisible(bool(self._remote_model()))
        self.query.returnPressed.connect(self.search.click)
        filters.addWidget(self.query, 1)
        filters.addWidget(self.search)
        filters.addWidget(self.prepare)
        if self.demo:
            demo_case = button("Caso LSASS", lambda: self._open_by_id(DEMO_ALERT), primary=True)
            filters.addWidget(demo_case)
            self.operations.append(demo_case)
        layout.addLayout(filters)

        options = QHBoxLayout()
        self.day_filter = QCheckBox("Fecha UTC")
        self.day = calendar(self.latest_day)
        self.day.setEnabled(False)
        self.day.hide()
        self.day_filter.toggled.connect(self.day.setEnabled)
        self.day_filter.toggled.connect(self.day.setVisible)
        self.day_filter.toggled.connect(self._search)
        self.day.dateChanged.connect(lambda _: self._search() if self.day_filter.isChecked() else None)
        self.severity = QComboBox()
        self.severity.setAccessibleName("Filtrar por severidad")
        self.severity.addItem("Toda severidad", "")
        for level in reversed(LEVELS):
            self.severity.addItem(SEVERITY[level][0], level)
        self.verdict = QComboBox()
        self.verdict.setAccessibleName("Filtrar por veredicto o estado")
        for text, key in [("Todos los estados", "all"), ("Sin decisión", "pending"), ("Revisadas", "done")]:
            self.verdict.addItem(text, key)
        for key in CLASSIFICATIONS:
            self.verdict.addItem(VERDICTS[key][0], key)
        self.sort = QComboBox()
        self.sort.setAccessibleName("Ordenar alertas")
        for name, key in [("Recientes primero", "latest"), ("Antiguas primero", "oldest"), ("Por severidad", "severity")]:
            self.sort.addItem(name, key)
        for control in (self.severity, self.verdict, self.sort):
            control.currentIndexChanged.connect(self._search)
        for control in (self.day_filter, self.day, self.severity, self.verdict, self.sort):
            options.addWidget(control)
        options.addStretch()
        self.reset_filters = button("Limpiar filtros", self._reset_filters)
        self.reset_filters.hide()
        options.addWidget(self.reset_filters)
        layout.addLayout(options)

        self.table = table(["Hora UTC", "Alerta", "Severidad", "Estado", "Veredicto", "Analista", "Detalle"])
        self.table.setAccessibleName("Cola de alertas")
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(6, 106)
        self.table.currentCellChanged.connect(self._select)
        self.table.cellActivated.connect(lambda row, _: self._detail(self.rows[row]))
        layout.addWidget(self.table, 1)
        self.empty_queue = label("No hay alertas que coincidan con la búsqueda. Prueba a limpiar los filtros.", "muted")
        layout.addWidget(self.empty_queue)

        decision_bar = QWidget()
        decision_bar.setObjectName("queueFooter")
        decisions = QHBoxLayout(decision_bar)
        decisions.setContentsMargins(0, 9, 0, 0)
        self.selected_alert = label("", "muted")
        self.queue_correct = button("Corregir", lambda: self._act_on_selection(self._correct))
        self.queue_accept = button("Aceptar propuesta", lambda: self._act_on_selection(self._accept), primary=True)
        decisions.addWidget(self.selected_alert, 1)
        decisions.addWidget(self.queue_correct)
        decisions.addWidget(self.queue_accept)
        layout.addWidget(decision_bar)
        pager = QHBoxLayout()
        self.count = label("", "muted")
        self.previous = button("Anterior", lambda: self._fetch(self.offset - PAGE_SIZE, self.filters))
        self.next = button("Siguiente", lambda: self._fetch(self.offset + PAGE_SIZE, self.filters))
        pager.addWidget(self.count, 1)
        pager.addWidget(self.previous)
        pager.addWidget(self.next)
        layout.addLayout(pager)
        self.operations += [self.search, self.prepare, self.day_filter, self.severity, self.verdict,
                            self.sort, self.reset_filters]
        return widget

    def _reset_filters(self):
        controls = (self.query, self.day_filter, self.severity, self.verdict, self.sort)
        blockers = [QSignalBlocker(control) for control in controls]
        self.query.clear()
        self.day_filter.setChecked(False)
        self.day.hide()
        for combo in controls[2:]:
            combo.setCurrentIndex(0)
        del blockers
        self._search()

    def _act_on_selection(self, action):
        if self.selected and not self.window.job:
            action(self.selected)

    def _search(self, *_):
        day = self.day.date().toString(Qt.DateFormat.ISODate) if self.day_filter.isChecked() else ""
        self._fetch(0, (self.query.text(), day, self.severity.currentData(),
                        self.sort.currentData(), self.verdict.currentData()))

    def _fetch(self, offset: int, filters):
        query, day, severity, sort, state = filters
        reviewed = [key for key, item in self.reviews.items() if item["decision"]]
        selected_ids = None
        if state == "done":
            selected_ids = reviewed
        elif state in CLASSIFICATIONS:
            selected_ids = [key for key, item in self.reviews.items() if self._verdict(item) == state]

        def finished(result, error):
            if error:
                self._error("No se pudieron recuperar las alertas.", error)
                return
            self.rows, self.total = result
            self.offset, self.filters = offset, filters
            self._render_rows()

        self._run(lambda: db.alert_page(query, offset, PAGE_SIZE, day=day, severity=severity, sort=sort,
                                       selected_ids=selected_ids, exclude_ids=reviewed if state == "pending" else None),
                  finished, "Consultando la cola…")

    @staticmethod
    def _verdict(item: dict) -> str:
        return item.get("verdict") or (item.get("analysis") or {}).get("verdict", "needs_more_info")

    @staticmethod
    def _can_accept(item: dict) -> bool:
        return not item.get("decision") and (item.get("analysis") or {}).get("verdict") in CLASSIFICATIONS

    def _queue_candidates(self):
        return [
            alert for alert in self.rows
            if not self.reviews.get(alert["alert_id"], {}).get("decision")
            and not (self.reviews.get(alert["alert_id"], {}).get("analysis") or {}).get("proposal")
            and alert.get("related_events")
        ][:5]

    def _prepare_queue(self):
        batch = self._queue_candidates()
        if not batch or not self._remote_model():
            return

        def operation():
            documents = {key: self.store.guidance(key) for key in {item["runbook"] for item in batch}}
            processed, failures = 0, []
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending = {pool.submit(investigate, item, True, documents[item["runbook"]]): item["alert_id"]
                           for item in batch}
                for task in as_completed(pending):
                    alert_id = pending[task]
                    try:
                        self.store.save_analysis(alert_id, task.result())
                        processed += 1
                    except (ValueError, OSError) as error:
                        failures.append(f"{alert_id} · {error}")
            return processed, "\n".join(failures)

        def done(result, error):
            self.reviews = self.store.all()
            self._render_rows()
            if error:
                self._error("Se interrumpió el análisis de la cola.", error)
                return
            processed, message = result
            self.stats_loaded = False
            self.status.setText(f"{processed}/{len(batch)} analizadas")
            if message:
                self._error("Algunas alertas no pudieron analizarse.", message)

        self._run(operation, done, f"Analizando {len(batch)} alertas con OpenAI…")

    def _render_rows(self):
        selected = self.selected["alert_id"] if self.selected else ""
        next_row = 0
        self.table.blockSignals(True)
        self.table.clearContents()
        self.table.setRowCount(len(self.rows))
        for row, alert in enumerate(self.rows):
            identifier = alert["alert_id"]
            item = self.reviews.get(identifier, {})
            analysis = item.get("analysis") or {}
            if identifier == selected:
                next_row = row
            verdict, color, _ = VERDICTS[self._verdict(item)]
            level, level_color = SEVERITY.get(analysis.get("severity", alert["severity"]), ("Info", "#536272"))
            state = {"accepted": "Validada", "corrected": "Corregida"}.get(item.get("decision"))
            state = state or ("Por decidir" if self._can_accept(item) else
                              "Sin consenso" if analysis.get("proposal") else "Pendiente")
            stamp = alert["created_at"]
            columns = (stamp[8:10] + "/" + stamp[5:7] + " " + stamp[11:16], alert["rule_name"], level,
                       state, verdict, item.get("reviewer") or "—")
            for column, value in enumerate(columns):
                cell = QTableWidgetItem(value)
                cell.setToolTip(f"{identifier}\n{alert['rule_name']}" if column == 1 else value)
                if column == 4 and analysis.get("confidence") is not None:
                    cell.setToolTip(f"{value} · {analysis['confidence']}% estimado")
                if column in (2, 4):
                    cell.setForeground(QBrush(QColor(level_color if column == 2 else color)))
                self.table.setItem(row, column, cell)
            actions = QWidget()
            controls = QHBoxLayout(actions)
            controls.setContentsMargins(2, 2, 2, 2)
            controls.setSpacing(4)
            detail = button("Ver detalle", lambda _, entry=alert: self._detail(entry),
                            tip=f"Ver detalle de {identifier}")
            detail.setObjectName("rowAction")
            detail.setAccessibleName(f"Ver detalle de {identifier}")
            controls.addWidget(detail)
            self.table.setCellWidget(row, 6, actions)
        self.table.blockSignals(False)
        self.count.setText(f"{self.offset + 1}–{self.offset + len(self.rows)} de {number(self.total)}"
                           if self.rows else "Sin coincidencias")
        self.empty_queue.setVisible(not self.rows)
        self.reset_filters.setVisible(self.filters != ("", "", "", "latest", "all"))
        if self.rows:
            self.table.setCurrentCell(next_row, 1)
            self.table.selectRow(next_row)
        self._select(next_row if self.rows else -1)
        self._controls(self.window.job is not None)

    def _select(self, row, *_):
        self.selected = self.rows[row] if 0 <= row < len(self.rows) else None
        self._selection_actions(self.window.job is not None)
        if hasattr(self, "chat_context"):
            self.chat_context.setText("Contexto: " + (self.selected["alert_id"] if self.selected else "ninguna alerta"))

    def _selection_actions(self, busy):
        identifier = self.selected["alert_id"] if self.selected else ""
        item = self.reviews.get(identifier, {})
        self.selected_alert.setText(f"Seleccionada · {identifier}" if identifier else "Selecciona una alerta")
        self.queue_accept.setEnabled(not busy and bool(identifier) and self._can_accept(item))
        self.queue_correct.setEnabled(not busy and bool(identifier) and not item.get("decision"))

    def _controls(self, busy: bool):
        for control in self.operations:
            control.setEnabled(not busy)
        self.previous.setEnabled(not busy and self.offset > 0)
        self.next.setEnabled(not busy and self.offset + len(self.rows) < self.total)
        self.day.setEnabled(not busy and self.day_filter.isChecked())
        self.prepare.setEnabled(not busy and bool(self._queue_candidates()))
        self.table.setEnabled(not busy)
        self._selection_actions(busy)

    def _run(self, operation, done, message: str):
        if self.window.job:
            return
        self.status.setText(message)
        self._controls(True)

        def finished(result, error):
            self.status.setText("Índice local listo" if error is None else "Consulta interrumpida")
            self._controls(False)
            done(result, error)

        self.window._background(operation, finished)

    def _error(self, title: str, error):
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Vigía")
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(f"{title}\n\n{error}")
        dialog.exec()

    def _accept(self, alert):
        item = self.reviews.get(alert["alert_id"], {})
        if not self.window.job and self._can_accept(item):
            self._save_decision(alert, item["analysis"]["verdict"], "accepted", item["analysis"])

    def _correct(self, alert):
        if self.window.job or self.reviews.get(alert["alert_id"], {}).get("decision"):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Corregir veredicto")
        layout = QVBoxLayout(dialog)
        layout.addWidget(label(alert["alert_id"] + " · " + alert["rule_name"], "sectionTitle"))
        layout.addWidget(label("Elige el veredicto que respalda tu revisión. La propuesta original se conserva.", "muted"))
        choices = QComboBox()
        for key in CLASSIFICATIONS:
            choices.addItem(VERDICTS[key][0], key)
        choices.setCurrentIndex(-1)
        layout.addWidget(choices)
        actions = QHBoxLayout()
        actions.addWidget(button("Cancelar", dialog.reject))
        save = button("Registrar decisión", dialog.accept, primary=True)
        save.setEnabled(False)
        choices.currentIndexChanged.connect(lambda index: save.setEnabled(index >= 0))
        actions.addWidget(save)
        layout.addLayout(actions)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._save_decision(alert, choices.currentData(), "corrected")

    def _save_decision(self, alert, verdict, decision, expected=None):
        try:
            changed = self.store.decide(alert["alert_id"], verdict, decision, self.window.account.name(), expected)
            self.reviews = self.store.all()
        except Exception as error:
            self._error("No se pudo guardar la decisión.", error)
            return
        self.stats_loaded = False
        self.status.setText("Decisión guardada" if changed else "La propuesta o la decisión ya cambió")
        if self.filters[-1] == "all":
            self._render_rows()
        else:
            self._search()

    def _open_by_id(self, alert_id):
        def done(alert, error):
            if error or alert is None:
                self._error("No se pudo abrir la alerta.", error or alert_id)
            else:
                self._detail(alert)

        self._run(lambda: db.get_alert(alert_id), done, "Buscando alerta…")

    def _detail(self, alert):
        if self.window.job:
            return
        alert_id = alert["alert_id"]
        ticket, incident, closed = for_alert(alert_id)
        baseline = {}
        dialog = QDialog(self)
        dialog.setWindowTitle("Detalle · " + alert_id)
        dialog.resize(900, 735)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(10)
        heading = QHBoxLayout()
        heading.addWidget(label(f"{alert_id}  ·  {alert['source_product']}  ·  {alert['runbook']}", "muted"), 1)
        heading.addWidget(button("Ver guías", lambda: self._view_guidance(dialog, alert["runbook"])))
        layout.addLayout(heading)
        layout.addWidget(label(alert["rule_name"], "title"))
        stamp = alert["created_at"]
        layout.addWidget(label(f"{madrid(stamp):%d/%m/%Y %H:%M %Z}  ·  {soc_status(stamp)} al dispararse", "muted"))

        facts = QWidget()
        facts.setObjectName("caseFacts")
        metrics = QHBoxLayout(facts)
        metrics.setContentsMargins(13, 10, 13, 10)
        values = {}
        for title in ("Severidad", "Veredicto", "Confianza", "Eventos"):
            column = QVBoxLayout()
            column.setSpacing(3)
            column.addWidget(label(title, "factLabel"))
            values[title] = label("—", "factValue")
            column.addWidget(values[title])
            metrics.addLayout(column, 2 if title == "Veredicto" else 1)
        layout.addWidget(facts)
        feedback = label("", "muted")
        layout.addWidget(feedback)

        tabs = QTabWidget()
        detail = Article("Proceso y revisión adversarial")
        detail.setObjectName("reviewProcess")
        tabs.addTab(detail, "Resumen")
        data_page = QWidget()
        data_layout = QVBoxLayout(data_page)
        selector = QHBoxLayout()
        event_choice = QComboBox()
        event_choice.setAccessibleName("Evento original")
        event_detail = button("Ver evento original")
        event_detail.setEnabled(False)
        selector.addWidget(event_choice, 1)
        selector.addWidget(event_detail)
        data_layout.addLayout(selector)
        evidence = text_area("Eventos y contexto consultados")
        evidence.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        data_layout.addWidget(evidence, 1)
        tabs.addTab(data_page, "Evidencias")
        extra = {name: text_area(name) for name in SECTION_NAMES}
        for name, widget in extra.items():
            tabs.addTab(widget, name)
        layout.addWidget(tabs, 1)

        footer = QHBoxLayout()
        if self.demo:
            remote = button("Cargar análisis de referencia", primary=True,
                            tip="Abre la propuesta y el contraste del expediente archivado")
            remote.setVisible(bool(ticket))
        else:
            remote = button("Analizar y contrastar con OpenAI", primary=True,
                            tip="Envía la alerta, sus eventos y las guías de triaje a OpenAI en dos pasadas")
            remote.setVisible(bool(self._remote_model()))
        export = button("Exportar JSON")
        footer.addWidget(remote)
        footer.addWidget(export)
        footer.addStretch()
        accept = button("Aceptar", primary=True)
        correct = button("Corregir")
        close = button("Cerrar", dialog.reject)
        for control in (accept, correct, close):
            footer.addWidget(control)
        layout.addLayout(footer)

        def render():
            item = self.reviews.get(alert_id, {})
            analysis = item.get("analysis") or baseline
            verdict = item.get("verdict") or analysis.get("verdict", "needs_more_info")
            verdict_name, verdict_color, _ = VERDICTS[verdict]
            severity, severity_color = SEVERITY[analysis.get("severity", alert["severity"])]
            values["Severidad"].setText(severity)
            values["Severidad"].setStyleSheet(f"color: {severity_color};")
            values["Veredicto"].setText(verdict_name)
            values["Veredicto"].setStyleSheet(f"color: {verdict_color};")
            confidence = analysis.get("confidence")
            values["Confianza"].setText(f"{confidence} %" if confidence is not None else "—")
            values["Eventos"].setText(str(len(analysis["events"])) if analysis else "—")

            sections = [("Qué detectó el SIEM", alert["description"])]
            sources = []
            event_ids = list(alert["related_events"])
            if analysis:
                if analysis.get("origin") == "demo":
                    feedback.setText("Análisis de referencia · propuesta y contraste archivados")
                elif analysis.get("review_error") or analysis.get("proposal_error"):
                    feedback.setText("Análisis pendiente de revisión")
                elif self._can_accept(item):
                    feedback.setText("El contraste coincide con la propuesta. Puedes aceptarla o corregirla.")
                else:
                    feedback.setText("Sin decisión registrada.")
                sections.extend([
                    ("Propuesta", self._result_text(analysis.get("proposal"), analysis.get("proposal_error", ""))),
                    ("Revisión adversarial", self._result_text(analysis.get("challenge"), analysis.get("review_error", ""))),
                ])
                for event in analysis["events"]:
                    sources.extend([f"{event['event_id']} · {event['source']}", pretty(event), ""])
                    event_ids.append(event["event_id"])
                missing = set(analysis["requested"]) - {x["event_id"] for x in analysis["events"]}
                policy = [analysis["severity_rationale"], f"SLA: {analysis['sla']}",
                          f"{len(analysis['events'])} eventos recuperados. Consulta la pestaña Evidencias."]
                if alert["related_events"]:
                    policy.append("Referencias de la alerta: " + ", ".join(alert["related_events"]))
                if missing:
                    policy.append("Eventos no encontrados: " + ", ".join(sorted(missing)))
                sections.append(("Datos y criterio de severidad", "\n".join(policy)))
                if "sent_events" in analysis:
                    sources.extend(["Registros incluidos en la solicitud a OpenAI",
                                    pretty(analysis["sent_events"]), ""])
                for name, records in analysis.get("context", {}).items():
                    if records:
                        sources.extend([name.capitalize(), pretty(records), ""])
                timings = analysis.get("timing", {})
                phases = {"evidence_ms": "Datos", "proposal_ms": "Propuesta",
                          "challenge_ms": "Contraste", "total_ms": "Total"}
                trace = ["  ·  ".join(f"{title} {timings[key]} ms" for key, title in phases.items() if key in timings)]
                if analysis.get("guidance"):
                    trace.append("Guías usadas: " + " · ".join(f"{key} v{rev}" for key, rev in analysis["guidance"].items()))
                if confidence is not None:
                    trace.append(f"Confianza estimada por {analysis['provider']}: {confidence}%")
                sections.append(("Tiempos y guías", "\n".join(line for line in trace if line)))
            else:
                feedback.setText("Cargando evidencias del índice…")
            if item.get("decision"):
                feedback.setText(f"Decisión registrada · {verdict_name} · {item['reviewer']}")
                sections.insert(1, ("Decisión humana", f"{verdict_name} · {item['reviewer']} · {item['reviewed_at']}"))
            if archived := demo_process(ticket, closed):
                sections.append(("Expediente de referencia", "\n".join(archived).strip()))
            if ticket:
                sources.extend(["Evidencias y hallazgos del expediente archivado", pretty(ticket.get("evidence", []))])
                event_ids.extend(event["event_id"] for event in ticket.get("evidence", []))
            event_ids.extend(point["event_id"] for point in incident.get("timeline", []))
            detail.show_sections(sections)
            evidence.setPlainText("\n".join(sources) or "No hay datos recuperados.")
            previous = event_choice.currentText()
            event_choice.clear()
            event_choice.addItems(list(dict.fromkeys(key for key in event_ids if key and key != "unknown")))
            if previous:
                event_choice.setCurrentText(previous)
            event_detail.setEnabled(bool(event_choice.count()) and self.window.job is None)
            history = self.store.history(alert_id)
            if item.get("decision") and not any(entry["kind"] in {"Aceptada", "Corregida"} for entry in history):
                history.append({"created_at": item["reviewed_at"], "kind": "Decisión humana",
                                "actor": item["reviewer"], "data": {"verdict": item["verdict"]}})
            for name, content in case_sections(alert, analysis, history).items():
                extra[name].setPlainText(content)
            can_accept = self._can_accept(item)
            accept.setEnabled(can_accept)
            set_primary(remote, not can_accept and not item.get("decision"))
            for control in (remote, correct):
                control.setEnabled(not item.get("decision") and self.window.job is None)

        def analyze(run_review):
            if self.window.job or not dialog.isVisible():
                return
            for control in (remote, accept, correct, event_detail):
                control.setEnabled(False)
            message = "Recuperando datos…"
            if run_review:
                message = ("Recuperando el expediente archivado…" if self.demo else
                           "Consultando datos y ejecutando las dos pasadas…")
            feedback.setText(message)

            def finished(result, error):
                if run_review:
                    self.reviews = self.store.all()
                    self.stats_loaded = False
                    self._render_rows()
                elif result:
                    baseline.update(result)
                if dialog.isVisible():
                    render()
                    if error:
                        feedback.setText(f"Análisis interrumpido: {error}")

            def operation():
                if run_review and self.demo:
                    analysis = replay_demo(alert, ticket)
                else:
                    guidance = self.store.guidance(alert["runbook"]) if run_review else None
                    analysis = investigate(alert, run_review, guidance)
                if run_review:
                    self.store.save_analysis(alert_id, analysis)
                return analysis

            self._run(operation, finished, "Investigando alerta…")

        def view_event():
            event_id = event_choice.currentText()

            def done(event, error):
                if not dialog.isVisible():
                    return
                if error or event is None:
                    self._error("No se pudo recuperar el evento.", error or event_id)
                    return
                viewer = QDialog(dialog)
                viewer.setWindowTitle(event_id)
                viewer.resize(720, 530)
                contents = QVBoxLayout(viewer)
                raw = text_area("Evento original")
                raw.setPlainText(pretty(event))
                contents.addWidget(raw, 1)
                contents.addWidget(button("Cerrar", viewer.reject))
                viewer.exec()

            self._run(lambda: db.get_event(event_id), done, "Consultando evento original…")

        def export_case():
            name, _ = QFileDialog.getSaveFileName(dialog, "Exportar expediente", f"{alert_id}.json", "JSON (*.json)")
            if not name:
                return
            try:
                record = self.reviews.get(alert_id, {})
                Path(name).write_text(pretty({"alerta": alert, "revision_local": record, "contexto": baseline,
                                             "historial": self.store.history(alert_id),
                                             "demo": {"ticket": ticket, "n2": incident, "descarte": closed}}) + "\n",
                                      encoding="utf-8")
            except OSError as error:
                self._error("No se pudo exportar el expediente.", error)

        remote.clicked.connect(lambda: analyze(True))
        accept.clicked.connect(lambda: (self._accept(alert), render()))
        correct.clicked.connect(lambda: (self._correct(alert), render()))
        event_detail.clicked.connect(view_event)
        export.clicked.connect(export_case)
        render()
        if not self.reviews.get(alert_id, {}).get("analysis"):
            QTimer.singleShot(0, lambda: analyze(False))
        dialog.exec()

    def _view_guidance(self, parent, runbook):
        viewer = QDialog(parent)
        viewer.setWindowTitle("Guías vigentes")
        viewer.resize(720, 560)
        layout = QVBoxLayout(viewer)
        layout.addWidget(label("Guías de triaje", "title"))
        tabs = QTabWidget()
        for key in dict.fromkeys((runbook, "SKILL")):
            if key not in PLAYBOOKS:
                continue
            revision, content = self.store.document(key)
            document = text_area(key)
            document.setPlainText(content)
            tabs.addTab(document, f"{key} · v{revision}")
        layout.addWidget(tabs, 1)
        layout.addWidget(button("Cerrar", viewer.reject), alignment=Qt.AlignmentFlag.AlignRight)
        viewer.exec()

    @staticmethod
    def _result_text(result, error=""):
        if not result:
            return error or "Pendiente de ejecución."
        confidence = result["confidence"]
        text = [f"{VERDICTS[result['verdict']][0]} · "
                + (f"{confidence}% estimado" if confidence is not None else "sin estimación propia"), result["summary"],
                f"Evidencias citadas: {', '.join(result['citations']) or 'ninguna'}"]
        if result.get("questions"):
            text.extend(["Preguntas abiertas:", *result["questions"]])
        return "\n".join(text)

    def _statistics(self):
        widget, layout = self._panel("Estadísticas", "Distribución del índice y decisiones guardadas en este perfil.")
        self.stats_total = label("Consultando el índice…", "sectionTitle")
        layout.addWidget(self.stats_total)
        self.stats_schedule = label("", "muted")
        layout.addWidget(self.stats_schedule)
        self.stats_bars = {}
        grid = QGridLayout()
        for row, level in enumerate(reversed(LEVELS)):
            grid.addWidget(label(SEVERITY[level][0]), row, 0)
            bar = QProgressBar()
            bar.setTextVisible(False)
            bar.setStyleSheet(f"QProgressBar::chunk {{ background:{SEVERITY[level][1]}; }}")
            number = label("—")
            grid.addWidget(bar, row, 1)
            grid.addWidget(number, row, 2)
            self.stats_bars[level] = (bar, number)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        self.stats_verdict = label("", "muted")
        layout.addWidget(self.stats_verdict)
        layout.addWidget(label("Alertas por fuente", "sectionTitle"))
        self.stats_table = table(["Fuente", "Alertas"])
        self.stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.stats_table, 1)
        return widget

    def _refresh_stats(self):
        analyzed_ids = [key for key, item in self.reviews.items() if (analysis := item.get("analysis"))
                        and analysis.get("proposal") and analysis.get("origin") != "demo"]

        def operation():
            with db.read_session():
                return (db.alert_totals(), db.alert_schedule(ids=analyzed_ids),
                        db.alert_schedule(ids=list(archive()["ticket_by_alert"])))

        def done(result, error):
            if error:
                self.stats_total.setText("No se pudieron cargar las estadísticas.")
                return
            self.stats_loaded = True
            rows, analyzed, demo = result
            self.stats_schedule.setText(
                f"Fuera de horario · Índice {fraction(*self.schedule)}  ·  "
                f"Propuesta OpenAI {fraction(*analyzed)}  ·  Agente simulado {fraction(*demo)}"
            )
            by_level, by_source = Counter(), Counter()
            for row in rows:
                by_level[row["severity"]] += row["total"]
                by_source[row["source"]] += row["total"]
            total = sum(by_level.values())
            decisions = Counter(item["verdict"] for item in self.reviews.values() if item["decision"])
            reviewed = sum(decisions.values())
            decision_text = "decisión registrada" if reviewed == 1 else "decisiones registradas"
            self.stats_total.setText(f"{number(total)} alertas  ·  {number(reviewed)} {decision_text}")
            self.stats_verdict.setText("  ·  ".join(f"{VERDICTS[key][0]}: {decisions[key]}"
                                                   for key in CLASSIFICATIONS))
            for key, (bar, count_label) in self.stats_bars.items():
                bar.setRange(0, max(total, 1))
                bar.setValue(by_level[key])
                count_label.setText(number(by_level[key]))
            self._fill_summary(self.stats_table, by_source.most_common())

        self._run(operation, done, "Calculando estadísticas…")

    @staticmethod
    def _fill_summary(widget, rows):
        widget.setRowCount(len(rows))
        for index, values in enumerate(rows):
            for column, value in enumerate(values):
                widget.setItem(index, column, QTableWidgetItem(str(value)))

    def _reports(self):
        widget, layout = self._panel("Informe diario", "Resumen por fecha y reproducción de la actividad por horas UTC.")
        controls = QHBoxLayout()
        self.report_day = calendar(self.latest_day)
        self.report_day.dateChanged.connect(self._refresh_report)
        controls.addWidget(self.report_day)
        refresh = button("Actualizar", self._refresh_report)
        load = button("Importar archivo…", self._load_report)
        self.report_reset = button("Volver al índice", self._reset_report)
        self.report_reset.hide()
        controls.addWidget(refresh)
        controls.addWidget(load)
        controls.addWidget(self.report_reset)
        self.presentation = button("Presentar", self._present)
        controls.addWidget(self.presentation)
        controls.addStretch()
        layout.addLayout(controls)
        self.report_source = label("Fuente: índice de Tarvia", "muted")
        self.report_count = label("—", "sectionTitle")
        layout.addWidget(self.report_source)
        layout.addWidget(self.report_count)
        self.report_schedule = label("", "muted")
        layout.addWidget(self.report_schedule)
        self.report_table = table(["Fuente", "Severidad", "Alertas"])
        self.report_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.report_table, 1)
        layout.addWidget(label("Reproducción de la jornada", "sectionTitle"))
        playback = QHBoxLayout()
        self.play = button("Reproducir", self._play)
        self.hour = QSlider(Qt.Orientation.Horizontal)
        self.hour.setRange(0, 23)
        self.hour.setAccessibleName("Hora del informe UTC")
        self.hour.valueChanged.connect(self._hour_changed)
        self.hour_totals = {}
        self.hour_signals = {}
        self.hour_notice = label("", "muted")
        self.replay_signals = label("", "muted")
        self.replay_signals.setMinimumHeight(46)
        playback.addWidget(self.play)
        playback.addWidget(self.hour, 1)
        layout.addLayout(playback)
        layout.addWidget(self.hour_notice)
        layout.addWidget(self.replay_signals)
        self.replay = QTimer(self, interval=440)
        self.replay.timeout.connect(self._tick_report)
        self.operations += [self.report_day, refresh, load, self.report_reset]
        return widget

    def _present(self):
        if self.window.isFullScreen():
            self.window.showNormal()
            self.presentation.setText("Presentar")
            self._apply_chat_width()
        else:
            self.window.showFullScreen()
            self.presentation.setText("Salir de presentación")
            self._toggle_chat(False)

    def _reset_report(self):
        self.report_rows = None
        self.report_source.setText("Fuente: índice de Tarvia")
        self.report_reset.hide()
        self._refresh_report()

    def _load_report(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Importar alertas para el informe", "",
                                                 "Alertas JSON o JSONL (*.json *.jsonl)")
        if not filename:
            return

        def done(result, error):
            if error:
                self._error("No se pudo importar el informe.", error)
                return
            self.report_rows = result
            self.report_source.setText(f"Fuente: {Path(filename).name}")
            self.report_reset.show()
            day = QDate.fromString(result[-1]["time"].date().isoformat(), Qt.DateFormat.ISODate)
            self.report_day.blockSignals(True)
            self.report_day.setDate(day)
            self.report_day.blockSignals(False)
            self._refresh_report()

        self._run(lambda: read_report(Path(filename)), done, "Importando informe…")

    def _refresh_report(self, *_):
        if self.window.job:
            return
        self.replay.stop()
        self.play.setText("Reproducir")
        day = self.report_day.date().toString(Qt.DateFormat.ISODate)
        imported = self.report_rows

        def operation():
            if imported is not None:
                times = [row["time"] for row in imported if row["time"].date().isoformat() == day]
                schedule = len(times), sum(fuera_de_horario(stamp.isoformat()) for stamp in times)
                return (*imported_summary(imported, day), schedule)
            with db.read_session():
                return db.alert_totals(day), db.alert_timeline(day), db.alert_schedule(day=day)

        def done(result, error):
            if error:
                self.report_count.setText("No se pudo cargar el informe.")
                return
            totals, timeline, schedule = result
            self.report_loaded = True
            count = sum(row["total"] for row in totals)
            critical = sum(row["total"] for row in totals if row["severity"] == "critical")
            self.report_schedule.setText(f"Alertas fuera de horario · {fraction(*schedule)}")
            self.report_count.setText(f"Total: {number(count)}  ·  Severidad crítica: {number(critical)}")
            self._fill_summary(self.report_table, [
                (row["source"], SEVERITY[row["severity"]][0], row["total"]) for row in totals
            ])
            self.hour_totals = {row["hour"]: row["total"] for row in timeline}
            self.hour_signals = {row["hour"]: row["signals"] for row in timeline}
            self.hour.setValue(0)
            self._hour_changed(0)
            self.play.setEnabled(bool(timeline))

        self._run(operation, done, "Preparando informe…")

    def _hour_changed(self, hour):
        count = self.hour_totals.get(hour, 0)
        cumulative = sum(count for time, count in self.hour_totals.items() if time <= hour)
        day = self.report_day.date().toPython()
        stamp = datetime(day.year, day.month, day.day, hour, tzinfo=timezone.utc).isoformat()
        self.hour_notice.setText(
            f"{hour:02d}:00 UTC · {madrid(stamp):%H:%M %Z} · {soc_status(stamp)}  ·  "
            f"{number(count)} alertas esta hora  ·  {number(cumulative)} acumuladas"
        )
        self.replay_signals.setText("\n".join(self.hour_signals.get(hour, [])) or "Sin actividad registrada en esta hora.")

    def _play(self):
        if self.replay.isActive():
            self.replay.stop()
            self.play.setText("Reproducir")
            return
        if self.hour.value() == 23:
            self.hour.setValue(0)
        self.replay.start()
        self.play.setText("Pausar")

    def _tick_report(self):
        self.hour.setValue(self.hour.value() + 1)
        if self.hour.value() >= 23:
            self.replay.stop()
            self.play.setText("Reproducir")

    def _chat(self):
        panel = QWidget()
        self.chat_panel = panel
        panel.setObjectName("chatPanel")
        panel.setMinimumWidth(270)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(13, 11, 13, 13)
        header = QHBoxLayout()
        header.addWidget(label("Chat", "sectionTitle"), 1)
        self.chat_size = button("Ampliar", self._resize_chat, tip="Ampliar o acoplar el chat")
        header.addWidget(button("Nuevo", self._clear_chat, tip="Empezar una consulta nueva"))
        header.addWidget(self.chat_size)
        layout.addLayout(header)
        self.chat_context = label("Contexto: ninguna alerta", "muted")
        layout.addWidget(self.chat_context)
        self.chat = text_area("Historial del chat")
        self.chat.document().setMaximumBlockCount(1200)
        self.chat.setPlainText("Selecciona una alerta o indica un ID de evento para consultar su evidencia.")
        layout.addWidget(self.chat, 1)
        self.attachment_info = label("", "muted")
        self.attachment_info.hide()
        layout.addWidget(self.attachment_info)
        options = QHBoxLayout()
        add = button("Adjuntar", self._attach, tip="Adjuntar o quitar un archivo de texto")
        prompts = button("Ejemplos", self._prompts, tip="Preguntas de ejemplo")
        mic = button("Dictado", self._dictation, tip="Usar dictado del sistema")
        options.addWidget(add)
        options.addWidget(prompts)
        options.addWidget(mic)
        options.addStretch()
        layout.addLayout(options)
        self.model = QComboBox()
        self.model.setAccessibleName("Modelo de investigación")
        self.model.addItem("Consulta local", False)
        if model := self._remote_model():
            self.model.addItem("OpenAI · envía contexto", True)
            self.model.setItemData(1, model, Qt.ItemDataRole.ToolTipRole)
        layout.addWidget(self.model)
        composer = QHBoxLayout()
        self.question = QLineEdit()
        self.question.setAccessibleName("Pregunta al asistente")
        self.question.setPlaceholderText("Pregunta sobre la alerta…")
        self.question.setMaxLength(1000)
        self.send = button("Enviar", self._ask, primary=True)
        self.question.returnPressed.connect(self.send.click)
        composer.addWidget(self.question, 1)
        composer.addWidget(self.send)
        layout.addLayout(composer)
        self.operations += [add, prompts, mic, self.model, self.send]
        return panel

    def _toggle_chat(self, visible):
        self.chat_panel.setVisible(visible)

    def _resize_chat(self):
        self.chat_expanded = not self.chat_expanded
        self.chat_size.setText("Acoplar" if self.chat_expanded else "Ampliar")
        self.split.setSizes([400, 650] if self.chat_expanded else [880, 350])

    def _clear_chat(self):
        if not self.window.job:
            self.chat.clear()
            self.question.clear()
            self._set_attachment("", "")
            self.question.setFocus()

    def _prompts(self):
        menu = QMenu(self)
        for prompt in ("¿Qué evidencias enlaza esta alerta?", "¿Qué impacto y SLA tiene esta alerta?",
                       "¿Qué falta para validar el veredicto?"):
            menu.addAction(prompt, lambda _=False, value=prompt: self.question.setText(value))
        menu.exec(self.question.mapToGlobal(self.question.rect().topLeft()))
        self.question.setFocus()

    def _dictation(self):
        shortcut = ("Windows + H" if sys.platform == "win32" else "la función Dictado de macOS"
                    if sys.platform == "darwin" else "el dictado o teclado de accesibilidad de tu escritorio")
        QMessageBox.information(self, "Dictado del sistema", f"Con el campo de chat enfocado, usa {shortcut}.")
        self.question.setFocus()

    def _set_attachment(self, name: str, text: str):
        self.attachment = (name, text)
        self.attachment_info.setText(f"Adjunto: {name}" if name else "")
        self.attachment_info.setVisible(bool(name))

    def _attach(self):
        if self.attachment[0]:
            self._set_attachment("", "")
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Adjuntar contexto", "", "Texto (*.txt *.json *.jsonl *.csv *.log)")
        if not filename:
            return
        try:
            with Path(filename).open("rb") as stream:
                data = stream.read(16_385)
            if len(data) > 16_384:
                raise ValueError("El adjunto supera 16 KB.")
            decoded = data.decode("utf-8-sig")
            if "\0" in decoded:
                raise ValueError("El adjunto debe contener texto.")
        except (OSError, ValueError) as error:
            self._error("No se pudo adjuntar el archivo.", error)
            return
        self._set_attachment(Path(filename).name, decoded)

    def _ask(self):
        question = self.question.text().strip()
        if not question or self.window.job:
            return
        selected, remote = self.selected, bool(self.model.currentData())
        name, attachment = self.attachment
        self.question.clear()
        self._set_attachment("", "")
        self.chat.appendPlainText(f"Analista · {question}" + (f"  [{name}]" if name else ""))

        def answer():
            alert, events = context_for(question + ("\n" + attachment if not remote else ""), selected)
            if remote:
                return openai_answer(question, alert, events, attachment)
            return local_answer(alert, events)

        def done(result, error):
            source = "OpenAI" if remote else "Consulta local"
            self.chat.appendPlainText(f"\n{source}\n{result if error is None else str(error)}\n")
            self.question.setFocus()

        self._run(answer, done, "Consultando evidencias…")
