"""Paneles de tickets, historial y edición de guías."""
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QHeaderView, QPlainTextEdit

from apps.desktop.case_data import display_record
from apps.desktop.defense import report_ticket_id
from apps.desktop.demo import archive
from apps.desktop.review import MAX_PLAYBOOK, PLAYBOOKS
from apps.desktop.widgets import button, label, text_area


class Operations:
    def __init__(self, work):
        self.work = work
        self.ticket_rows = []
        self.history_rows = []

    def tickets(self, table_factory):
        widget, layout = self.work._panel("Tickets", "Casos del índice local y expedientes archivados de referencia.")
        self.ticket_table = table_factory(["Ticket", "Origen", "Alerta o grupo", "Estado"])
        self.ticket_table.setAccessibleName("Tickets")
        self.ticket_table.setWordWrap(False)
        self.ticket_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.ticket_table.cellDoubleClicked.connect(lambda row, _: self._open_ticket(row))
        self.ticket_table.currentCellChanged.connect(self._ticket_selection)
        layout.addWidget(self.ticket_table)
        footer = QHBoxLayout()
        self.ticket_selection = label("", "muted")
        self.ticket_open = button("Ver detalle", lambda: self._open_ticket(self.ticket_table.currentRow()))
        self.ticket_open.setEnabled(False)
        footer.addWidget(self.ticket_selection, 1)
        footer.addWidget(self.ticket_open)
        layout.addLayout(footer)
        return widget

    def refresh_tickets(self):
        groups = {}
        for key, record in sorted(self.work.reviews.items(), reverse=True):
            analysis = record.get("analysis") or {}
            report = analysis.get("report") or {}
            ticket_id = report_ticket_id(key, analysis)
            group = groups.setdefault(ticket_id, {"representative": key, "members": set()})
            group["members"].add(key)
            if ticket_id.startswith("VIG-INC-"):
                group["members"].update(report["alert_ids"])
                if report.get("rule_id") == "UC-EDR-004":
                    group["representative"] = key

        self.ticket_rows = []
        for ticket_id, group in groups.items():
            key, members = group["representative"], group["members"]
            description = f"{len(members)} alertas · {key}" if len(members) > 1 else key
            decided = all(self.work.reviews.get(member, {}).get("decision") for member in members)
            self.ticket_rows.append(((ticket_id, "Local", description, "Decidido" if decided else "Por revisar"), key))
        self.ticket_rows.extend([
            ((ticket["ticket_id"], "Archivo", ticket["title"], "Referencia"),
             ticket["alert_ids"][0])
            for ticket in archive()["tickets"] if ticket["alert_ids"]
        ])
        self.work._fill_summary(self.ticket_table, [item[0] for item in self.ticket_rows])
        if self.ticket_rows:
            self.ticket_table.selectRow(0)
        self._ticket_selection(self.ticket_table.currentRow())

    def _ticket_selection(self, row, *_):
        selected = 0 <= row < len(self.ticket_rows)
        self.ticket_open.setEnabled(selected)
        self.ticket_selection.setText(self.ticket_rows[row][0][2] if selected else "No hay tickets en esta vista.")

    def _open_ticket(self, row: int):
        if 0 <= row < len(self.ticket_rows):
            self.work._open_by_id(self.ticket_rows[row][1])

    def history(self, table_factory):
        widget, layout = self.work._panel("Historial", "Análisis, decisiones y cambios de guías de este perfil.")
        self.history_table = table_factory(["Fecha UTC", "Tipo", "Autor", "Referencia"])
        self.history_table.setAccessibleName("Actividad del perfil")
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.currentCellChanged.connect(self._history_selection)
        layout.addWidget(self.history_table, 2)
        self.history_detail = text_area("Detalle del historial")
        layout.addWidget(self.history_detail, 1)
        return widget

    def refresh_history(self):
        self.history_rows = self.work.store.history()
        known = {(entry["target"], entry["kind"]) for entry in self.history_rows}
        for key, record in self.work.reviews.items():
            kind = {"accepted": "Aceptada", "corrected": "Corregida"}.get(record["decision"])
            if kind and (key, kind) not in known:
                self.history_rows.append({"target": key, "kind": kind, "actor": record["reviewer"],
                                          "created_at": record["reviewed_at"],
                                          "data": {"verdict": record["verdict"]}})
        self.history_rows.sort(key=lambda row: row["created_at"], reverse=True)
        self.work._fill_summary(self.history_table, [
            (row["created_at"][:19], row["kind"], row["actor"], row["target"])
            for row in self.history_rows
        ])
        if self.history_rows:
            self.history_table.selectRow(0)
            self._history_selection(0)
        else:
            self.history_detail.setPlainText("Todavía no hay actividad registrada.")

    def _history_selection(self, row, *_):
        if not 0 <= row < len(self.history_rows):
            return
        entry = self.history_rows[row]
        data = entry["data"]
        if entry["kind"] == "Análisis":
            data = {key: data[key] for key in
                    ("verdict", "confidence", "proposal", "challenge", "proposal_error", "review_error",
                     "requested", "timing", "guidance") if key in data and data[key] not in (None, "")}
        heading = f"{entry['kind']} · {entry['target']}"
        self.history_detail.setPlainText(
            f"{heading}\n{entry['created_at']} · {entry['actor']}\n\n{display_record(data)}"
        )

    def playbooks(self):
        widget, layout = self.work._panel("Playbooks y skill", "Edita las guías que Vigía consulta durante el triaje.")
        bar = QHBoxLayout()
        self.document = QComboBox()
        self.document.setAccessibleName("Elegir playbook o skill")
        for name in PLAYBOOKS:
            self.document.addItem("Skill de triaje" if name == "SKILL" else name, name)
        bar.addWidget(self.document)
        self.revision_note = label("", "muted")
        bar.addWidget(self.revision_note, 1)
        self.revert = button("Recargar", self._load_document)
        bar.addWidget(self.revert)
        self.save = button("Guardar versión", self._save_document, primary=True)
        bar.addWidget(self.save)
        layout.addLayout(bar)
        self.editor = QPlainTextEdit()
        self.editor.setAccessibleName("Contenido de la guía")
        self.editor.document().modificationChanged.connect(self._dirty)
        layout.addWidget(self.editor, 1)
        self.document.currentIndexChanged.connect(self._load_document)
        self._load_document()
        return widget

    def _dirty(self, dirty: bool):
        self.save.setEnabled(dirty)
        self.document.setEnabled(not dirty)

    def _load_document(self, *_):
        key = self.document.currentData()
        self.revision, text = self.work.store.document(key)
        self.editor.setPlainText(text)
        self.editor.document().setModified(False)
        self._dirty(False)
        self.revision_note.setText(f"Versión {self.revision}" if self.revision else "Guía original")

    def _save_document(self):
        body = self.editor.toPlainText()
        if len(body) > MAX_PLAYBOOK:
            self.revision_note.setText("El documento supera 16.000 caracteres.")
            return
        try:
            self.revision = self.work.store.save_document(
                self.document.currentData(), body, self.revision, self.work.window.account.name()
            )
        except ValueError as error:
            self.revision_note.setText(str(error))
            return
        self.editor.document().setModified(False)
        self.revision_note.setText(f"Versión {self.revision} guardada")
