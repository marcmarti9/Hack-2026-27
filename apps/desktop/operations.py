"""Paneles de tickets, historial y edición de guías."""
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QPlainTextEdit

from apps.desktop.case_data import pretty
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
        self.ticket_table.horizontalHeader().setStretchLastSection(True)
        self.ticket_table.cellDoubleClicked.connect(lambda row, _: self._open_ticket(row))
        layout.addWidget(self.ticket_table)
        layout.addWidget(button("Ver detalle", lambda: self._open_ticket(self.ticket_table.currentRow())))
        return widget

    def refresh_tickets(self):
        self.ticket_rows = [
            ((f"VIG-{key}", "Local", key, "Decidido" if record["decision"] else "Por revisar"), key)
            for key, record in sorted(self.work.reviews.items(), reverse=True)
        ] + [
            ((ticket["ticket_id"], "Archivo", f"{len(ticket['alert_ids'])} alertas · {ticket['title']}", "Referencia"),
             ticket["alert_ids"][0])
            for ticket in archive()["tickets"] if ticket["alert_ids"]
        ]
        self.work._fill_summary(self.ticket_table, [item[0] for item in self.ticket_rows])
        if self.ticket_rows:
            self.ticket_table.selectRow(0)

    def _open_ticket(self, row: int):
        if 0 <= row < len(self.ticket_rows):
            self.work._open_by_id(self.ticket_rows[row][1])

    def history(self, table_factory):
        widget, layout = self.work._panel("Historial", "Análisis, decisiones y cambios de guías de este perfil.")
        self.history_table = table_factory(["Fecha UTC", "Tipo", "Autor", "Referencia"])
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
        data = self.history_rows[row]["data"]
        if self.history_rows[row]["kind"] == "Análisis":
            data = {key: data.get(key) for key in
                    ("verdict", "confidence", "proposal", "challenge", "proposal_error", "review_error",
                     "requested", "timing", "guidance")}
        self.history_detail.setPlainText(pretty(data))

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
