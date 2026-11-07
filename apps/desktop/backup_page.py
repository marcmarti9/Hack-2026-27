"""Gestor de destinos y ejecución de copias de seguridad."""
import json
import shutil

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLayout, QLineEdit,
    QListWidget, QMessageBox, QProgressBar, QScrollArea, QSpinBox, QStackedWidget,
    QVBoxLayout, QWidget,
)

from apps.desktop.backup import CLOUD_HELPER, MODELS, destinations, run_backup
from apps.desktop.widgets import button, label, text_area


class BackupPage(QWidget):
    def __init__(self, work):
        super().__init__()
        self.work = work
        self.settings = work.window.settings
        self.profile = work.window.account.path.parent
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 14, 0)
        layout.setSpacing(16)
        header = QVBoxLayout()
        header.setSpacing(5)
        header.addWidget(label("Copias de seguridad", "title"))
        header.addWidget(label("Protege el perfil, las revisiones, las guías y las preferencias de Vigía.", "muted"))
        layout.addLayout(header)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        layout.addWidget(self.scroll, 1)
        self.form = QWidget()
        self.scroll.setWidget(self.form)
        body = QVBoxLayout(self.form)
        body.setContentsMargins(0, 2, 12, 14)
        body.setSpacing(14)
        body.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

        template = QHBoxLayout()
        template.addWidget(label("Plan de copia", "sectionTitle"), 1)
        self.model = QComboBox()
        self.model.setAccessibleName("Plantilla de copia")
        self.model.setMinimumWidth(165)
        self.model.addItems(MODELS)
        template.addWidget(self.model)
        body.addLayout(template)
        self.description = label("", "muted")
        body.addWidget(self.description)
        self.model.currentTextChanged.connect(self._describe)

        self._divider(body)
        body.addWidget(label("Destinos", "sectionTitle"))
        folders = QGridLayout()
        folders.setHorizontalSpacing(24)
        folders.setVerticalSpacing(8)
        folders.setColumnStretch(0, 1)
        folders.setColumnStretch(1, 1)
        self.local = self._folders(folders, 0, "Carpetas locales", "Aún no hay carpetas locales.")
        self.usb = self._folders(folders, 1, "Unidades USB", "Aún no hay unidades USB seleccionadas.")
        body.addLayout(folders)

        remote = QGridLayout()
        remote.setHorizontalSpacing(24)
        remote.setVerticalSpacing(8)
        remote.setColumnStretch(0, 1)
        remote.setColumnStretch(1, 1)
        heading = QHBoxLayout()
        heading.addWidget(label("En la nube"), 1)
        heading.addWidget(button("Obtener código", self._download_helper, tip="Descargar el generador de códigos para S3"))
        remote.addLayout(heading, 0, 0)
        remote.addWidget(label("Depósito inmutable"), 0, 1)
        self.cloud = QLineEdit()
        self.cloud.setAccessibleName("Destino en la nube")
        self.cloud.setPlaceholderText("Código de conexión o s3://bucket/carpeta")
        self.cloud.setMaxLength(1600)
        self.cloud.setMinimumHeight(self.cloud.sizeHint().height())
        remote.addWidget(self.cloud, 1, 0)
        self.immutable = QLineEdit()
        self.immutable.setAccessibleName("Depósito inmutable")
        self.immutable.setPlaceholderText("Código o ruta de S3 Object Lock")
        self.immutable.setMaxLength(1600)
        self.immutable.setMinimumHeight(self.immutable.sizeHint().height())
        remote.addWidget(self.immutable, 1, 1)
        remote.addWidget(label("Vigía sube la copia a S3 con tu perfil de AWS CLI.", "muted"), 2, 0)
        retention = QHBoxLayout()
        retention.addWidget(label("Retención", "muted"), 1)
        self.days = QSpinBox()
        self.days.setAccessibleName("Días de retención")
        self.days.setRange(1, 3650)
        self.days.setSuffix(" días")
        self.days.setMinimumHeight(self.days.sizeHint().height())
        retention.addWidget(self.days)
        remote.addLayout(retention, 2, 1)
        self.immutable.textChanged.connect(lambda text: self.days.setEnabled(bool(text.strip())))
        body.addLayout(remote)

        self._divider(body)
        body.addWidget(label("Última ejecución", "sectionTitle"))
        self.empty_result = label("Los resultados aparecerán al crear la primera copia.", "muted")
        body.addWidget(self.empty_result)
        self.result = text_area("Resultado de la última copia")
        self.result.setMinimumHeight(95)
        self.result.setMaximumHeight(160)
        body.addWidget(self.result)

        self._divider(layout)
        footer = QHBoxLayout()
        self.status = label("", "muted")
        footer.addWidget(self.status, 1)
        self.progress = QProgressBar()
        self.progress.setAccessibleName("Creación de copia en curso")
        self.progress.setRange(0, 0)
        self.progress.setMaximumWidth(90)
        self.progress.setTextVisible(False)
        self.progress.hide()
        footer.addWidget(self.progress)
        self.save = button("Guardar cambios", self._save)
        self.start = button("Crear copia", self._create, primary=True)
        footer.addWidget(self.save)
        footer.addWidget(self.start)
        layout.addLayout(footer)
        self._load()

    @staticmethod
    def _divider(layout):
        divider = QFrame()
        divider.setObjectName("backupDivider")
        divider.setFixedHeight(1)
        layout.addWidget(divider)

    def _folders(self, layout, column, title, empty):
        layout.addWidget(label(title), 0, column)
        content = QStackedWidget()
        content.setMinimumHeight(72)
        content.setMaximumHeight(112)
        placeholder = label(empty, "muted")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        content.addWidget(placeholder)
        listing = QListWidget()
        listing.setAccessibleName(title)
        listing.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        content.addWidget(listing)
        layout.addWidget(content, 1, column)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        add = button("Añadir carpeta", lambda: self._add_folder(listing), tip=f"Añadir destino a {title.lower()}")
        actions.addWidget(add)
        remove = button("Quitar", lambda: listing.takeItem(listing.currentRow()), tip=f"Quitar destino de {title.lower()}")
        remove.setEnabled(False)
        listing.currentRowChanged.connect(lambda row: remove.setEnabled(row >= 0))
        listing.model().rowsInserted.connect(lambda *_: content.setCurrentWidget(listing))

        def on_removed(*_):
            if not listing.count():
                content.setCurrentWidget(placeholder)
                add.setFocus()

        listing.model().rowsRemoved.connect(on_removed)
        actions.addWidget(remove)
        actions.addStretch()
        layout.addLayout(actions, 2, column)
        return listing

    def _add_folder(self, listing):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar destino de copia")
        if folder and all(listing.item(row).text() != folder for row in range(listing.count())):
            listing.addItem(folder)
            listing.item(listing.count() - 1).setToolTip(folder)
            listing.setCurrentRow(listing.count() - 1)

    def _describe(self, model):
        descriptions = {
            "3-2-1": "Mantén el original, una copia local o USB y una fuera de tu equipo.",
            "3-2-1-1": "Añade un depósito independiente con retención inmutable a la plantilla 3-2-1.",
            "Personalizado": "Elige los destinos que quieres usar para esta copia.",
        }
        self.description.setText(descriptions[model])

    def _load(self):
        try:
            plan = json.loads(self.settings.value("backup_plan", "{}", type=str))
        except ValueError:
            plan = {}
        if not isinstance(plan, dict):
            plan = {}
        model = plan.get("model")
        self.model.setCurrentText(model if model in MODELS else "Personalizado")
        self._describe(self.model.currentText())
        for key, listing in (("local", self.local), ("usb", self.usb)):
            paths = plan.get(key)
            if isinstance(paths, list):
                for path in paths:
                    if isinstance(path, str) and path:
                        listing.addItem(path)
                        listing.item(listing.count() - 1).setToolTip(path)
        for key, edit in (("cloud", self.cloud), ("immutable", self.immutable)):
            value = plan.get(key)
            edit.setText(value if isinstance(value, str) else "")
        days = plan.get("days")
        self.days.setValue(days if type(days) is int and 1 <= days <= 3650 else 30)
        self.days.setEnabled(bool(self.immutable.text().strip()))
        self._show_result(self.settings.value("backup_result", "", type=str))

    def _show_result(self, report):
        self.result.setPlainText(report)
        self.result.setVisible(bool(report))
        self.empty_result.setVisible(not report)

    def _plan(self):
        return {
            "model": self.model.currentText(),
            "local": [self.local.item(row).text() for row in range(self.local.count())],
            "usb": [self.usb.item(row).text() for row in range(self.usb.count())],
            "cloud": self.cloud.text().strip(), "immutable": self.immutable.text().strip(),
            "days": self.days.value(),
        }

    def _save(self):
        if self.work.window.job:
            return
        plan = self._plan()
        try:
            destinations(plan, self.profile)
        except (ValueError, OSError) as error:
            self.status.setText(str(error))
            return
        self.settings.setValue("backup_plan", json.dumps(plan, ensure_ascii=False))
        self.settings.sync()
        self.status.setText("Destinos guardados.")

    def _download_helper(self):
        name, _ = QFileDialog.getSaveFileName(self, "Descargar generador de código", CLOUD_HELPER.name, "Python (*.py)")
        if not name:
            return
        try:
            shutil.copyfile(CLOUD_HELPER, name)
        except OSError as error:
            self.status.setText(str(error))
            return
        QMessageBox.information(self, "Código de conexión",
                                "Ejecuta python vigia_codigo_s3.py NOMBRE_DEL_BUCKET en el servidor. "
                                "Pega el código que imprime. Vigía usa el perfil de AWS CLI de tu equipo para subir la copia.")

    def _create(self):
        if self.work.window.job:
            return
        plan = self._plan()
        self.settings.sync()
        self.form.setEnabled(False)
        self.save.setEnabled(False)
        self.start.setEnabled(False)
        self.progress.show()
        self.status.setText("Preparando instantánea…")

        def done(rows, error):
            self.form.setEnabled(True)
            self.save.setEnabled(True)
            self.start.setEnabled(True)
            self.progress.hide()
            if error:
                self.status.setText(str(error))
                return
            report = "\n\n".join(f"{name} · {state}\n{result}" for name, state, result in rows)
            self._show_result(report)
            self.settings.setValue("backup_result", report)
            self.settings.sync()
            verified = sum(state == "Verificada" for _, state, _ in rows)
            self.status.setText(f"{verified} de {len(rows)} destinos verificados.")
            self.scroll.ensureWidgetVisible(self.result)

        self.work._run(lambda: run_backup(self.profile, plan), done, "Creando copia de seguridad…")
